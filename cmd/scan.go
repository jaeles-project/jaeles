package cmd

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/thoas/go-funk"

	"github.com/fatih/color"
	"github.com/jaeles-project/jaeles/core"
	"github.com/spf13/cobra"
)

var scanCmd *cobra.Command

func init() {
	// byeCmd represents the bye command
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Do the Scan",
		Long:  `Scan list of URLs based on signatures`,
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("url", "u", "", "URL of target")
	scanCmd.Flags().String("ssrf", "", "Fill your BurpCollab")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringP("sign", "s", "", "Provide custom header seperate by ';'")
	RootCmd.AddCommand(scanCmd)

}

func runScan(cmd *cobra.Command, args []string) error {
	// DB connect
	dbPath := path.Join(options.RootFolder, "sqlite.db")
	db, err := database.InitDB(dbPath)
	if err != nil {
		panic("err open databases")
	}
	defer db.Close()
	signs := []string{}
	urls := []string{}
	info := color.HiBlueString("[*]")

	// create output folder
	err = os.MkdirAll(options.Output, 0750)
	if err != nil && options.NoOutput == false {
		fmt.Fprintf(os.Stderr, "failed to create output directory: %s\n", err)
		os.Exit(1)
	}

	ssrf, _ := cmd.Flags().GetString("ssrf")
	if ssrf != "" {
		if options.Verbose {
			fmt.Printf("%v SSRF set: %v \n", info, ssrf)
		}
		database.ImportBurpCollab(ssrf)
	}

	// parse URL here
	urlFile, _ := cmd.Flags().GetString("urls")
	urlInput, _ := cmd.Flags().GetString("url")
	if urlInput != "" {
		urls = append(urls, urlInput)
	}
	if urlFile != "" {
		URLs := core.ReadingFile(urlFile)
		for _, url := range URLs {
			urls = append(urls, url)
		}
	}
	if len(urls) == 0 {
		libs.ErrorF("No Input found")
		os.Exit(1)
	}

	signName, _ := cmd.Flags().GetString("sign")
	// Get exactly signature
	if strings.HasSuffix(signName, ".yaml") {
		if core.FileExists(signName) {
			signs = append(signs, signName)
		}
	}
	// get more sign nature
	if strings.Contains(signName, "*") && strings.Contains(signName, "/") {
		asbPath, _ := filepath.Abs(signName)
		baseSelect := filepath.Base(signName)
		rawSigns := core.GetFileNames(filepath.Dir(asbPath), "yaml")
		for _, signFile := range rawSigns {
			baseSign := filepath.Base(signFile)
			r, err := regexp.Compile(baseSelect)
			if err != nil {
				continue
			}
			if r.MatchString(baseSign) {
				signs = append(signs, signFile)
			}
		}
	}

	// search signature through Signatures table
	Signs := database.SelectSign(signName)
	signs = append(signs, Signs...)
	fmt.Printf("%v Signatures Loaded: %v \n", info, len(signs))

	// create new scan or group with old one
	var scanID string
	if options.ScanID == "" {
		scanID = database.NewScan(options, "scan", signs)
	} else {
		scanID = options.ScanID
	}
	fmt.Printf("%v Start Scan with ID: %v \n", info, scanID)

	if len(signs) == 0 {
		fmt.Println("[Error] No signature loaded")
		os.Exit(1)
	}

	if options.Verbose {
		fmt.Printf("%v Signature Loaded: ", info)
		for _, signName := range signs {
			fmt.Printf("%v ", filepath.Base(signName))
		}
		fmt.Printf("\n")
	}

	// run background detector
	go func() {
		for {
			core.Background(options)
		}
	}()

	// gen request for sending
	var recQueue []libs.Record
	for _, signFile := range signs {
		for _, url := range urls {
			sign, err := core.ParseSign(signFile)
			if err != nil {
				log.Fatalf("Error parsing YAML sign %v", signFile)
			}

			sign.Target = core.ParseTarget(url)
			sign.Target = core.MoreVariables(sign.Target, options)
			var originReq libs.Request
			if sign.Origin.Method != "" {
				originReq = core.ParseRequest(sign.Origin, sign)[0]
			}

			// start to send stuff
			for _, req := range sign.Requests {
				realReqs := core.ParseRequest(req, sign)
				if len(realReqs) > 0 {
					for _, realReq := range realReqs {
						var realRec libs.Record
						realRec.Request = realReq
						realRec.Request.Target = sign.Target
						realRec.OriginReq = originReq
						realRec.Sign = sign
						realRec.ScanID = scanID

						recQueue = append(recQueue, realRec)
					}
				}
			}
		}
	}

	if len(recQueue) == 0 {
		libs.ErrorF("No Request Generated")
		os.Exit(1)
	}

	/* Start sending request here */
	var wg sync.WaitGroup
	jobs := make(chan libs.Record, options.Concurrency)
	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for realRec := range jobs {
				originRes, err := core.JustSend(options, realRec.OriginReq)
				if err == nil {
					// continue
					realRec.OriginRes = originRes
					if options.Verbose && (realRec.OriginReq.Method != "") {
						fmt.Printf("[Sent-Origin] %v %v \n", realRec.OriginReq.Method, realRec.OriginReq.URL)
					}
				}

				// run middleware here
				req := realRec.Request
				if !funk.IsEmpty(req.Middlewares) {
					core.MiddleWare(&realRec, options)
				}

				// if middleware return the response skip sending it
				if realRec.Response.StatusCode == 0 {
					res, err := core.JustSend(options, req)
					if err != nil {
						continue
					}
					realRec.Request = req
					realRec.Response = res
				}
				// print some log
				if options.Verbose && realRec.Request.Method != "" {
					fmt.Printf("[Sent] %v %v %v %v\n", realRec.Request.Method, realRec.Request.URL, realRec.Response.Status, realRec.Response.ResponseTime)
				}
				if options.Debug {
					if realRec.Request.MiddlewareOutput != "" {
						fmt.Println(realRec.Request.MiddlewareOutput)
					}
				}
				// resolve detection this time because we need parse something in the variable
				target := core.ParseTarget(realRec.Request.URL)
				target = core.MoreVariables(target, options)
				realRec.Request.Detections = core.ResolveDetection(realRec.Request.Detections, target)
				// start to run detection
				core.Analyze(options, &realRec)

			}
		}()
	}

	// job
	go func() {
		for _, rec := range recQueue {
			jobs <- rec
		}
		close(jobs)
	}()
	wg.Wait()

	return nil
}
