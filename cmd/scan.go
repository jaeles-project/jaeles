package cmd

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
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
	scanCmd.Flags().String("ssrf", "", "Fill your BurpCollab or any Out of Band host")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringP("sign", "s", "", "Provide custom header seperate by ','")
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
			libs.InforF("SSRF set: %v ", ssrf)
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
	signs = core.SelectSign(signName)

	// search signature through Signatures table
	Signs := database.SelectSign(signName)
	signs = append(signs, Signs...)
	libs.InforF("Signatures Loaded: %v", len(signs))

	// create new scan or group with old one
	var scanID string
	if options.ScanID == "" {
		scanID = database.NewScan(options, "scan", signs)
	} else {
		scanID = options.ScanID
	}
	libs.InforF("Start Scan with ID: %v", scanID)

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

	var sg sync.WaitGroup
	var wg sync.WaitGroup
	records := make(chan libs.Record)

	type Job struct {
		URL  string
		Sign libs.Signature
	}
	var jobs []Job
	for _, url := range urls {
		for _, signFile := range signs {
			sign, err := core.ParseSign(signFile)
			if err != nil {
				log.Fatalf("Error parsing YAML sign %v", signFile)
			}
			// realSigns = append(realSigns, sign)
			realjob := Job{url, sign}
			jobs = append(jobs, realjob)
		}
	}

	if options.Debug {
		libs.DebugF("Number of jobs: %v", len(jobs))
	}

	// run background detector
	if options.NoBackGround {
		go func() {
			for {
				core.Background(options)
			}
		}()
	}

	/* Start main stuff here */
	sg.Add(1)
	go func() {
		defer sg.Done()
		// prepare request with signature
		for _, job := range jobs {
			sign := job.Sign
			url := job.URL
			sign.Target = core.ParseTarget(url)
			sign.Target = core.MoreVariables(sign.Target, options)
			var originReq libs.Request
			var originRes libs.Response
			if sign.Origin.Method != "" {
				originReq = core.ParseRequest(sign.Origin, sign)[0]
				originRes, err = core.JustSend(options, originReq)
				if err == nil {
					if options.Verbose && (originReq.Method != "") {
						fmt.Printf("[Sent-Origin] %v %v \n", originReq.Method, originReq.URL)
					}
				}
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
						realRec.OriginRes = originRes
						realRec.Sign = sign
						realRec.ScanID = scanID
						records <- realRec
					}
				}

			}
		}
	}()

	/* Start main stuff here */
	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for realRec := range records {
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

	sg.Wait()
	wg.Wait()
	close(records)

	return nil
}
