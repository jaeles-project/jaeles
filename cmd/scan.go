package cmd

import (
	"bufio"
	"fmt"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/thoas/go-funk"
	"os"
	"strings"
	"sync"

	"github.com/jaeles-project/jaeles/core"
	"github.com/spf13/cobra"
)

var scanCmd *cobra.Command

func init() {
	// byeCmd represents the bye command
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan list of URLs based on signatures",
		Long:  libs.Banner(),
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("url", "u", "", "URL of target")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringP("raw", "r", "", "Raw request from Burp for origin")
	scanCmd.SetHelpFunc(ScanHelp)
	RootCmd.AddCommand(scanCmd)

}

func runScan(cmd *cobra.Command, args []string) error {
	SelectSign()
	var urls []string
	// parse URL input here
	urlFile, _ := cmd.Flags().GetString("urls")
	urlInput, _ := cmd.Flags().GetString("url")
	if urlInput != "" {
		urls = append(urls, urlInput)
	}
	// input as a file
	if urlFile != "" {
		URLs := utils.ReadingLines(urlFile)
		for _, url := range URLs {
			urls = append(urls, url)
		}
	}

	// input as stdin
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		url := strings.TrimSpace(sc.Text())
		if err := sc.Err(); err == nil && url != "" {
			urls = append(urls, url)
		}
	}

	if len(urls) == 0 {
		utils.ErrorF("No Input found")
		os.Exit(1)
	}
	utils.InforF("Input Loaded: %v", len(urls))

	// get origin request from a file
	raw, _ := cmd.Flags().GetString("raw")
	var OriginRaw libs.Request
	var RawRequest string
	if raw != "" {
		RawRequest = utils.GetFileContent(raw)
		OriginRaw = core.ParseBurpRequest(RawRequest)
	}

	// Really start do something

	// run background detector
	if !options.NoBackGround {
		go func() {
			for {
				core.Background(options)
			}
		}()
	}

	jobs := make(chan libs.Job)

	var wg sync.WaitGroup
	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			for job := range jobs {
				sign := job.Sign
				url := job.URL

				// get origin from -r req.txt options
				if OriginRaw.Raw != "" {
					sign.Origin = OriginRaw
				}
				if RawRequest != "" {
					sign.RawRequest = RawRequest
				}
				// really run the job
				RunJob(url, sign, options)
			}
			wg.Done()
		}()
	}

	// jobs to send request
	for _, signFile := range options.SelectedSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign %v", signFile)
			continue
		}
		for _, url := range urls {
			jobs <- libs.Job{url, sign}
		}
	}

	close(jobs)
	wg.Wait()
	return nil
}

// RunJob really run the job
func RunJob(url string, sign libs.Signature, options libs.Options) {
	// var signatures []libs.Signature
	var originRec libs.Record
	var err error

	// prepare initial signature and variables
	Target := core.ParseTarget(url)
	Target = core.MoreVariables(Target, sign, options)

	// sending original
	if sign.Origin.Method != "" {
		var originReq libs.Request
		var originRes libs.Response

		originSign := sign
		if sign.Origin.Raw == "" {
			originSign.Target = Target
			originReq = core.ParseOrigin(originSign.Origin, originSign, options)
		} else {
			originReq = sign.Origin
		}

		originRes, err = sender.JustSend(options, originReq)
		if err == nil {
			if options.Verbose && (originReq.Method != "") {
				fmt.Printf("[Sent-Origin] %v %v \n", originReq.Method, originReq.URL)
			}
		}
		originRec.Request = originReq
		originRec.Response = originRes
		// set some more variables
		core.RunConclusions(originRec, &originSign)
		for k, v := range originSign.Target {
			if Target[k] == "" {
				Target[k] = v
			}
		}
	}
	singleJob(originRec, sign, Target)
}

func singleJob(originRec libs.Record, sign libs.Signature, target map[string]string) {

	globalVariables := core.ParseVariable(sign)
	if len(globalVariables) > 0 {
		// if Parallel not enable, override the threads
		var rg sync.WaitGroup
		count := 0
		for _, globalVariable := range globalVariables {
			sign.Target = target
			for k, v := range globalVariable {
				sign.Target[k] = v
			}

			// start to send stuff
			for _, req := range sign.Requests {
				rg.Add(1)
				// receive request from "-r req.txt"
				if sign.RawRequest != "" {
					req.Raw = sign.RawRequest
				}
				// gen bunch of request to send
				realReqs := core.ParseRequest(req, sign, options)
				// sending things
				go func() {
					defer rg.Done()
					SendRequest(realReqs, sign, originRec)
				}()

				count++
				if count == options.Threads {
					rg.Wait()
					count = 0
				}
			}

		}
		rg.Wait()
	} else {
		sign.Target = target
		//singleJob(originRec, sign)
		// start to send stuff
		for _, req := range sign.Requests {
			// receive request from "-r req.txt"
			if sign.RawRequest != "" {
				req.Raw = sign.RawRequest
			}
			// gen bunch of request to send
			realReqs := core.ParseRequest(req, sign, options)
			// sending things
			SendRequest(realReqs, sign, originRec)
			//go func () {
			//}()
		}
	}
}

// SendRequest sending request generated
func SendRequest(realReqs []libs.Request, sign libs.Signature, originRec libs.Record) {
	for _, realReq := range realReqs {
		var realRec libs.Record
		// set some stuff
		realRec.OriginReq = originRec.Request
		realRec.OriginRes = originRec.Response
		realRec.Request = realReq
		realRec.Request.Target = sign.Target
		realRec.Sign = sign
		realRec.ScanID = options.ScanID

		// replace things second time here with values section
		core.AltResolveRequest(&realRec.Request)

		// check conditions
		if len(realRec.Request.Conditions) > 0 {
			validate := checkConditions(realRec)
			if !validate {
				return
			}
		}

		// run middleware here
		if !funk.IsEmpty(realRec.Request.Middlewares) {
			core.MiddleWare(&realRec, options)
		}

		req := realRec.Request
		// if middleware return the response skip sending it
		if realRec.Response.StatusCode == 0 && realRec.Request.Method != "" && realRec.Request.MiddlewareOutput == "" {
			var res libs.Response
			// sending with real browser
			if req.Engine == "chrome" {
				res, _ = sender.SendWithChrome(options, req)
			} else {
				res, _ = sender.JustSend(options, req)
			}
			realRec.Request = req
			realRec.Response = res
		}

		DoAnalyze(realRec, &sign)
	}
}

func DoAnalyze(realRec libs.Record, sign *libs.Signature) {
	// print some log
	if options.Verbose && realRec.Request.Method != "" {
		if realRec.Response.StatusCode != 0 {
			fmt.Printf("[Sent] %v %v %v %v\n", realRec.Request.Method, realRec.Request.URL, realRec.Response.Status, realRec.Response.ResponseTime)
		}
		// middleware part
		if realRec.Request.MiddlewareOutput != "" {
			utils.DebugF(realRec.Request.MiddlewareOutput)
		}
	}

	// set new values for next request here
	core.RunConclusions(realRec, sign)
	// really do analyzer
	core.Analyze(options, &realRec)
	// do passive scan

	if options.EnablePassive {
		core.PassiveAnalyze(options, realRec)
		//	go func() {
		//		utils.DebugF("Passive Analyze")
		//		core.PassiveAnalyze(options, realRec)
		//	}()
	}
}

// check conditions before sending request
func checkConditions(record libs.Record) bool {
	for _, conditionString := range record.Request.Conditions {
		utils.DebugF("[conditionString] %v", conditionString)
		_, check := core.RunDetector(record, conditionString)
		if !check {
			return false
		}
	}
	return true
}
