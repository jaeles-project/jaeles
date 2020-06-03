package cmd

import (
	"bufio"
	"fmt"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/panjf2000/ants"
	"github.com/spf13/cobra"
	"github.com/thoas/go-funk"
	"os"
	"strings"
	"sync"
	"time"
)

func init() {
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan list of URLs based on selected signatures",
		Long:  libs.Banner(),
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("url", "u", "", "URL of target")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringP("raw", "r", "", "Raw request from Burp for origin")
	scanCmd.Flags().Bool("html", false, "Generate HTML report after done")
	scanCmd.SetHelpFunc(ScanHelp)
	RootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
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
	if len(urls) == 0 {
		stat, _ := os.Stdin.Stat()
		// detect if anything came from std
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				url := strings.TrimSpace(sc.Text())
				if err := sc.Err(); err == nil && url != "" {
					urls = append(urls, url)
				}
			}
		}
	}

	if len(urls) == 0 {
		fmt.Println("[Error] No signature loaded")
		ScanMessage()
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

	/* ---- Really start do something ---- */

	// run background detector
	if !options.NoBackGround {
		go func() {
			for {
				core.Background(options)
			}
		}()
	}

	var wg sync.WaitGroup
	for _, signFile := range options.SelectedSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign %v", signFile)
			continue
		}
		// filter signature by level
		if sign.Level > options.Level {
			continue
		}

		// pass to parallel to run later
		if sign.Parallel {
			options.ParallelSigns = append(options.ParallelSigns, signFile)
			continue
		}

		p, _ := ants.NewPoolWithFunc(options.Concurrency, func(i interface{}) {
			startSingleJob(i)
			wg.Done()
		}, ants.WithPreAlloc(true))
		defer p.Release()

		//get origin from -r req.txt options
		if OriginRaw.Raw != "" {
			sign.Origin = OriginRaw
		}
		if RawRequest != "" {
			sign.RawRequest = RawRequest
		}

		// Submit tasks one by one.
		for _, url := range urls {
			wg.Add(1)
			job := libs.Job{URL: url, Sign: sign}
			_ = p.Invoke(job)
		}
	}

	// run parallel routine instead
	if !options.DisableParallel || len(options.ParallelSigns) > 0 {
		utils.InforF("Sending request with Parallel mode.")
		// pass all signs to parallel if forced from cli
		if !options.DisableParallel {
			options.ParallelSigns = options.SelectedSigns
		}
		runParallel(urls)
	}

	wg.Wait()
	CleanOutput()

	genReport, _ := cmd.Flags().GetBool("html")
	if genReport == true && utils.FolderExists(options.Output) {
		DoGenReport(options)
	}
	return nil
}

func startSingleJob(j interface{}) {
	job := j.(libs.Job)
	originRec, sign, target := InitJob(job.URL, job.Sign)
	realReqs := genRequests(sign, target)
	SendRequests(realReqs, sign, originRec)
}

// InitJob init origin and some variables
func InitJob(url string, sign libs.Signature) (libs.Record, libs.Signature, map[string]string) {
	var originRec libs.Record
	var origin libs.Origin
	// prepare initial signature and variables
	Target := make(map[string]string)
	// parse Input from JSON format
	if options.EnableFormatInput {
		Target = core.ParseInputFormat(url)
	} else {
		Target = core.ParseTarget(url)
	}

	Target = core.MoreVariables(Target, sign, options)
	sign.Target = Target

	// base origin
	if sign.Origin.Method != "" {
		origin, Target = sendOrigin(sign, sign.Origin, Target)
		originRec.Request = origin.ORequest
		originRec.Response = origin.OResponse
	}
	// in case we have many origin
	if len(sign.Origins) > 0 {
		var origins []libs.Origin
		for index, origin := range sign.Origins {
			origin, Target = sendOrigin(sign, origin.ORequest, Target)
			if origin.Label == "" {
				origin.Label = fmt.Sprintf("%v", index)
			}
			origins = append(origins, origin)
		}
		sign.Origins = origins
	}

	return originRec, sign, Target
}

// sending origin request
func sendOrigin(sign libs.Signature, originReq libs.Request, target map[string]string) (libs.Origin, map[string]string) {
	var origin libs.Origin
	var err error
	var originRes libs.Response

	originSign := sign
	if originReq.Raw == "" {
		originSign.Target = target
		originReq = core.ParseOrigin(originReq, originSign, options)
	}

	originRes, err = sender.JustSend(options, originReq)
	if err == nil {
		if options.Verbose && (originReq.Method != "") {
			fmt.Printf("[Sent-Origin] %v %v %v %v %v\n", originReq.Method, originReq.URL, originRes.Status, originRes.ResponseTime, len(originRes.Beautify))
		}
	}
	originRec := libs.Record{Request: originReq, Response: originRes}
	// set some more variables
	core.RunConclusions(originRec, &originSign)
	for k, v := range originSign.Target {
		if target[k] == "" {
			target[k] = v
		}
	}
	origin.ORequest = originReq
	origin.OResponse = originRes
	return origin, target
}

// generate request for sending
func genRequests(sign libs.Signature, target map[string]string) []libs.Request {
	// quick param for calling resource
	sign.Target = core.MoreVariables(sign.Target, sign, options)

	var realReqs []libs.Request
	globalVariables := core.ParseVariable(sign)
	if len(globalVariables) > 0 {
		for _, globalVariable := range globalVariables {
			sign.Target = target
			for k, v := range globalVariable {
				sign.Target[k] = v
			}
			// start to send stuff
			for _, req := range sign.Requests {
				// receive request from "-r req.txt"
				if sign.RawRequest != "" {
					req.Raw = sign.RawRequest
				}
				// gen bunch of request to send
				realReqs = append(realReqs, core.ParseRequest(req, sign, options)...)
			}
		}
	} else {
		sign.Target = target
		// start to send stuff
		for _, req := range sign.Requests {
			// receive request from "-r req.txt"
			if sign.RawRequest != "" {
				req.Raw = sign.RawRequest
			}
			// gen bunch of request to send
			realReqs = append(realReqs, core.ParseRequest(req, sign, options)...)
		}
	}
	return realReqs
}

// SendRequests sending request generated
func SendRequests(realReqs []libs.Request, sign libs.Signature, originRec libs.Record) {
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

		if options.Delay > 0 {
			utils.DebugF("Delay sending request: %v", options.Delay)
			time.Sleep(time.Duration(options.Delay) * time.Second)
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

// Start parallels jobs
func runParallel(urls []string) {
	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(options.Concurrency, func(i interface{}) {
		parallelJob(i)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	for _, signFile := range options.ParallelSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign %v", signFile)
			continue
		}
		// filter signature by level
		if sign.Level > options.Level {
			continue
		}
		// avoid duplicate sending in signature
		if sign.Single {
			continue
		}

		// Submit tasks one by one.
		for _, url := range urls {
			originRec, sign, target := InitJob(url, sign)
			realReqs := genRequests(sign, target)
			for _, req := range realReqs {
				wg.Add(1)
				// parsing request here
				job := libs.PJob{
					Req:  req,
					ORec: originRec,
					Sign: sign,
				}
				_ = p.Invoke(job)
			}
		}

	}
	wg.Wait()
}

func parallelJob(j interface{}) {
	job := j.(libs.PJob)
	parallelSending(job.Req, job.Sign, job.ORec)
}

// sending func for parallel mode
func parallelSending(realReq libs.Request, sign libs.Signature, originRec libs.Record) {
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

func DoAnalyze(realRec libs.Record, sign *libs.Signature) {
	// print some log
	if options.Verbose && realRec.Request.Method != "" {
		if realRec.Response.StatusCode != 0 {
			fmt.Printf("[Sent] %v %v %v %v %v \n", realRec.Request.Method, realRec.Request.URL, realRec.Response.Status, realRec.Response.ResponseTime, len(realRec.Response.Beautify))
		}
		// middleware part
		if realRec.Request.MiddlewareOutput != "" {
			utils.DebugF(realRec.Request.MiddlewareOutput)
		}
	}

	if len(sign.Origins) > 0 {
		realRec.Origins = sign.Origins
	}

	// set new values for next request here
	core.RunConclusions(realRec, sign)
	// really do analyze
	core.Analyze(options, &realRec)

	// do passive scan
	if options.EnablePassive || sign.Passive {
		if !realRec.DonePassive {
			core.PassiveAnalyze(options, realRec)
		}
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
