package core

import (
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/panjf2000/ants"
	"github.com/thoas/go-funk"
	"sync"
)

func (r *Runner) Sending() {
	if len(r.CRecords) > 0 {
		if r.Sign.Match == "" {
			r.Sign.Match = "all"
		}
		r.SendCRequests()
		if !r.CMatched {
			utils.DebugF("Check request not matched")
			return
		}
		utils.DebugF("Passed check request")
	}

	switch r.SendingType {
	case "serial":
		r.SendingSerial()
		break
	case "parallels":
		r.SendingParallels()
		break
	default:
		r.SendingParallels()
	}
}

func (r *Runner) SendingSerial() {
	var recordsSent []Record
	// Submit tasks one by one.
	for _, record := range r.Records {
		record.DoSending()
		if r.InRoutine {
			recordsSent = append(recordsSent, record)
		}
	}
	if r.InRoutine {
		r.Records = recordsSent
	}
}

func (r *Runner) SendingParallels() {
	var recordsSent []Record
	threads := r.Opt.Threads
	if r.Sign.Threads != 0 {
		threads = r.Sign.Threads
	}
	if r.Sign.Single {
		threads = 1
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(threads, func(j interface{}) {
		rec := j.(Record)
		rec.DoSending()
		if r.InRoutine {
			recordsSent = append(recordsSent, rec)
		}
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	// Submit tasks one by one.
	for _, record := range r.Records {
		wg.Add(1)
		_ = p.Invoke(record)
	}
	wg.Wait()
	if r.InRoutine {
		r.Records = recordsSent
	}
}

// sending func for parallel mode
func (r *Record) DoSending() {
	// replace things second time here with new values section
	AltResolveRequest(&r.Request)
	// check conditions
	if len(r.Request.Conditions) > 0 {
		validate := r.Condition()
		if !validate {
			return
		}
	}

	// run middleware here
	if !funk.IsEmpty(r.Request.Middlewares) {
		r.MiddleWare()
	}

	req := r.Request
	// if middleware return the response skip sending it
	var res libs.Response
	if r.Response.StatusCode == 0 && r.Request.Method != "" && r.Request.MiddlewareOutput == "" && req.Res == "" {
		// sending with real browser
		if req.Engine == "chrome" {
			res, _ = sender.SendWithChrome(r.Opt, req)
		} else {
			res, _ = sender.JustSend(r.Opt, req)
		}
	}
	// parse response directly without sending
	if req.Res != "" {
		res = ParseBurpResponse("", req.Res)
	}
	r.Request = req
	r.Response = res
	r.Analyze()
}

// SendCRequests sending condition requests
func (r *Runner) SendCRequests() {
	var matchCount int
	for _, rec := range r.CRecords {

		// sending func for parallel mode
		// replace things second time here with new values section
		AltResolveRequest(&rec.Request)
		// check conditions
		if len(rec.Request.Conditions) > 0 {
			validate := rec.Condition()
			if !validate {
				return
			}
		}

		// run middleware here
		if !funk.IsEmpty(rec.Request.Middlewares) {
			rec.MiddleWare()
		}

		req := rec.Request
		// if middleware return the response skip sending it
		var res libs.Response
		if rec.Response.StatusCode == 0 && rec.Request.Method != "" && rec.Request.MiddlewareOutput == "" && req.Res == "" {
			// sending with real browser
			if req.Engine == "chrome" {
				res, _ = sender.SendWithChrome(rec.Opt, req)
			} else {
				res, _ = sender.JustSend(rec.Opt, req)
			}
		}
		// parse response directly without sending
		if req.Res != "" {
			res = ParseBurpResponse("", req.Res)
		}
		rec.Request = req
		rec.Response = res

		rec.Analyze()
		if rec.IsVulnerable {
			matchCount += 1
		}

	}

	switch r.Sign.Match {
	case "all":
		if matchCount == len(r.CRecords) {
			r.CMatched = true
		}
		break
	case "any":
		if matchCount > 0 {
			r.CMatched = true
		}
		break
	}
}
