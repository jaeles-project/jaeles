package core

import (
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/panjf2000/ants"
	"github.com/thoas/go-funk"
	"sync"
)

func (r *Runner) Sending() {
	switch r.SendingType {
	case "single":
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
	// Submit tasks one by one.
	for _, record := range r.Records {
		record.DoSending()
	}
}

func (r *Runner) SendingParallels() {
	//fmt.Println("== Start with Concurrency", r.Opt.Concurrency)
	threads := r.Opt.Threads
	if r.Sign.Threads != 0 {
		threads = r.Sign.Threads
	}
	if r.Sign.Single {
		threads = 1
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(threads, func(j interface{}) {
		r := j.(Record)
		r.DoSending()
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	// Submit tasks one by one.
	for _, record := range r.Records {
		wg.Add(1)
		_ = p.Invoke(record)
	}
	wg.Wait()
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
