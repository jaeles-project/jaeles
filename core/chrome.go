package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/jaeles-project/jaeles/libs"
)

// SendWithChrome send request with real browser
func SendWithChrome(options libs.Options, req libs.Request) (libs.Response, error) {
	// parsing some stuff
	url := req.URL
	// @TODO: parse more request component later
	// method := req.Method
	// body := req.Body
	// headers := GetHeaders(req)
	libs.DebugF("Sending with chrome: %v", url)
	var res libs.Response

	// chromeContext, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	chromeContext, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	if options.Debug {
		// show the chrome page in debug mode
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", false),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("enable-automation", true),
			chromedp.Flag("disable-extensions", false),
			chromedp.Flag("disable-setuid-sandbox", true),
			// chromedp.Flag("ignore-certificate-errors", true),
		)
		allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
		defer cancel()
		chromeContext, cancel = chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
		// chromeContext, cancel = chromedp.NewContext(context.Background())
		defer cancel()
	} else {
		// chromeContext, cancel = chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
		chromeContext, cancel = chromedp.NewContext(context.Background())
		defer cancel()
	}
	// where we'll store the details of the response
	var response string
	var statusCode int64
	var responseHeaders map[string]interface{}

	timeout := time.Duration(options.Timeout)
	if req.Timeout != 0 {
		timeout = time.Duration(req.Timeout)
	}

	// start Chrome and run given tasks
	// var res string
	err := chromedp.Run(
		chromeContext,
		chromeTask(
			chromeContext, url,
			// @TODO: add header here
			map[string]interface{}{},
			// map[string]interface{}{"User-Agent": "Mozilla/5.0"},
			&response, &statusCode, &responseHeaders),
		// wait for the page to load
		chromedp.Sleep(timeout*time.Second),
		// get response after the page load
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			response, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			return err
		}),
	)

	if err != nil {
		libs.ErrorF("%v", err)
		return libs.Response{}, err
	}

	// parse response
	res.StatusCode = int(statusCode)
	res.Body = response
	var header string
	for k, v := range responseHeaders {
		header += fmt.Sprintf("%v: %v\n", k, v)
	}
	res.Beautify = fmt.Sprintf("%v\n%v\n%v", res.StatusCode, header, res.Body)
	return res, err
}

// chrome debug protocol tasks to run
func chromeTask(chromeContext context.Context, url string, requestHeaders map[string]interface{}, response *string, statusCode *int64, responseHeaders *map[string]interface{}) chromedp.Tasks {
	// setup a listener for events
	chromedp.ListenTarget(chromeContext, func(event interface{}) {
		// get which type of event it is
		switch msg := event.(type) {

		// just before request sent
		case *network.EventRequestWillBeSent:
			request := msg.Request
			// fmt.Printf(" request url: %s\n", request.URL)

			// see if we have been redirected
			// if so, change the URL that we are tracking
			if msg.RedirectResponse != nil {
				url = request.URL
				// fmt.Printf(" got redirect: %s\n", msg.RedirectResponse.URL)
			}

		// once we have the full response
		case *network.EventResponseReceived:

			response := msg.Response

			// is the request we want the status/headers on?
			if response.URL == url {
				*statusCode = response.Status
				*responseHeaders = response.Headers
				// fmt.Printf(" url: %s\n", response.URL)
				// fmt.Printf(" status code: %d\n", *statusCode)
				// fmt.Printf(" # headers: %d\n", len(*responseHeaders))
			}
		}

	})

	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(requestHeaders)),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			*response, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)

			return err
		})}
}
