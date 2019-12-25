package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jaeles-project/jaeles/libs"
	"github.com/parnurzeal/gorequest"
)

// JustSend just sending request
func JustSend(options libs.Options, req libs.Request) (res libs.Response, err error) {
	// sending with real browser
	if req.Engine == "chrome" {
		res, err = SendWithChrome(options, req)
		return res, err
	}

	// parsing some stuff
	method := req.Method
	url := req.URL
	body := req.Body
	headers := GetHeaders(req)

	// sending with real chrome

	// new client
	client := gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.Timeout(time.Duration(options.Timeout) * time.Second)
	if options.Proxy != "" {
		client.Proxy(options.Proxy)
	}

	// choose method
	switch method {
	case "GET":
		client.Get(url)
		break
	case "POST":
		client.Post(url)
		break
	case "PUT":
		client.Put(url)
		break
	case "HEAD":
		client.Head(url)
		break
	case "PATCH":
		client.Patch(url)
		break
	case "DELETE":
		client.Delete(url)
		break
	}

	timeStart := time.Now()
	for k, v := range headers {
		client.AppendHeader(k, v)
	}
	if body != "" {
		client.Send(body)
	}

	// handle Redirect
	if req.Redirect == true {
		client.RedirectPolicy(func(req gorequest.Request, via []gorequest.Request) error {
			for attr, val := range via[0].Header {
				if _, ok := req.Header[attr]; !ok {
					req.Header[attr] = val
				}
			}

			for k, v := range headers {
				client.AppendHeader(k, v)
			}
			if body != "" {
				client.Send(body)
			}
			return nil
		})
	} else {
		client.RedirectPolicy(func(req gorequest.Request, via []gorequest.Request) error {
			// parsing respone in case we have redirect
			res.Status = req.Response.Status
			res.StatusCode = req.Response.StatusCode
			resp := req.Response
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			bodyString := string(bodyBytes)

			// bodyString := string(bodyBytes)
			resLength := len(bodyString)
			// format the headers
			var resHeaders []map[string]string
			for k, v := range resp.Header {
				element := make(map[string]string)
				element[k] = strings.Join(v[:], "")
				resLength += len(fmt.Sprintf("%s: %s\n", k, strings.Join(v[:], "")))
				resHeaders = append(resHeaders, element)
			}

			// respones time in second
			resTime := time.Since(timeStart).Seconds()
			resHeaders = append(resHeaders,
				map[string]string{"Total Length": strconv.Itoa(resLength)},
				map[string]string{"Response Time": fmt.Sprintf("%f", resTime)},
			)

			// set some variable
			res.Headers = resHeaders
			res.Body = bodyString
			res.ResponseTime = resTime
			res.Length = resLength
			// beautify
			res.Beautify = BeautifyResponse(res)
			return errors.New("auto redirect is disabled")
		})
	}
	// really sending stuff
	resp, resBody, errs := client.End()
	resTime := time.Since(timeStart).Seconds()

	if len(errs) > 0 && res.StatusCode != 0 {
		return res, nil
	} else if len(errs) > 0 {
		if options.Verbose {
			libs.ErrorF("Error sending: %v %v", url, errs)
		}
		if options.Retry > 0 {
			client.Retry(3, time.Duration(options.Timeout/2)*time.Second, http.StatusBadRequest, http.StatusInternalServerError)
		}
		return libs.Response{}, errs[0]
	}

	resp.Body.Close()
	return ParseResponse(resp, resBody, resTime), nil
}

// ParseResponse field to Response
func ParseResponse(resp gorequest.Response, resBody string, resTime float64) (res libs.Response) {
	// var res libs.Response
	resLength := len(string(resBody))

	// format the headers
	var resHeaders []map[string]string
	for k, v := range resp.Header {
		element := make(map[string]string)
		element[k] = strings.Join(v[:], "")
		resLength += len(fmt.Sprintf("%s: %s\n", k, strings.Join(v[:], "")))
		resHeaders = append(resHeaders, element)
	}
	// respones time in second
	resHeaders = append(resHeaders,
		map[string]string{"Total Length": strconv.Itoa(resLength)},
		map[string]string{"Response Time": fmt.Sprintf("%f", resTime)},
	)

	// set some variable
	res.Headers = resHeaders
	res.StatusCode = resp.StatusCode
	res.Status = resp.Status
	res.Body = resBody
	res.ResponseTime = resTime
	res.Length = resLength
	// beautify
	res.Beautify = BeautifyResponse(res)
	return res
}

// GetHeaders generate headers if not provide
func GetHeaders(req libs.Request) map[string]string {
	// random user agent
	UserAgens := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3941.0 Safari/537.36",
		"Mozilla/5.0 (X11; U; Windows NT 6; en-US) AppleWebKit/534.12 (KHTML, like Gecko) Chrome/9.0.587.0 Safari/534.12",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
	}

	headers := make(map[string]string)
	if len(req.Headers) == 0 {
		rand.Seed(time.Now().Unix())
		headers["User-Agent"] = UserAgens[rand.Intn(len(UserAgens))]
		return headers
	}

	for _, header := range req.Headers {
		for key, value := range header {
			headers[key] = value
		}
	}

	rand.Seed(time.Now().Unix())
	// append user agent in case you didn't set user-agent
	if headers["User-Agent"] == "" {
		rand.Seed(time.Now().Unix())
		headers["User-Agent"] = UserAgens[rand.Intn(len(UserAgens))]
	}
	return headers
}

// BeautifyRequest beautify request
func BeautifyRequest(req libs.Request) string {
	var beautifyReq string
	// hardcord HTTP/1.1 for now
	beautifyReq += fmt.Sprintf("%v %v HTTP/1.1\n", req.Method, req.URL)

	for _, header := range req.Headers {
		for key, value := range header {
			if key != "" && value != "" {
				beautifyReq += fmt.Sprintf("%v: %v\n", key, value)
			}
		}
	}
	if req.Body != "" {
		beautifyReq += fmt.Sprintf("\n%v\n", req.Body)
	}
	return beautifyReq
}

// BeautifyResponse beautify response
func BeautifyResponse(res libs.Response) string {
	var beautifyRes string
	beautifyRes += fmt.Sprintf("%v \n", res.Status)

	for _, header := range res.Headers {
		for key, value := range header {
			beautifyRes += fmt.Sprintf("%v: %v\n", key, value)
		}
	}

	beautifyRes += fmt.Sprintf("\n%v\n", res.Body)
	return beautifyRes
}
