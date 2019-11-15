package core

import (
	"strings"
	"testing"

	"github.com/jaeles-project/jaeles/libs"
)

func TestReallySending(t *testing.T) {
	var headers []map[string]string
	var req libs.Request
	headers = append(headers, map[string]string{
		"Content-Type": "application/json",
	})

	req.Method = "POST"
	req.URL = "https://httpbin.org/post"
	req.Headers = headers

	var opt libs.Options
	// opt.Proxy = "http://127.0.0.1:8080"
	res, err := JustSend(opt, req)
	if err != nil {
		t.Errorf("Error sending request")
	}

	status := res.StatusCode
	if status != 200 {
		t.Errorf("Error parsing result")
	}
	// sending with POST data
	req.Body = "example1=23"
	res, err = JustSend(opt, req)
	if err != nil {
		t.Errorf("Error sending request")
	}

	if !strings.Contains(res.Body, "example1") {
		t.Errorf("Error parsing result")
	}

	req.Body = `{"example1": "3333"}`
	res, err = JustSend(opt, req)
	if err != nil {
		t.Errorf("Error sending request")
	}

	if !strings.Contains(res.Body, "example1") {
		t.Errorf("Error parsing result")
	}
}
