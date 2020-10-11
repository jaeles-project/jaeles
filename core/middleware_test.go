package core

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/jaeles-project/jaeles/libs"
	"testing"
)

func TestMiddleWare(t *testing.T) {
	opt := libs.Options{
		Concurrency: 3,
		Threads:     5,
		Verbose:     true,
		NoDB:        true,
		NoOutput:    true,
	}
	URL := "http://httpbin.org:80"

	signContent := `
id: nginx-smuggling-01
info:
  name: Nginx Smuggling
  risk: High

variables:
  - random: RandomString("6")

requests:
  - middlewares:
      - >-
        InvokeCmd('echo {{.BaseURL}}/sam; ls /tmp/')
      - >-
        InvokeCmd('touch /tmp/ssssssss')
    detections:
      - >-
        StringSearch("middleware", "dlm_message_server_in")
`
	sign, err := ParseSignFromContent(signContent)
	if err != nil {
		t.Errorf("Error parsing signature")
	}
	runner, err := InitRunner(URL, sign, opt)
	if err != nil {
		t.Errorf("Error parsing signature")
	}
	fmt.Println("New Requests generated: ", len(runner.Records))

	spew.Dump(runner.Records[0].Request.Middlewares)
	runner.Sending()
}
