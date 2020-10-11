package core

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/jaeles-project/jaeles/libs"
	"testing"
)

func TestInitRunner(t *testing.T) {
	opt := libs.Options{
		Concurrency: 3,
		Threads:     5,
		Verbose:     true,
		NoDB:        true,
		NoOutput:    true,
	}
	URL := "http://httpbin.org"
	signContent := `
# info to search signature
id: cred-01-01
noutput: true
info:
  name: Default Credentials
  risk: High

origin:
  method: GET
  redirect: false
  headers:
    - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55
  url: >-
    {{.BaseURL}}/anything?q=1122
  concllousions:
    - SetValue("code", StatusCode())

variables:
  - tomcat: |
      /manager/
      /manager/html/
      /server-status/
      /html/
      /
requests:
  - method: GET
    redirect: false
    url: >-
      {{.BaseURL}}/anything?aaaa={{.tomcat}}
    headers:
      - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55
    detections:
      - >-
        StatusCode() == 200 && (1 == 1)
      - >-
        StatusCode() == 200

`
	//signFile := "/Users/j3ssie/go/src/github.com/jaeles-project/jaeles/test-sign/default-cred.yaml"
	sign, err := ParseSignFromContent(signContent)
	if err != nil {
		t.Errorf("Error parsing signature")

	}
	runner, err := InitRunner(URL, sign, opt)
	if err != nil {
		t.Errorf("Error parsing signature")
	}
	spew.Dump(runner.Target)
	fmt.Println("New Requests generated: ", len(runner.Records))

	runner.Sending()
}

func TestInitRunnerSerial(t *testing.T) {
	opt := libs.Options{
		Concurrency: 3,
		Threads:     5,
		Verbose:     true,
		NoDB:        true,
		NoOutput:    true,
	}
	URL := "http://httpbin.org"

	signContent := `
id: dom-xss-01
single: true
info:
  name: DOM XSS test
  risk: High


variables:
  - xss: RandomString(4)

requests:
  - method: GET
    url: >-
      {{.BaseURL}}/tests/sinks.html?name=[[.custom]]{{.xss}}
    conclusions:
      - StringSelect("component", "res1", "right", "left")
      - SetValue("sam", "regex")
      - RegexSelect("component", "var_name", "regex")
    detections:
      - StatusCode() == 200 && StringSearch("response", "{{.xss}}")

  - conditions:
      - ValueOf('sam') == 'regex'
    method: GET
    url: >-
      {{.BaseURL}}/tests/sinks.html?name=111{{.xss}}22[[.custom]]
    detections:
      - >-
        StatusCode() == 200 && StringSearch("response", "{{.xss}}")

`
	sign, err := ParseSignFromContent(signContent)
	if err != nil {
		t.Errorf("Error parsing signature")

	}
	runner, err := InitRunner(URL, sign, opt)
	if err != nil {
		t.Errorf("Error parsing signature")
	}
	spew.Dump(runner.Target)
	fmt.Println("New Requests generated: ", len(runner.Records))

	runner.Sending()
}
