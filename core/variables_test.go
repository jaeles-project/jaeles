package core

import (
	"fmt"
	"testing"

	"github.com/jaeles-project/jaeles/libs"
)

func TestVariables(t *testing.T) {
	varString := `RandomString("6")`
	data := RunVariables(varString)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `RandomString(3)`
	data = RunVariables(varString)

	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `Range(0,5)`
	data = RunVariables(varString)
	fmt.Println(varString, ":", data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `File("~/suites/contents/quick.txt")`
	data = RunVariables(varString)
	fmt.Println(varString, ":", len(data))
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `InputCmd("echo 123")`
	data = RunVariables(varString)
	fmt.Println(varString, ":", data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
}

func TestMultipleVariables(t *testing.T) {
	var sign libs.Signature
	var vars []map[string]string

	varElement := make(map[string]string)
	varElement["param"] = `[1,2,3,4]`
	vars = append(vars, varElement)

	varElement2 := make(map[string]string)
	varElement2["dest"] = `[a,b,c]`
	vars = append(vars, varElement2)

	sign.Variables = vars

	realVaris := ParseVariable(sign)
	fmt.Println(realVaris)
	if len(realVaris) <= 0 {
		t.Errorf("Error RandomString")
	}
}

func TestEncoding(t *testing.T) {
	varString := `URLEncode(" das da")`
	data := RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `Base64Encode("das da c")`
	data = RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}

	varString = `Base64EncodeByLines('das\nda\nc')`
	data = RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
}

func TestReplicationJob(t *testing.T) {
	opt := libs.Options{
		Concurrency: 3,
		Threads:     5,
		Verbose:     true,
		NoDB:        true,
		NoOutput:    true,
	}
	URL := "http://httpbin.org:80"

	signContent := `
# info to search signature
id: cred-01-01
noutput: true
info:
  name: Default Credentials
  risk: High

ports: '8080,9000'
postfixes: 'foo,bar'

requests:
  - method: GET
    redirect: false
    url: >-
      {{.BaseURL}}/anything?aaaa=sample
    headers:
      - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55
    detections:
      - >-
        StatusCode() == 200

`
	sign, err := ParseSignFromContent(signContent)
	if err != nil {
		t.Errorf("Error parsing signature")

	}
	job := libs.Job{
		URL:  URL,
		Sign: sign,
	}

	jobs := []libs.Job{job}

	if job.Sign.Ports != "" || job.Sign.Prefixes != "" {
		moreJobs, err := ReplicationJob(job.URL, job.Sign)
		if err == nil {
			jobs = append(jobs, moreJobs...)
		}
	}

	for _, job := range jobs {
		runner, err := InitRunner(job.URL, job.Sign, opt)
		if err != nil {
			t.Errorf("Error replicate")
		}
		if len(runner.Records) == 0 {
			t.Errorf("Error replicate")
		}
		fmt.Println("New Requests generated: ", runner.Records[0].Request.URL)

	}

}
