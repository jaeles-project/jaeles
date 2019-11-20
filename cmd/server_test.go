package cmd

import (
	"fmt"
	"testing"

	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/libs"
)

func TestServerWithSign(t *testing.T) {
	raw := `GET /rest/sample/redirect?to=localhoost&example=123 HTTP/1.1
	Host: juice-shop.herokuapp.com
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3968.0 Safari/537.36
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
	Accept-Encoding: gzip, deflate
	Accept-Language: en-US,en;q=0.9
	Connection: close
	Cookie: language=en
	Upgrade-Insecure-Requests: 1
	`
	var record libs.Record
	record.OriginReq = core.ParseBurpRequest(raw)
	signFile := "../test-sign/open-redirect.yaml"
	sign, err := core.ParseSign(signFile)
	if err != nil {
		t.Errorf("Error parsing signature")
	}
	for _, req := range sign.Requests {
		core.ParseRequestFromServer(&record, req, sign)
		// send origin request
		Reqs := core.ParseFuzzRequest(record, sign)

		if len(Reqs) == 0 {
			t.Errorf("Error generate Path")
		}
		for _, req := range Reqs {
			fmt.Println(req.Method, req.URL)
			// fmt.Println(req.URL)
		}
	}
}
