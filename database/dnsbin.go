package database

// Use to gen bunch of DNS on  dns.requestbin.net

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/go-resty/resty"
	"github.com/gorilla/websocket"
)

// NewDNSBin create new dnsbin
func NewDNSBin() string {
	var dnsbin string
	// var .fbbbf336914aa6bd9b58.d.requestbin.net
	addr := "dns.requestbin.net:8080"
	u := url.URL{Scheme: "ws", Host: addr, Path: "/dns"}

	// init a connection
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return ""
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				os.Exit(1)
			}
			jsonParsed, err := gabs.ParseJSON([]byte(message))
			if err != nil {
				return
			}
			// jsonParsed.Path("master")
			prefix := strconv.FormatInt(time.Now().Unix(), 10)
			token := strings.Trim(fmt.Sprintf("%v", jsonParsed.Path("master")), `"`)
			dnsbin = fmt.Sprintf("%v.%v.d.requestbin.net", prefix, token)
			return
		}
	}()

	err = c.WriteMessage(websocket.TextMessage, []byte(``))
	if err != nil {
		return dnsbin
	}
	time.Sleep(time.Second)
	c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return dnsbin
}

// NewReqBin gen new http bin
func NewReqBin() string {
	var reqbin string
	url := fmt.Sprintf("https://bin-api.pipedream.com/api/v2/http_endpoints")
	prefix := strconv.FormatInt(time.Now().Unix(), 10)
	client := resty.New()
	body := fmt.Sprintf(`{"name":"%v","pvt":false}`, prefix)
	resp, err := client.R().
		SetBody([]byte(body)).
		Post(url)

	message := string(resp.Body())
	// {"status":0,"message":"success","data":{"api_key":"enw9yvvawe47","name":"Untitled","pvt":false,"created_at":"2019-11-20T10:56:29.962Z"}}
	jsonParsed, err := gabs.ParseJSON([]byte(message))
	if err != nil {
		return ""
	}
	// jsonParsed.Path("master")
	// prefix := strconv.FormatInt(time.Now().Unix(), 10)
	token := strings.Trim(fmt.Sprintf("%v", jsonParsed.Path("data.api_key")), `"`)
	reqbin = fmt.Sprintf("https://%v.x.pipedream.net/", token)
	if err != nil {
		return ""
	}

	return reqbin
}

// GetTS get current timestamp and return a string
func GetTS() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}
