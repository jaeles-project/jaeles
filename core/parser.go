package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v2"
)

// ParseSign parsing YAML signature file
func ParseSign(signFile string) (sign libs.Signature, err error) {
	yamlFile, err := ioutil.ReadFile(signFile)
	if err != nil {
		log.Printf("yamlFile.Get err  #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &sign)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	// set some default value
	if sign.Info.Category == "" {
		if strings.Contains(sign.ID, "-") {
			sign.Info.Category = strings.Split(sign.ID, "-")[0]
		} else {
			sign.Info.Category = sign.ID
		}
	}
	if sign.Info.Name == "" {
		sign.Info.Name = sign.ID
	}
	if sign.Info.Risk == "" {
		sign.Info.Risk = "Potential"
	}
	return sign, err
}

// ParseTarget parsing target and some variable for template
func ParseTarget(raw string) map[string]string {
	target := make(map[string]string)
	if raw == "" {
		return target
	}
	u, err := url.Parse(raw)

	// something wrong so parsing it again
	if err != nil || u.Scheme == "" || strings.Contains(u.Scheme, ".") {
		raw = fmt.Sprintf("https://%v", raw)
		u, err = url.Parse(raw)
		if err != nil {
			return target
		}
		// fmt.Println("parse again")
	}
	var hostname string
	port := u.Port()
	if u.Port() == "" {
		if strings.Contains(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}

		hostname = u.Hostname()
	} else {
		// ignore common port in Host
		if u.Port() == "443" || u.Port() == "80" {
			hostname = u.Hostname()
		} else {
			hostname = u.Hostname() + ":" + u.Port()
		}
	}

	target["Scheme"] = u.Scheme
	target["Path"] = u.Path
	target["Host"] = hostname
	target["Port"] = port
	target["BaseURL"] = fmt.Sprintf("%v://%v", target["Scheme"], target["Host"])
	target["URL"] = fmt.Sprintf("%v://%v%v", target["Scheme"], target["Host"], target["Path"])
	target["Extension"] = filepath.Ext(target["BaseURL"])

	ssrf := database.GetDefaultBurpCollab()
	if ssrf != "" {
		target["oob"] = ssrf
	} else {
		target["oob"] = database.GetCollab()
	}

	return target
}

// MoreVariables get more options to render in sign template
func MoreVariables(target map[string]string, options libs.Options) map[string]string {
	realTarget := target
	// more options
	realTarget["homePath"] = options.RootFolder
	realTarget["proxy"] = options.Proxy
	realTarget["output"] = options.Output
	return realTarget
}

// JoinURL just joining baseURL with path
func JoinURL(base string, child string) string {
	u, err := url.Parse(child)
	if err != nil {
		log.Fatal(err)
	}
	result, err := url.Parse(base)
	if err != nil {
		log.Fatal(err)
	}
	return result.ResolveReference(u).String()
}

// ParseRequest parse request part in YAML signature file
func ParseRequest(req libs.Request, sign libs.Signature) []libs.Request {
	var Reqs []libs.Request
	if sign.Type == "list" && len(sign.Variables) > 0 {
		realVariables := ParseVariable(sign)
		// Replace template with variable
		// @TODO: adding multple variable later
		for _, variable := range realVariables {
			target := sign.Target
			// replace here
			for k, v := range variable {
				target[k] = v
			}

			// in case we only want to run a middleware alone
			if req.Raw != "" {
				rawReq := ResolveVariable(req.Raw, target)
				burpReq := ParseBurpRequest(rawReq)
				burpReq.Detections = ResolveDetection(req.Detections, target)
				burpReq.Middlewares = ResolveDetection(req.Middlewares, target)
				Reqs = append(Reqs, burpReq)
			}
			if req.Path == "" && funk.IsEmpty(req.Middlewares) {
				continue
			} else if !funk.IsEmpty(req.Middlewares) {
				Req := req
				Req.Middlewares = ResolveDetection(req.Middlewares, target)
				Reqs = append(Reqs, Req)
				continue
			}
			Req := req
			Req.URL = ResolveVariable(req.Path, target)
			Req.Body = ResolveVariable(req.Body, target)
			Req.Headers = ResolveHeader(req.Headers, target)
			Req.Detections = ResolveDetection(req.Detections, target)
			Req.Middlewares = ResolveDetection(req.Middlewares, target)
			Req.Redirect = req.Redirect
			if Req.URL != "" {
				Reqs = append(Reqs, Req)
			}
		}
	}
	if sign.Type == "" || sign.Type == "single" {
		Req := req
		target := sign.Target
		// in case we only want to run a middleware alone

		if req.Raw != "" {
			rawReq := ResolveVariable(req.Raw, target)
			burpReq := ParseBurpRequest(rawReq)
			burpReq.Detections = ResolveDetection(req.Detections, target)
			Req.Middlewares = ResolveDetection(req.Middlewares, target)
			Reqs = append(Reqs, burpReq)
		}
		if req.Path != "" {
			Req.URL = ResolveVariable(req.Path, target)
			Req.Body = ResolveVariable(req.Body, target)
			Req.Headers = ResolveHeader(req.Headers, target)
			Req.Detections = ResolveDetection(req.Detections, target)
			Req.Middlewares = ResolveDetection(req.Middlewares, target)
			Req.Redirect = req.Redirect
			if Req.URL != "" {
				Reqs = append(Reqs, Req)
			}
		} else if !funk.IsEmpty(req.Middlewares) {
			Req.Middlewares = ResolveDetection(req.Middlewares, target)
			Reqs = append(Reqs, Req)
		}

	}

	return Reqs
}

// ParseVariable parse variable in YAML signature file
func ParseVariable(sign libs.Signature) []map[string]string {
	var realVariables []map[string]string
	rawVariables := make(map[string][]string)
	// reading variable
	for _, variable := range sign.Variables {
		for key, value := range variable {
			// strip out blank line
			if strings.Trim(value, " ") == "" {
				continue
			}
			/*
				- variable: [google.com,example.com]
			*/
			// variable as a list
			if strings.HasPrefix(value, "[") && strings.Contains(value, ",") {
				rawVar := strings.Trim(value[1:len(value)-1], " ")
				rawVariables[key] = strings.Split(rawVar, ",")
				continue
			}
			/*
				- variable: |
					google.com
					example.com
			*/
			if strings.Contains(value, "\n") {
				value = strings.Trim(value, "\n\n")
				rawVariables[key] = strings.Split(value, "\n")
				continue
			}

			// variable as a file
			rawVariables[key] = ReadingFile(value)
		}
	}

	if len(rawVariables) == 1 {
		for k, v := range rawVariables {
			variable := make(map[string]string)
			for _, value := range v {
				variable[k] = value
			}
			realVariables = append(realVariables, variable)
		}
		return realVariables
	}

	// select max number of list
	var maxLength int
	for _, v := range rawVariables {
		if maxLength < len(v) {
			maxLength = len(v)
		}
	}

	// make all variable to same length
	Variables := make(map[string][]string)
	for k, v := range rawVariables {
		Variables[k] = ExpandLength(v, maxLength)
	}

	// join all together to make list of map variable
	for i := 1; i <= maxLength; i++ {
		variable := make(map[string]string)
		for k, v := range Variables {
			variable[k] = v[i]
		}
		realVariables = append(realVariables, variable)
	}

	return realVariables
}

// ParseFuzzRequest parse request recive in API server
func ParseFuzzRequest(record libs.Record, sign libs.Signature) []libs.Request {
	req := record.Request
	var Reqs []libs.Request

	// color.Green("-- Start do Injecting")
	if req.URL == "" {
		req.URL = record.OriginReq.URL
	}
	Reqs = Generators(req, sign)
	return Reqs
}

// ParsePayloads parse payload to replace
func ParsePayloads(sign libs.Signature) []string {
	payloads := []string{}
	payloads = append(payloads, sign.Payloads...)
	if len(sign.PayloadLists) > 0 {
		for _, payloadFile := range sign.PayloadLists {
			realPayloads := ReadingFile(payloadFile)
			if len(realPayloads) > 0 {
				payloads = append(payloads, realPayloads...)
			}
		}
	} else {
		payloads = append(payloads, "")
	}
	return payloads
}

// ParseBurpRequest parse burp style request
func ParseBurpRequest(raw string) (req libs.Request) {
	var realReq libs.Request
	realReq.Raw = raw
	reader := bufio.NewReader(strings.NewReader(raw))
	parsedReq, err := http.ReadRequest(reader)
	if err != nil {
		return realReq
	}
	realReq.Method = parsedReq.Method
	// URL part
	if parsedReq.URL.Host == "" {
		realReq.Host = parsedReq.Host
		parsedReq.URL.Host = parsedReq.Host
	}
	if parsedReq.URL.Scheme == "" {
		if parsedReq.Referer() == "" {
			realReq.Scheme = "https"
			parsedReq.URL.Scheme = "https"
		} else {
			u, err := url.Parse(parsedReq.Referer())
			if err == nil {
				realReq.Scheme = u.Scheme
				parsedReq.URL.Scheme = u.Scheme
			}
		}
	}
	// fmt.Println(parsedReq.URL)
	// parsedReq.URL.RequestURI = parsedReq.RequestURI
	realReq.URL = parsedReq.URL.String()
	realReq.Path = parsedReq.RequestURI
	realReq.Headers = ParseHeaders(parsedReq.Header)

	body, _ := ioutil.ReadAll(parsedReq.Body)
	realReq.Body = string(body)

	return realReq
}

// ParseHeaders parse header for sending method
func ParseHeaders(rawHeaders map[string][]string) []map[string]string {
	var headers []map[string]string
	for name, value := range rawHeaders {
		header := map[string]string{
			name: strings.Join(value[:], ""),
		}
		headers = append(headers, header)
	}
	return headers
}

// ParseBurpResponse parse burp style response
func ParseBurpResponse(rawReq string, rawRes string) (res libs.Response) {
	// var res libs.Response
	readerr := bufio.NewReader(strings.NewReader(rawReq))
	parsedReq, _ := http.ReadRequest(readerr)

	reader := bufio.NewReader(strings.NewReader(rawRes))
	parsedRes, err := http.ReadResponse(reader, parsedReq)
	if err != nil {
		return res
	}

	res.Status = fmt.Sprintf("%v %v", parsedRes.Status, parsedRes.Proto)
	res.StatusCode = parsedRes.StatusCode

	var headers []map[string]string
	for name, value := range parsedReq.Header {
		header := map[string]string{
			name: strings.Join(value[:], ""),
		}
		headers = append(headers, header)
	}
	res.Headers = headers

	body, _ := ioutil.ReadAll(parsedRes.Body)
	res.Body = string(body)

	return res
}

// ParseRequestFromServer parse request recive from API server
func ParseRequestFromServer(record *libs.Record, req libs.Request, sign libs.Signature) {
	if req.Raw != "" {
		parsedReq := ParseBurpRequest(req.Raw)
		// check if parse request ok
		if parsedReq.Method != "" {
			record.Request = parsedReq
		} else {
			record.Request = record.OriginReq
		}
	} else {
		record.Request = record.OriginReq
	}

	// get some component from sign
	if req.Method != "" {
		record.Request.Method = req.Method
	}
	if req.Path != "" {
		record.Request.Path = req.Path
	} else {
		record.Request.Path = record.Request.URL
	}
	if req.Body != "" {
		record.Request.Body = req.Body
	}

	// header stuff
	if len(req.Headers) > 0 {
		realHeaders := req.Headers
		keys := []string{}
		for _, realHeader := range req.Headers {
			for key := range realHeader {
				keys = append(keys, key)
			}
		}
		for _, rawHeader := range record.Request.Headers {
			for key := range rawHeader {
				// only add header we didn't define
				if !funk.Contains(keys, key) {
					realHeaders = append(realHeaders, rawHeader)
				}
			}
		}
		record.Request.Headers = realHeaders
	}
	record.Request.Generators = req.Generators
	record.Request.Encoding = req.Encoding
	record.Request.Middlewares = req.Middlewares
	record.Request.Redirect = req.Redirect

	// resolve some template
	target := ParseTarget(record.Request.URL)
	record.Request.URL = ResolveVariable(record.Request.Path, target)
	record.Request.Body = ResolveVariable(record.Request.Body, target)
	record.Request.Headers = ResolveHeader(record.Request.Headers, target)
	record.Request.Detections = ResolveDetection(req.Detections, target)
}

/* Resolve template part */
// ResolveDetection resolve detection part in YAML signature file
func ResolveDetection(detections []string, target map[string]string) []string {
	var realDetections []string
	for _, detect := range detections {
		realDetections = append(realDetections, ResolveVariable(detect, target))
	}
	return realDetections
}

// ResolveHeader resolve headers part in YAML signature file
func ResolveHeader(headers []map[string]string, target map[string]string) []map[string]string {
	// realHeaders := headers
	var realHeaders []map[string]string

	for _, head := range headers {
		realHeader := make(map[string]string)
		for key, value := range head {
			realKey := ResolveVariable(key, target)
			realVal := ResolveVariable(value, target)
			realHeader[realKey] = realVal
		}
		realHeaders = append(realHeaders, realHeader)
	}

	return realHeaders
}

// ResolveVariable resolve template from signature file
func ResolveVariable(format string, data map[string]string) string {
	t := template.Must(template.New("").Parse(format))

	buf := &bytes.Buffer{}
	err := t.Execute(buf, data)
	if err != nil {
		return format
	}
	return buf.String()
}
