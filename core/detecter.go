package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/parnurzeal/gorequest"

	"github.com/robertkrimen/otto"
)

/*
@TODO: Add OOB check from Burp Collab and dnsbin.zhack.ca
*/

// RunDetector is main function for detections
func RunDetector(record libs.Record, detectionString string) (string, bool) {
	var extra string
	vm := otto.New()
	vm.Set("StringSearch", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := StringSearch(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StringCount", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := StringCount(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("RegexSearch", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := RegexSearch(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("RegexCount", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		analyzeString := call.Argument(1).String()
		component := GetComponent(record, componentName)
		validate := RegexCount(component, analyzeString)
		result, _ := vm.ToValue(validate)
		return result
	})

	vm.Set("StatusCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.Response.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("ResponeTime", func(call otto.FunctionCall) otto.Value {
		responseTime := record.Response.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("ContentLength", func(call otto.FunctionCall) otto.Value {
		ContentLength := record.Response.Length
		result, _ := vm.ToValue(ContentLength)
		return result
	})

	// Origin field
	vm.Set("OriginStatusCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.OriginRes.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("OriginResponeTime", func(call otto.FunctionCall) otto.Value {
		responseTime := record.OriginRes.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("OriginContentLength", func(call otto.FunctionCall) otto.Value {
		ContentLength := record.OriginRes.Length
		result, _ := vm.ToValue(ContentLength)
		return result
	})
	vm.Set("Collab", func(call otto.FunctionCall) otto.Value {
		analyzeString := call.Argument(0).String()
		res, validate := PollCollab(record, analyzeString)
		extra = res
		result, _ := vm.ToValue(validate)
		return result
	})

	result, _ := vm.Run(detectionString)
	analyzeResult, err := result.Export()
	if err != nil {
		return "", false
	}
	return extra, analyzeResult.(bool)
}

// GetComponent get component to run detection
func GetComponent(record libs.Record, component string) string {
	switch strings.ToLower(component) {
	case "orequest":
		return record.OriginReq.Beautify
	case "oresponse":
		return record.OriginRes.Beautify
	case "request":
		return record.Request.Beautify
	case "response":
		if record.Response.Beautify == "" {
			return record.Response.Body
		}
		return record.Response.Beautify
	case "resbody":
		return record.Response.Body
	case "middleware":
		return record.Request.MiddlewareOutput
	default:
		return record.Response.Beautify
	}
}

// StringSearch search string literal in component
func StringSearch(component string, analyzeString string) bool {
	if strings.Contains(component, analyzeString) {
		return true
	}
	return false
}

// StringCount count string literal in component
func StringCount(component string, analyzeString string) int {
	return strings.Count(component, analyzeString)
}

// RegexSearch search regex string in component
func RegexSearch(component string, analyzeString string) bool {
	r, err := regexp.Compile(analyzeString)
	if err != nil {
		return false
	}
	return r.MatchString(component)
}

// RegexCount count regex string in component
func RegexCount(component string, analyzeString string) int {
	r, err := regexp.Compile(analyzeString)
	if err != nil {
		return 0
	}
	matches := r.FindAllStringIndex(component, -1)
	return len(matches)
}

// PollCollab polling burp collab with secret from DB
func PollCollab(record libs.Record, analyzeString string) (string, bool) {
	// only checking response return in external OOB
	ssrf := database.GetDefaultBurpCollab()
	if ssrf != "" {
		res := database.GetDefaultBurpRes()
		result := StringSearch(record.Response.Beautify, res)
		return res, result
	}

	// storing raw here so we can poll later
	database.ImportReqLog(record, analyzeString)
	secretCollab := url.QueryEscape(database.GetSecretbyCollab(analyzeString))

	// poll directly
	url := fmt.Sprintf("http://polling.burpcollaborator.net/burpresults?biid=%v", secretCollab)
	_, response, _ := gorequest.New().Get(url).End()
	jsonParsed, _ := gabs.ParseJSON([]byte(response))
	exists := jsonParsed.Exists("responses")
	if exists == false {
		data := database.GetOOB(analyzeString)
		if data != "" {
			return data, strings.Contains(data, analyzeString)
		}
		return "", false
	}

	// jsonParsed.Path("responses").Children()
	for _, element := range jsonParsed.Path("responses").Children() {
		protocol := element.Path("protocol").Data().(string)
		// import this to DB so we don't miss in other detect
		database.ImportOutOfBand(fmt.Sprintf("%v", element))
		if protocol == "http" {
			interactionString := element.Path("interactionString").Data().(string)
			return element.String(), strings.Contains(analyzeString, interactionString)
		} else if protocol == "dns" {
			interactionString := element.Path("interactionString").Data().(string)
			return element.String(), strings.Contains(analyzeString, interactionString)
		}
	}

	return "", false
}
