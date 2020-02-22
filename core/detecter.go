package core

import (
	"fmt"
	"github.com/jaeles-project/jaeles/utils"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/parnurzeal/gorequest"

	"github.com/robertkrimen/otto"
)

// RunDetector is main function for detections
func RunDetector(record libs.Record, detectionString string) (string, bool) {
	var extra string
	vm := otto.New()

	// ExecCmd execute command command
	vm.Set("ExecCmd", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(Execution(call.Argument(0).String()))
		return result
	})

	// Printf print ouf some value, useful for debug
	vm.Set("Printf", func(call otto.FunctionCall) otto.Value {
		var err error
		args := call.ArgumentList
		componentName := args[0].String()
		grepString := "**"
		position := 0
		if len(args) > 1 {
			grepString = args[1].String()
			if len(args) > 2 {
				position, err = strconv.Atoi(args[2].String())
				if err != nil {
					position = 0
				}
			}
		}
		component := GetComponent(record, componentName)
		if grepString != "**" {
			r, rerr := regexp.Compile(grepString)
			if rerr == nil {
				matches := r.FindStringSubmatch(component)
				if len(matches) > 0 {
					if position <= len(matches) {
						component = matches[position]
					} else {
						component = matches[0]
					}
				}
			}
		}
		fmt.Println(component)
		result, _ := vm.ToValue(true)
		return result
	})

	vm.Set("StringGrepCmd", func(call otto.FunctionCall) otto.Value {
		command := call.Argument(0).String()
		searchString := call.Argument(0).String()
		result, _ := vm.ToValue(StringSearch(Execution(command), searchString))
		return result
	})

	vm.Set("RegexGrepCmd", func(call otto.FunctionCall) otto.Value {
		command := call.Argument(0).String()
		searchString := call.Argument(0).String()
		result, _ := vm.ToValue(RegexSearch(Execution(command), searchString))
		return result
	})

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
		result, err := vm.ToValue(validate)
		if err != nil {
			utils.ErrorF("Error Regex: %v", analyzeString)
			result, _ = vm.ToValue(false)
		}
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
	vm.Set("ResponseTime", func(call otto.FunctionCall) otto.Value {
		responseTime := record.Response.ResponseTime
		result, _ := vm.ToValue(responseTime)
		return result
	})
	vm.Set("ContentLength", func(call otto.FunctionCall) otto.Value {
		ContentLength := record.Response.Length
		result, _ := vm.ToValue(ContentLength)
		return result
	})

	vm.Set("HasPopUp", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(record.Response.HasPopUp)
		return result
	})

	// Origin field
	vm.Set("OriginStatusCode", func(call otto.FunctionCall) otto.Value {
		statusCode := record.OriginRes.StatusCode
		result, _ := vm.ToValue(statusCode)
		return result
	})
	vm.Set("OriginResponseTime", func(call otto.FunctionCall) otto.Value {
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

	// StringGrep select a string from component
	// e.g: StringGrep("component", "right", "left")
	vm.Set("StringSelect", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		left := call.Argument(2).String()
		right := call.Argument(3).String()
		component := GetComponent(record, componentName)
		value := Between(component, left, right)
		result, _ := vm.ToValue(value)
		return result
	})

	//  - RegexGrep("component", "regex")
	//  - RegexGrep("component", "regex", "position")
	vm.Set("RegexGrep", func(call otto.FunctionCall) otto.Value {
		value := RegexGrep(record, call.ArgumentList)
		result, _ := vm.ToValue(value)
		return result
	})

	vm.Set("ValueOf", func(call otto.FunctionCall) otto.Value {
		valueName := call.Argument(0).String()
		if record.Request.Target[valueName] != "" {
			value := record.Request.Target[valueName]
			result, _ := vm.ToValue(value)
			return result
		}
		result, _ := vm.ToValue(false)
		return result
	})

	// check if folder, file exist or not
	vm.Set("Exist", func(call otto.FunctionCall) otto.Value {
		input := utils.NormalizePath(call.Argument(0).String())
		var exist bool
		if utils.FileExists(input) {
			exist = true
		}
		if utils.FolderExists(input) {
			exist = true
		}
		result, _ := vm.ToValue(exist)
		return result
	})

	result, _ := vm.Run(detectionString)
	analyzeResult, err := result.Export()
	if err != nil || analyzeResult == nil {
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
	case "resheader":
		beautifyHeader := fmt.Sprintf("%v \n", record.Response.Status)
		for _, header := range record.Response.Headers {
			for key, value := range header {
				beautifyHeader += fmt.Sprintf("%v: %v\n", key, value)
			}
		}
		return beautifyHeader
	case "resheaders":
		beautifyHeader := fmt.Sprintf("%v \n", record.Response.Status)
		for _, header := range record.Response.Headers {
			for key, value := range header {
				beautifyHeader += fmt.Sprintf("%v: %v\n", key, value)
			}
		}
		return beautifyHeader
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

//utils.ErrorF("Error Compile Regex: %v", analyzeString)

// RegexCount count regex string in component
func RegexCount(component string, analyzeString string) int {
	r, err := regexp.Compile(analyzeString)
	if err != nil {
		return 0
	}
	matches := r.FindAllStringIndex(component, -1)
	return len(matches)
}

// RegexGrep grep regex string from component
func RegexGrep(realRec libs.Record, arguments []otto.Value) string {
	componentName := arguments[0].String()
	component := GetComponent(realRec, componentName)

	regexString := arguments[1].String()
	var position int
	var err error
	if len(arguments) > 2 {
		position, err = strconv.Atoi(arguments[2].String())
		if err != nil {
			position = 0
		}
	}

	var value string
	r, rerr := regexp.Compile(regexString)
	if rerr != nil {
		return ""
	}
	matches := r.FindStringSubmatch(component)
	if len(matches) > 0 {
		if position <= len(matches) {
			value = matches[position]
		} else {
			value = matches[0]
		}
	}
	return value
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
