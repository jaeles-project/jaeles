package core

import (
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/robertkrimen/otto"
	"os/exec"
	"regexp"
	"strings"
)

// RunConclusions set new value for next request
func RunConclusions(record libs.Record, sign *libs.Signature) {
	if len(record.Request.Conclusions) == 0 {
		return
	}
	for _, concludeScript := range record.Request.Conclusions {
		utils.DebugF("[Conclude]: %v", concludeScript)
		RunConclude(concludeScript, record, sign)
	}
}

// RunConclude run conclusion script
func RunConclude(concludeScript string, record libs.Record, sign *libs.Signature) {
	vm := otto.New()

	// ExecCmd execute command command
	vm.Set("ExecCmd", func(call otto.FunctionCall) otto.Value {
		result, _ := vm.ToValue(Execution(call.Argument(0).String()))
		return result
	})

	// write something to a file
	vm.Set("WriteTo", func(call otto.FunctionCall) otto.Value {
		dest := utils.NormalizePath(call.Argument(0).String())
		value := call.Argument(1).String()
		utils.WriteToFile(dest, value)
		return otto.Value{}
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
		_, validate := RegexSearch(component, analyzeString)
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

	// StringSelect select a string from component
	// e.g: StringSelect("component", "res1", "right", "left")
	vm.Set("StringSelect", func(call otto.FunctionCall) otto.Value {
		componentName := call.Argument(0).String()
		valueName := call.Argument(1).String()
		left := call.Argument(2).String()
		right := call.Argument(3).String()
		component := GetComponent(record, componentName)
		value := Between(component, left, right)
		sign.Target[valueName] = value
		utils.DebugF("StringSelect: %v --> %v", valueName, value)
		return otto.Value{}
	})

	//  - RegexSelect("component", "var_name", "regex")
	//  - RegexSelect("component", "var_name", "regex")
	vm.Set("RegexSelect", func(call otto.FunctionCall) otto.Value {
		valueName, value := RegexSelect(record, call.ArgumentList)
		if valueName != "" && value != "" {
			utils.DebugF("New variales: %v -- %v", valueName, value)
			sign.Target[valueName] = value
		}
		return otto.Value{}
	})

	// SetValue("var_name", StatusCode())
	// SetValue("status", StringCount('middleware', '11'))
	vm.Set("SetValue", func(call otto.FunctionCall) otto.Value {
		valueName := call.Argument(0).String()
		value := call.Argument(1).String()
		utils.DebugF("SetValue: %v -- %v", valueName, value)
		sign.Target[valueName] = value
		return otto.Value{}
	})

	vm.Run(concludeScript)
}

// Between get string between left and right
func Between(value string, left string, right string) string {
	// Get substring between two strings.
	posFirst := strings.Index(value, left)
	if posFirst == -1 {
		return ""
	}
	posLast := strings.Index(value, right)
	if posLast == -1 {
		return ""
	}
	posFirstAdjusted := posFirst + len(left)
	if posFirstAdjusted >= posLast {
		return ""
	}
	return value[posFirstAdjusted:posLast]
}

// RegexSelect get regex string from component
func RegexSelect(realRec libs.Record, arguments []otto.Value) (string, string) {
	//  - RegexSelect("component", "var_name", "regex")
	utils.DebugF("arguments -- %v", arguments)
	if len(arguments) < 1 {
		utils.DebugF("Invalid Conclude")
		return "", ""
	}
	componentName := arguments[0].String()
	valueName := arguments[1].String()
	component := GetComponent(realRec, componentName)
	regexString := arguments[2].String()

	// map all selected
	var myExp = regexp.MustCompile(regexString)
	match := myExp.FindStringSubmatch(component)
	if len(match) == 0 {
		utils.DebugF("No match found: %v", regexString)
	}
	result := make(map[string]string)
	for i, name := range myExp.SubexpNames() {
		if i != 0 && name != "" && len(match) > i {
			result[name] = match[i]
		}
	}
	utils.DebugF("RegexMatchs: %v", result)
	value, exist := result[valueName]
	if !exist {
		return "", ""
	}
	utils.DebugF("RegexSelect: %v --> %v", valueName, value)
	return valueName, value
}

// Execution Run a command
func Execution(cmd string) string {
	command := []string{
		"bash",
		"-c",
		cmd,
	}
	var output string
	utils.DebugF("[Exec] %v", command)
	realCmd := exec.Command(command[0], command[1:]...)
	out, _ := realCmd.CombinedOutput()
	output = string(out)
	return output
}
