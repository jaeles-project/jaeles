package core

import (
	"encoding/base64"
	"fmt"
	"github.com/thoas/go-funk"
	"math/rand"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/robertkrimen/otto"
)

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

			// variable as a script
			if strings.Contains(value, "(") && strings.Contains(value, ")") {
				if strings.Contains(value, "{{.") && strings.Contains(value, "}}") {
					value = ResolveVariable(value, sign.Target)
				}
				rawVariables[key] = RunVariables(value)
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
		}
	}

	if len(rawVariables) == 1 {
		for k, v := range rawVariables {
			for _, value := range v {
				variable := make(map[string]string)
				variable[k] = value
				realVariables = append(realVariables, variable)
			}
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

	// @TODO: Need to improve this
	if len(rawVariables) > 1 && len(rawVariables) <= 3 {
		keys := funk.Keys(rawVariables).([]string)
		list1 := rawVariables[keys[0]]
		list2 := rawVariables[keys[1]]

		if len(rawVariables) == 2 {
			for _, item1 := range list1 {
				// loop in second var
				for _, item2 := range list2 {
					element := make(map[string]string)
					element[keys[0]] = item1
					element[keys[1]] = item2
					realVariables = append(realVariables, element)
				}
			}
		} else if len(rawVariables) == 3 {
			list3 := rawVariables[keys[2]]
			for _, item1 := range list1 {
				// loop in second var
				for _, item2 := range list2 {
					// loop in third var
					for _, item3 := range list3 {
						element := make(map[string]string)
						element[keys[0]] = item1
						element[keys[1]] = item2
						element[keys[2]] = item3
						realVariables = append(realVariables, element)
					}
				}
			}
		}

		//fmt.Println("realVariables: ", realVariables)
		//fmt.Println("len(realVariables): ", len(realVariables))
		return realVariables
	}

	// make all variable to same length
	Variables := make(map[string][]string)
	for k, v := range rawVariables {
		Variables[k] = utils.ExpandLength(v, maxLength)
	}

	// join all together to make list of map variable
	for i := 0; i < maxLength; i++ {
		for j := 0; j < maxLength; j++ {
			variable := make(map[string]string)
			for k, v := range Variables {
				variable[k] = v[j]
			}
			realVariables = append(realVariables, variable)
		}
	}

	seen := make(map[string]bool)
	// just unique the variables
	var uniqVariables []map[string]string
	for index := 0; index < len(realVariables); index++ {
		for k, v := range realVariables[index] {
			val := fmt.Sprintf("%v%v", k, v)
			if _, ok := seen[val]; !ok {
				// fmt.Println(k, v)
				seen[val] = true
				uniqVariables = append(uniqVariables, realVariables[index])
			}
		}
	}

	return uniqVariables
}

// RunVariables is main function for detections
func RunVariables(variableString string) []string {
	var extra []string
	if !strings.Contains(variableString, "(") {
		return extra
	}

	vm := otto.New()
	vm.Set("ExecJS", func(call otto.FunctionCall) otto.Value {
		jscode := call.Argument(0).String()
		value, err := vm.Run(jscode)
		if err == nil {
			data := value.String()
			extra = append(extra, data)
		}
		return otto.Value{}
	})

	vm.Set("File", func(call otto.FunctionCall) otto.Value {
		filename := call.Argument(0).String()
		filename = utils.NormalizePath(filename)
		data := utils.ReadingLines(filename)
		if len(data) > 0 {
			extra = append(extra, data...)
		}
		return otto.Value{}
	})

	vm.Set("InputCmd", func(call otto.FunctionCall) otto.Value {
		cmd := call.Argument(0).String()
		data := InputCmd(cmd)
		if len(data) <= 0 {
			return otto.Value{}
		}
		if !strings.Contains(data, "\n") {
			extra = append(extra, data)
			return otto.Value{}
		}
		extra = append(extra, strings.Split(data, "\n")...)
		return otto.Value{}
	})

	vm.Set("RandomString", func(call otto.FunctionCall) otto.Value {
		length, err := strconv.Atoi(call.Argument(0).String())
		if err != nil {
			return otto.Value{}
		}
		extra = append(extra, RandomString(length))
		return otto.Value{}
	})

	vm.Set("RandomNumber", func(call otto.FunctionCall) otto.Value {
		length, err := strconv.Atoi(call.Argument(0).String())
		if err != nil {
			return otto.Value{}
		}
		extra = append(extra, RandomNumber(length))
		return otto.Value{}
	})

	vm.Set("Range", func(call otto.FunctionCall) otto.Value {
		min, err := strconv.Atoi(call.Argument(0).String())
		max, err := strconv.Atoi(call.Argument(1).String())
		if err != nil {
			return otto.Value{}
		}
		for i := min; i < max; i++ {
			extra = append(extra, fmt.Sprintf("%v", i))
		}
		return otto.Value{}
	})

	vm.Set("SplitLines", func(call otto.FunctionCall) otto.Value {
		data := call.Argument(0).String()
		extra = append(extra, SplitLines(data)...)
		return otto.Value{}
	})

	vm.Set("Base64Encode", func(call otto.FunctionCall) otto.Value {
		data := call.Argument(0).String()
		extra = append(extra, Base64Encode(data))
		return otto.Value{}
	})

	vm.Set("Base64EncodeByLines", func(call otto.FunctionCall) otto.Value {
		data := SplitLines(call.Argument(0).String())
		if len(data) == 0 {
			return otto.Value{}
		}
		for _, line := range data {
			extra = append(extra, Base64Encode(line))
		}
		return otto.Value{}
	})

	vm.Set("URLEncode", func(call otto.FunctionCall) otto.Value {
		data := call.Argument(0).String()
		extra = append(extra, URLEncode(data))
		return otto.Value{}
	})

	vm.Set("URLEncodeByLines", func(call otto.FunctionCall) otto.Value {
		data := SplitLines(call.Argument(0).String())
		if len(data) == 0 {
			return otto.Value{}
		}
		for _, line := range data {
			extra = append(extra, URLEncode(line))
		}
		return otto.Value{}
	})

	utils.DebugF("variableString: %v", variableString)
	vm.Run(variableString)
	return extra
}

// RandomString return a random string with length
func RandomString(n int) string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

// RandomNumber return a random number with length
func RandomNumber(n int) string {
	var letter = []rune("0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	result := string(b)
	if !strings.HasPrefix(result, "0") || len(result) == 1 {
		return result
	}
	return result[1:]
}

// InputCmd take input as os command
// @NOTE: this is a feature not an RCE :P
func InputCmd(Cmd string) string {
	command := []string{
		"bash",
		"-c",
		Cmd,
	}
	out, _ := exec.Command(command[0], command[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// SplitLines just split new Line
func SplitLines(raw string) []string {
	var result []string
	if strings.Contains(raw, "\n") {
		result = strings.Split(raw, "\n")
	}
	return result
}

// Base64Encode just Base64 Encode
func Base64Encode(raw string) string {
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// URLEncode just URL Encode
func URLEncode(raw string) string {
	return url.QueryEscape(raw)
}
