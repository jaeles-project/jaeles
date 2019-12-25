package core

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/jaeles-project/jaeles/libs"
	"github.com/thoas/go-funk"

	"github.com/robertkrimen/otto"
)

// @NOTE: This middleware allow execute command on your machine
// So make sure you trusted authenticaed user because he can create a signature.

// MiddleWare is main function for middleware
func MiddleWare(rec *libs.Record, options libs.Options) {
	// func MiddleWare(req *libs.Request) {
	vm := otto.New()

	vm.Set("Host2IP", func(call otto.FunctionCall) otto.Value {
		var realHeaders []map[string]string
		for _, head := range rec.Request.Headers {
			containHost := funk.Contains(head, "Host")
			if containHost == false {
				realHeaders = append(realHeaders, head)
			}
		}
		HostHeader := Host2IP(rec.Request.URL)
		if !funk.IsEmpty(HostHeader) {
			realHeaders = append(realHeaders, HostHeader)
		}
		rec.Request.Headers = realHeaders
		return otto.Value{}
	})

	vm.Set("InvokeCmd", func(call otto.FunctionCall) otto.Value {
		rawCmd := call.Argument(0).String()
		result := InvokeCmd(&rec.Request, rawCmd)
		if options.Verbose {
			fmt.Println(result)
		}
		return otto.Value{}
	})

	vm.Set("TurboIntruder", func(call otto.FunctionCall) otto.Value {
		if rec.Request.Raw != "" {
			result := TurboIntruder(rec)
			if options.Verbose {
				fmt.Println(result)
			}
		}

		return otto.Value{}
	})

	for _, middleString := range rec.Request.Middlewares {
		libs.DebugF(middleString)
		vm.Run(middleString)
	}
}

// Host2IP replace Host header with IP address
func Host2IP(rawURL string) map[string]string {
	// HostHeader =
	u, err := url.Parse(rawURL)
	if err != nil {
		return map[string]string{}
	}
	hostname := u.Hostname()
	resolved, err := net.LookupHost(hostname)
	if err != nil {
		return map[string]string{}
	}

	ip := resolved[0]
	if u.Port() == "443" || u.Port() == "80" || u.Port() == "" {
		hostname = ip
	} else {
		hostname = ip + ":" + u.Port()
	}

	return map[string]string{"Host": hostname}
}

// InvokeCmd execute external command
func InvokeCmd(req *libs.Request, rawCmd string) string {
	target := ParseTarget(req.URL)
	realCommand := Encoder(req.Encoding, ResolveVariable(rawCmd, target))
	command := []string{
		"bash",
		"-c",
		realCommand,
	}
	out, _ := exec.Command(command[0], command[1:]...).CombinedOutput()
	req.MiddlewareOutput = string(out)
	return realCommand
}

// TurboIntruder execute Turbo Intruder CLI
func TurboIntruder(rec *libs.Record) string {
	req := rec.Request
	turboPath := ResolveVariable("{{.homePath}}/plugins/turbo-intruder/turbo-intruder-all.jar", req.Target)
	scriptPath := ResolveVariable("{{.homePath}}/plugins/turbo-intruder/basic.py", req.Target)

	// create a folder in case it didn't exist
	logReqPath := ResolveVariable("{{.homePath}}/log/req/", req.Target)
	url := ResolveVariable("{{.URL}}", req.Target)
	rec.Request.URL = url
	if _, err := os.Stat(logReqPath); os.IsNotExist(err) {
		os.MkdirAll(logReqPath, 0750)
	}
	// write request to a file
	rawReq := ResolveVariable(req.Raw, req.Target)
	reqPath := path.Join(logReqPath, GenHash(rawReq))
	WriteToFile(reqPath, rawReq)

	// call the command and parse some info
	turboCmd := fmt.Sprintf(`java -jar %v %v %v %v foo`, turboPath, scriptPath, reqPath, url)

	command := []string{
		"bash",
		"-c",
		turboCmd,
	}
	out, _ := exec.Command(command[0], command[1:]...).CombinedOutput()

	// parse output
	rawOutput := string(out)
	if strings.Contains(rawOutput, "=-+-================") {
		// split the prefix
		resp := strings.Split(rawOutput, "=-+-================")[1]
		result := strings.Split(resp, "------------------+=")

		// [Info] 403 11585 0.272
		info := result[0]
		statusCode, _ := strconv.Atoi(strings.Split(info, " ")[1])
		rec.Response.StatusCode = statusCode

		length, _ := strconv.Atoi(strings.Split(info, " ")[2])
		rec.Response.Length = length

		resTime, _ := strconv.ParseFloat(strings.TrimSpace(strings.Split(info, " ")[2]), 64)
		rec.Response.ResponseTime = resTime

		rec.Request.Beautify = result[1]
		rec.Response.Beautify = result[2]
		verbose := fmt.Sprintf("[TurboIntruder] %v %v %v %v", rec.Request.URL, reqPath, rec.Response.StatusCode, rec.Response.ResponseTime)
		return verbose
	} else {
		verbose := fmt.Sprintf("[TurboIntruder] Error sending request from: %v", reqPath)
		return verbose
	}
}
