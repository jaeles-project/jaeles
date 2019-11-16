package core

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/robertkrimen/otto"
	"github.com/thoas/go-funk"
)

// Generators run multiple generator
func Generators(req libs.Request, sign libs.Signature) []libs.Request {
	var reqs []libs.Request
	realPayloads := ParsePayloads(sign)
	for _, payload := range realPayloads {
		for _, genString := range req.Generators {
			injectedReqs := RunGenerator(req, payload, genString)
			reqs = append(reqs, injectedReqs...)
		}
	}

	return reqs
}

// RunGenerator is main function for generator
func RunGenerator(req libs.Request, payload string, genString string) []libs.Request {
	var reqs []libs.Request
	vm := otto.New()

	vm.Set("Query", func(call otto.FunctionCall) otto.Value {
		injectedReq := Query(req, payload, call.ArgumentList)
		if len(injectedReq) > 0 {
			reqs = append(reqs, injectedReq...)
		}
		return otto.Value{}
	})

	vm.Set("Body", func(call otto.FunctionCall) otto.Value {
		injectedReq := Body(req, payload, call.ArgumentList)
		if len(injectedReq) > 0 {
			reqs = append(reqs, injectedReq...)
		}
		return otto.Value{}
	})

	vm.Set("Path", func(call otto.FunctionCall) otto.Value {
		injectedReq := Path(req, payload, call.ArgumentList)
		if len(injectedReq) > 0 {
			reqs = append(reqs, injectedReq...)
		}
		return otto.Value{}
	})

	vm.Set("Header", func(call otto.FunctionCall) otto.Value {
		injectedReq := Header(req, payload, call.ArgumentList)
		if len(injectedReq) > 0 {
			reqs = append(reqs, injectedReq...)
		}
		return otto.Value{}
	})

	vm.Set("Cookie", func(call otto.FunctionCall) otto.Value {
		injectedReq := Cookie(req, payload, call.ArgumentList)
		if len(injectedReq) > 0 {
			reqs = append(reqs, injectedReq...)
		}

		return otto.Value{}
	})

	vm.Set("Method", func(call otto.FunctionCall) otto.Value {
		if len(reqs) > 0 {
			for _, req := range reqs {
				injectedReq := Method(req, call.ArgumentList)
				reqs = append(reqs, injectedReq...)
			}
		} else {
			injectedReq := Method(req, call.ArgumentList)
			reqs = append(reqs, injectedReq...)
		}
		return otto.Value{}
	})

	vm.Run(genString)
	return reqs
}

// Encoder encoding part after resolve
func Encoder(encodeString string, data string) string {
	if encodeString == "" {
		return data
	}
	var result string
	vm := otto.New()

	// Encode part
	vm.Set("URL", func(call otto.FunctionCall) otto.Value {
		result = url.QueryEscape(data)
		return otto.Value{}
	})

	vm.Run(encodeString)
	return result
}

// Method gen request with multiple method
func Method(req libs.Request, arguments []otto.Value) []libs.Request {
	methods := []string{"GET", "POST", "PUT", "HEAD", "PATCH"}
	if len(arguments) > 0 {
		methods = []string{strings.ToUpper(arguments[0].String())}
	}
	var reqs []libs.Request
	for _, method := range methods {
		injectedReq := req
		injectedReq.Method = method
		reqs = append(reqs, injectedReq)
	}

	return reqs
}

// Query gen request with query string
func Query(req libs.Request, payload string, arguments []otto.Value) []libs.Request {
	injectedString := arguments[0].String()
	paramName := "undefined"
	if len(arguments) > 1 {
		paramName = arguments[1].String()
	}

	var reqs []libs.Request
	rawURL := req.URL
	target := ParseTarget(rawURL)
	target["payload"] = payload
	u, _ := url.Parse(rawURL)

	// replace one or create a new one if they're not exist
	if paramName != "undefined" {
		injectedReq := req
		uu, _ := url.Parse(injectedReq.URL)
		target["original"] = uu.Query().Get(paramName)
		// only replace value for now
		newValue := ResolveVariable(injectedString, target)
		query := uu.Query()
		query.Set(paramName, newValue)
		uu.RawQuery = query.Encode()

		injectedReq.URL = uu.String()
		reqs = append(reqs, injectedReq)
		return reqs
	}

	for key, value := range u.Query() {
		injectedReq := req
		uu, _ := url.Parse(injectedReq.URL)
		if len(value) == 1 {
			target["original"] = strings.Join(value[:], "")
		}
		// only replace value for now
		newValue := ResolveVariable(injectedString, target)

		query := uu.Query()
		query.Set(key, newValue)
		uu.RawQuery = query.Encode()

		injectedReq.URL = uu.String()
		reqs = append(reqs, injectedReq)
	}
	// return rawURL
	return reqs
}

// Body gen request with body
func Body(req libs.Request, payload string, arguments []otto.Value) []libs.Request {
	injectedString := arguments[0].String()
	paramName := "undefined"
	if len(arguments) > 1 {
		paramName = arguments[1].String()
	}

	var reqs []libs.Request
	rawURL := req.URL
	target := ParseTarget(rawURL)
	target["payload"] = payload

	rawBody := req.Body
	// @TODO: deal with XML body later
	// @TODO: deal with multipart form later
	if paramName == "undefined" {
		// var newBody []string
		if rawBody != "" {

			// @TODO: inject for all child node, only 3 depth for now
			if IsJSON(rawBody) {
				jsonParsed, _ := gabs.ParseJSON([]byte(rawBody))
				for key, child := range jsonParsed.ChildrenMap() {
					injectedReq := req
					if len(child.Children()) == 0 {
						str := fmt.Sprint(child)
						target["original"] = str
						newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
						jsonBody, _ := gabs.ParseJSON([]byte(rawBody))
						jsonBody.Set(newValue, key)
						injectedReq.Body = jsonBody.String()
						reqs = append(reqs, injectedReq)

					} else {
						// depth 2
						for _, ch := range child.Children() {
							if len(ch.Children()) == 0 {
								str := fmt.Sprint(child)
								target["original"] = str
								newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
								jsonBody, _ := gabs.ParseJSON([]byte(rawBody))
								jsonBody.Set(newValue, key)
								injectedReq.Body = jsonBody.String()
								reqs = append(reqs, injectedReq)
							} else {
								// depth 3
								for _, ch := range child.Children() {
									if len(ch.Children()) == 0 {
										str := fmt.Sprint(child)
										target["original"] = str
										newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
										jsonBody, _ := gabs.ParseJSON([]byte(rawBody))
										jsonBody.Set(newValue, key)
										injectedReq.Body = jsonBody.String()
										reqs = append(reqs, injectedReq)
									}
								}
							}
						}
					}
					// dd, ok := nn[1].Data().(int)
				}

			} else {
				// normal form body
				params := strings.SplitN(rawBody, "&", -1)
				for index, param := range params {
					newParams := strings.SplitN(rawBody, "&", -1)
					injectedReq := req
					k := strings.SplitN(param, "=", -1)
					if len(k) > 1 {
						target["original"] = k[1]
						newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
						newParams[index] = fmt.Sprintf("%v=%v", k[0], newValue)
						injectedReq.Body = strings.Join(newParams[:], "&")
						reqs = append(reqs, injectedReq)
					} else if len(k) == 1 {
						target["original"] = k[0]
						newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
						newParams[index] = fmt.Sprintf("%v=%v", k[0], newValue)
						injectedReq.Body = strings.Join(newParams[:], "&")
						reqs = append(reqs, injectedReq)
					}
				}

			}

		}
	}
	// return rawURL
	return reqs

}

// Path gen request with path
func Path(req libs.Request, payload string, arguments []otto.Value) []libs.Request {
	injectedString := arguments[0].String()
	paramName := "last"
	if len(arguments) > 1 {
		paramName = arguments[1].String()
	}

	var reqs []libs.Request
	target := ParseTarget(req.URL)
	target["payload"] = payload
	u, _ := url.Parse(req.URL)
	rawPath := u.Path
	Paths := strings.Split(rawPath, "/")
	ext := filepath.Ext(Paths[len(Paths)-1])

	// only replace extension file
	if paramName == "ext" && ext != "" {
		injectedReq := req
		target["original"] = filepath.Ext(Paths[len(Paths)-1])
		newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
		newPaths := Paths
		newPaths[len(newPaths)-1] = strings.Replace(Paths[len(Paths)-1], target["original"], newValue, -1)
		injectedReq.URL = target["BaseURL"] + strings.Join(newPaths[:], "/")
		reqs = append(reqs, injectedReq)
		// only replace the last path
	} else if paramName == "last" || (paramName == "ext" && ext == "") {
		injectedReq := req
		target["original"] = Paths[len(Paths)-1]
		newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))

		newPaths := Paths
		newPaths[len(newPaths)-1] = newValue
		injectedReq.URL = target["BaseURL"] + strings.Join(newPaths[:], "/")
		reqs = append(reqs, injectedReq)
		// specific position
	} else if paramName != "*" && len(paramName) == 1 {
		position, err := strconv.ParseInt(paramName, 10, 64)
		if err == nil {
			injectedReq := req
			target["original"] = Paths[position]
			newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))

			newPaths := Paths
			newPaths[position] = newValue
			injectedReq.URL = target["BaseURL"] + strings.Join(newPaths[:], "/")
			reqs = append(reqs, injectedReq)
		}
	} else if paramName == "*" || strings.Contains(paramName, ",") {
		// select path
		var injectPositions []int
		if strings.Contains(paramName, ",") {
			positions := strings.Split(paramName, ",")
			for _, pos := range positions {
				index, err := strconv.Atoi(strings.TrimSpace(pos))
				if err == nil {
					injectPositions = append(injectPositions, index)
				}
			}
		} else {
			// all paths
			for index, _ := range Paths {
				injectPositions = append(injectPositions, index)
			}
		}

		for _, injectPos := range injectPositions {
			Paths := strings.Split(rawPath, "/")

			injectedReq := req
			target["original"] = Paths[injectPos]
			newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))

			newPaths := Paths
			newPaths[injectPos] = newValue
			injectedReq.URL = target["BaseURL"] + strings.Join(newPaths[:], "/")
			reqs = append(reqs, injectedReq)
		}

	}
	return reqs
}

// Cookie gen request with Cookie
func Cookie(req libs.Request, payload string, arguments []otto.Value) []libs.Request {
	var reqs []libs.Request
	injectedString := arguments[0].String()
	cookieName := "undefined"
	if len(arguments) > 1 {
		cookieName = arguments[1].String()
	}

	target := ParseTarget(req.URL)
	target["payload"] = payload

	var haveCookie bool
	var cookieExist bool
	var originalCookies string
	originCookies := make(map[string]string)
	// check if request have cookie or not
	for _, header := range req.Headers {
		haveCookie = funk.Contains(header, "Cookie")
		if haveCookie == true {
			// got a cookie
			for _, v := range header {
				originalCookies = v
				rawCookies := strings.Split(v, ";")
				for _, rawCookie := range rawCookies {

					name := strings.Split(strings.TrimSpace(rawCookie), "=")[0]
					// just in case some weird part after '='
					value := strings.Join(strings.Split(strings.TrimSpace(rawCookie), "=")[1:], "")
					originCookies[name] = value
				}
			}
			break
		} else {
			haveCookie = false
		}

	}
	if haveCookie == true && funk.Contains(originCookies, cookieName) {
		cookieExist = true
	}

	// start gen request
	if haveCookie == true {
		// replace entire old cookie if you don't define cookie name
		if cookieName == "undefined" {
			newHeaders := req.Headers
			target["original"] = originalCookies
			newCookie := Encoder(req.Encoding, ResolveVariable(injectedString, target))

			for _, header := range req.Headers {
				for k := range header {
					if k == "Cookie" {
						head := map[string]string{
							"Cookie": newCookie,
						}
						newHeaders = append(newHeaders, head)
					} else {
						newHeaders = append(newHeaders, header)
					}

				}
			}
			injectedReq := req
			injectedReq.Headers = newHeaders
			reqs = append(reqs, injectedReq)
			return reqs
		}

		var newHeaders []map[string]string
		// replace old header
		for _, header := range req.Headers {
			for k := range header {
				// do things with Cookie header
				if k == "Cookie" {
					if cookieExist == true {
						target["original"] = originCookies[cookieName]
						newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
						originCookies[cookieName] = newValue

					} else {
						target["original"] = ""
						newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
						originCookies[cookieName] = newValue
					}

					// join it again to append to the rest of header
					var realCookies string
					for name, value := range originCookies {
						realCookies += fmt.Sprintf("%v=%v; ", name, value)
					}
					newHead := map[string]string{
						"Cookie": realCookies,
					}

					// replace cookie
					newHeaders = append(newHeaders, newHead)
				} else {
					newHeaders = append(newHeaders, header)
				}
			}
		}
		injectedReq := req
		injectedReq.Headers = newHeaders
		reqs = append(reqs, injectedReq)

	} else {
		target["original"] = ""
		var realCookies string
		newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
		if cookieName == "undefined" {
			realCookies = fmt.Sprintf("%v; ", newValue)

		} else {
			realCookies = fmt.Sprintf("%v=%v; ", cookieName, newValue)
		}
		head := map[string]string{
			"Cookie": realCookies,
		}
		injectedReq := req
		newHeaders := req.Headers
		newHeaders = append(newHeaders, head)
		injectedReq.Headers = newHeaders
		reqs = append(reqs, injectedReq)
	}

	return reqs
}

// Header gen request with header
func Header(req libs.Request, payload string, arguments []otto.Value) []libs.Request {
	var reqs []libs.Request
	injectedString := arguments[0].String()
	headerName := arguments[1].String()

	target := ParseTarget(req.URL)
	target["payload"] = payload

	injectedReq := req
	var isExistHeader bool
	// check if inject header is  new or not
	for _, header := range req.Headers {
		isExistHeader = funk.Contains(header, headerName)
		if isExistHeader == true {
			break
		} else {
			isExistHeader = false
		}
	}

	if isExistHeader == false {
		newHeaders := req.Headers
		target["original"] = ""
		newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
		head := map[string]string{
			headerName: newValue,
		}
		newHeaders = append(newHeaders, head)
		injectedReq.Headers = newHeaders
		reqs = append(reqs, injectedReq)
	} else {
		var newHeaders []map[string]string
		// replace old header
		for _, header := range req.Headers {
			for k, v := range header {
				if k == headerName {
					target["original"] = v
					newValue := Encoder(req.Encoding, ResolveVariable(injectedString, target))
					newHead := map[string]string{
						headerName: newValue,
					}
					newHeaders = append(newHeaders, newHead)
				} else {
					newHeaders = append(newHeaders, header)
				}
			}
		}
		injectedReq.Headers = newHeaders
		reqs = append(reqs, injectedReq)
	}

	return reqs
}
