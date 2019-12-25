package core

import (
	"crypto/sha1"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/fatih/color"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
)

// Analyze run analyze with each detections
func Analyze(options libs.Options, rec *libs.Record) {
	if options.Debug {
		libs.DebugF(strings.Join(rec.Request.Detections, " "))
	}
	/* Analyze part */
	if rec.Request.Beautify == "" {
		rec.Request.Beautify = BeautifyRequest(rec.Request)
	}

	for _, analyze := range rec.Request.Detections {
		extra, result := RunDetector(*rec, analyze)
		if extra != "" {
			rec.ExtraOutput = extra
		}
		if result == true {
			if options.Verbose {
				color.Magenta("[Found] %v", analyze)
			}
			var outputName string
			if options.NoOutput == false {
				outputName = StoreOutput(*rec, options)
				rec.RawOutput = outputName
				database.ImportRecord(*rec)
			}
			color.Green("[Vulnerable][%v] %v %v", rec.Sign.Info.Risk, rec.Request.URL, outputName)
		}
	}
}

// StoreOutput store vulnerable request to a file
func StoreOutput(rec libs.Record, options libs.Options) string {
	// store output to a file
	content := fmt.Sprintf("[%v] - %v\n\n", rec.Sign.ID, rec.Request.URL)
	if rec.Request.MiddlewareOutput != "" {
		content += rec.Request.MiddlewareOutput
	}
	if rec.ExtraOutput != "" {
		content += rec.ExtraOutput
	}
	content += rec.Request.Beautify
	content += fmt.Sprintf("\n%v\n", strings.Repeat("-", 50))
	content += rec.Response.Beautify

	// hash the content
	h := sha1.New()
	h.Write([]byte(content))
	checksum := h.Sum(nil)

	parts := []string{options.Output}
	u, _ := url.Parse(rec.Request.URL)
	parts = append(parts, u.Hostname())
	parts = append(parts, fmt.Sprintf("%v-%x", rec.Sign.ID, checksum))

	p := path.Join(parts...)
	if _, err := os.Stat(path.Dir(p)); os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(p), 0750)
		if err != nil {
			libs.ErrorF("Error Write content to: %v", p)
		}
	}
	WriteToFile(p, content)
	return p
}
