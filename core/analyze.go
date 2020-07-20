package core

import (
	"crypto/sha1"
	"fmt"
	"github.com/fatih/color"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	jsoniter "github.com/json-iterator/go"
	"net/url"
	"os"
	"path"
	"strings"
)

// Analyze run analyzer with each detections
func Analyze(options libs.Options, record *libs.Record) {
	/* Analyze part */
	if record.Request.Beautify == "" {
		record.Request.Beautify = sender.BeautifyRequest(record.Request)
	}
	if len(record.Request.Detections) <= 0 {
		return
	}

	for _, analyze := range record.Request.Detections {
		// skip multiple detection for the same request
		if record.IsVulnerable && record.Sign.Donce {
			return
		}
		extra, result := RunDetector(*record, analyze)
		if extra != "" {
			record.ExtraOutput = extra
		}
		if result == true {
			record.DetectString = analyze
			if options.Verbose {
				color.Magenta("[Found] %v", analyze)
			}

			// do passive analyze if got called from detector
			if strings.Contains(strings.ToLower(analyze), "dopassive") {
				PassiveAnalyze(options, *record)
				record.DonePassive = true
			}

			var outputName string
			if options.NoOutput == false {
				outputName = StoreOutput(*record, options)
				record.RawOutput = outputName
				if !options.NoDB {
					database.ImportRecord(*record)
				}
			}
			vulnInfo := fmt.Sprintf("[%v][%v] %v", record.Sign.ID, record.Sign.Info.Risk, record.Request.URL)
			if options.Quiet {
				record.Request.Target["VulnURL"] = record.Request.URL
				fmt.Printf("%v\n", ResolveVariable(options.QuietFormat, record.Request.Target))
			} else {
				color.Green("[Vulnerable]%v %v", vulnInfo, outputName)
			}

			if options.FoundCmd != "" {
				// add some more variables for notification
				record.Request.Target["vulnInfo"] = vulnInfo
				record.Request.Target["vulnOut"] = outputName
				record.Request.Target["notiText"] = vulnInfo
				options.FoundCmd = ResolveVariable(options.FoundCmd, record.Request.Target)
				Execution(options.FoundCmd)
			}
			record.Request.Target["IsVulnerable"] = "true"
			record.IsVulnerable = true
		}
		utils.DebugF("[Detection] %v -- %v", analyze, result)
	}
}

type VulnData struct {
	SignID          string
	SignName        string
	URL             string
	Risk            string
	DetectionString string
	Confidence      string
	Req             string
	Res             string
}

// StoreOutput store vulnerable request to a file
func StoreOutput(rec libs.Record, options libs.Options) string {
	// store output to a file
	if rec.Request.URL == "" {
		rec.Request.URL = rec.Request.Target["URL"]
	}
	head := fmt.Sprintf("[%v][%v-%v] - %v\n", rec.Sign.ID, rec.Sign.Info.Confidence, rec.Sign.Info.Risk, rec.Request.URL)
	sInfo := fmt.Sprintf("[Sign-Info][%v-%v] - %v - %v\n", rec.Sign.Info.Confidence, rec.Sign.Info.Risk, rec.Sign.RawPath, rec.Sign.Info.Name)
	content := "[Vuln-Info]" + head + sInfo + fmt.Sprintf("[Detect-String] - %v\n\n", rec.DetectString)
	if rec.Request.MiddlewareOutput != "" {
		content += strings.Join(rec.Request.Middlewares, "\n")
		content += fmt.Sprintf("\n<<%v>>\n", strings.Repeat("-", 50))
		content += rec.Request.MiddlewareOutput
	}

	if rec.ExtraOutput != "" {
		content += fmt.Sprintf("%v\n", strings.Repeat("-", 50))
		content += fmt.Sprintf("[Matches String]\n")
		content += strings.TrimSpace(rec.ExtraOutput)
		content += fmt.Sprintf("\n")
	}

	content += fmt.Sprintf(">>>>%v\n", strings.Repeat("-", 50))
	if rec.Request.MiddlewareOutput == "" {
		content += rec.Request.Beautify
		content += fmt.Sprintf("\n%v<<<<\n", strings.Repeat("-", 50))
		content += rec.Response.Beautify
	}

	// hash the content
	h := sha1.New()
	h.Write([]byte(content))
	checksum := h.Sum(nil)

	parts := []string{options.Output}
	if rec.Request.URL == "" {
		parts = append(parts, rec.Request.Target["Domain"])
	} else {
		host := utils.StripName(rec.Request.Host)
		u, err := url.Parse(rec.Request.URL)
		if err == nil {
			host = u.Hostname()
		}
		if host == "" {
			host = URLEncode(rec.Request.URL)
		}
		parts = append(parts, host)
	}
	parts = append(parts, fmt.Sprintf("%v-%x", rec.Sign.ID, checksum))

	p := path.Join(parts...)
	if _, err := os.Stat(path.Dir(p)); os.IsNotExist(err) {
		err = os.MkdirAll(path.Dir(p), 0750)
		if err != nil {
			utils.ErrorF("Error Write content to: %v", p)
		}
	}
	// store output as JSON
	if options.JsonOutput {
		vulnData := VulnData{
			SignID:          rec.Sign.ID,
			SignName:        rec.Sign.Info.Name,
			Risk:            rec.Sign.Info.Risk,
			Confidence:      rec.Sign.Info.Confidence,
			DetectionString: rec.DetectString,
			URL:             rec.Request.URL,
			Req:             Base64Encode(rec.Request.Beautify),
			Res:             Base64Encode(rec.Response.Beautify),
		}
		if data, err := jsoniter.MarshalToString(vulnData); err == nil {
			content = data
		}
	}

	// normal output
	utils.WriteToFile(p, content)
	sum := fmt.Sprintf("%v - %v", strings.TrimSpace(head), p)
	utils.AppendToContent(options.SummaryOutput, sum)

	vulnSum := fmt.Sprintf("[%v][%v] - %v", rec.Sign.ID, rec.Sign.Info.Risk, rec.Request.Target["Raw"])
	utils.AppendToContent(options.SummaryVuln, vulnSum)
	return p
}
