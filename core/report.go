package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"html/template"
	"path"
	"path/filepath"
	"strings"
)

type Vulnerability struct {
	SignID     string
	SignPath   string
	URL        string
	Risk       string
	ReportPath string
	ReportFile string
}

type ReportData struct {
	Vulnerabilities []Vulnerability
}

// GenReport generate report file
func GenReport(options libs.Options) error {
	// parse vulns from jaeles-summary.txt
	vulns := ParseVuln(options)
	if len(vulns) == 0 {
		return errors.New(fmt.Sprintf("no Vulnerability found from %v", options.Output))
	}
	data := struct {
		Vulnerabilities []Vulnerability
		CurrentDay      string
		Version         string
	}{
		Vulnerabilities: vulns,
		CurrentDay:      utils.GetCurrentDay(),
		Version:         libs.VERSION,
	}

	// read template file
	tmpl := utils.GetFileContent(options.Report.TemplateFile)
	if tmpl == "" {
		return errors.New("blank template file")
	}

	t := template.Must(template.New("").Parse(tmpl))
	buf := &bytes.Buffer{}
	err := t.Execute(buf, data)
	if err != nil {
		return err
	}
	result := buf.String()

	if !strings.Contains(options.Report.ReportName, "/") {
		options.Report.ReportName = path.Join(path.Dir(options.Output), options.Report.ReportName)
	}
	utils.DebugF("Writing HTML report to: %v", options.Report.ReportName)
	_, err = utils.WriteToFile(options.Report.ReportName, result)

	if err == nil {
		utils.GoodF("Genereted HTML report: %v", options.Report.ReportName)
	}
	return err
}

// ParseVuln parse vulnerbility based on
func ParseVuln(options libs.Options) []Vulnerability {
	var vulns []Vulnerability
	utils.DebugF("Parsing summary file: %v", options.SummaryOutput)
	content := utils.ReadingLines(options.SummaryOutput)
	if len(content) == 0 {
		return vulns
	}

	for _, line := range content {
		data := strings.Split(line, " - ")
		if len(data) <= 0 {
			continue
		}
		var signID, risk string

		if !strings.Contains(data[0], "][") {
			continue
		}
		signID = strings.Split(data[0], "][")[0][1:]
		risk = strings.Split(data[0], "][")[1][:len(strings.Split(data[0], "][")[1])-1]

		raw := data[2]
		// host/sign-hash
		reportPath := path.Join(path.Base(path.Dir(raw)), filepath.Base(raw))

		vuln := Vulnerability{
			SignID:     signID,
			SignPath:   "SignPath",
			URL:        data[1],
			Risk:       strings.ToLower(risk),
			ReportPath: reportPath,
			ReportFile: filepath.Base(raw),
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}
