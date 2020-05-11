package cmd

import (
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/spf13/cobra"
	"os"
	"path"
)

func init() {
	var reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Generate HTML report based on scanned output",
		Long:  libs.Banner(),
		RunE:  runReport,
	}
	reportCmd.Flags().StringP("html", "R", "jaeles-report.html", "Report name")
	reportCmd.Flags().String("template", "~/.jaeles/plugins/report/index.html", "Report Template File")
	RootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, _ []string) error {
	html, _ := cmd.Flags().GetString("html")
	templateFile, _ := cmd.Flags().GetString("template")

	options.Report.TemplateFile = templateFile
	options.Report.ReportName = html
	DoGenReport(options)
	return nil
}

// DoGenReport generate report from scanned result
func DoGenReport(options libs.Options) error {
	if options.Report.TemplateFile == "" {
		options.Report.TemplateFile = "~/.jaeles/plugins/report/index.html"
	}
	if options.Report.ReportName == "" {
		options.Report.ReportName = "jaeles-report.html"
	}

	// get template file
	options.Report.TemplateFile = utils.NormalizePath(options.Report.TemplateFile)
	if !utils.FileExists(options.Report.TemplateFile) {
		// get content of remote URL via GET request
		req := libs.Request{
			URL: libs.REPORT,
		}
		utils.DebugF("Download template from: %v", libs.REPORT)
		res, err := sender.JustSend(options, req)
		if err != nil || len(res.Body) <= 0 {
			utils.ErrorF("Error GET templateFile: %v", err)
			return nil
		}

		os.MkdirAll(path.Dir(options.Report.TemplateFile), 0750)
		_, err = utils.WriteToFile(options.Report.TemplateFile, res.Body)
		if err != nil {
			utils.ErrorF("Error write templateFile: %v", err)
			return nil
		}
		utils.InforF("Write report template to: %v", options.Report.TemplateFile)
	}

	err := core.GenReport(options)
	if err != nil {
		utils.ErrorF("Error gen report: %v", err)
		return nil
	}
	return nil
}
