package core

import (
	"fmt"
	"github.com/jaeles-project/jaeles/libs"
	"testing"
)

//
//func TestReportTemplate(t *testing.T) {
//	var opt libs.Options
//	result := GenVulnData(opt)
//	fmt.Println(result)
//	if result == "" {
//		t.Errorf("Error resolve variable")
//	}
//}

func TestParseVuln(t *testing.T) {
	var opt libs.Options
	opt.SummaryOutput = "/tmp/rr/out/jaeles-summary.txt"
	vulns := ParseVuln(opt)
	fmt.Println(vulns)
	if len(vulns) == 0 {
		t.Errorf("Error read jaeles-summary")
	}
}
