package core

import (
	"fmt"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/sender"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/thoas/go-funk"
)

var baseFiltering = []string{
	"hopetoget404" + RandomString(6),
	fmt.Sprintf("%s", RandomString(16)+"/"+RandomString(5)),
	fmt.Sprintf("%s.html", RandomString(16)),
	fmt.Sprintf("%s.php~", RandomString(16)),
	fmt.Sprintf("%s.%00", RandomString(16)),
	fmt.Sprintf("%s.json", RandomString(16)),
}

func BaseCalculateFiltering(job *libs.Job, options libs.Options) {
	utils.DebugF("Start Calculate Basic Filtering: %s", job.URL)
	for _, filterPath := range baseFiltering {
		var req libs.Request
		req.Method = "GET"
		req.EnableChecksum = true
		req.URL = utils.JoinURL(job.URL, filterPath)

		res, err := sender.JustSend(options, req)
		// in case of timeout or anything
		if err != nil {
			return
		}

		if res.Checksum != "" {
			utils.DebugF("[Checksum] %s - %s", req.URL, res.Checksum)
			job.Checksums = append(job.Checksums, res.Checksum)
		}
	}
	job.Checksums = funk.UniqString(job.Checksums)
}

func CalculateFiltering(job *libs.Job, options libs.Options) {
	var filteringPaths []string

	// ignore old result
	if job.Sign.OverrideFilerPaths {
		job.Sign.Checksums = []string{}
	} else {
		// mean doesn't have --fi in cli
		if len(job.Sign.Checksums) == 0 {
			filteringPaths = append(filteringPaths, baseFiltering...)
		}
	}

	if len(job.Sign.FilteringPaths) > 0 {
		filteringPaths = append(filteringPaths, job.Sign.FilteringPaths...)
	}

	if len(filteringPaths) == 0 {
		return
	}

	for _, filterPath := range filteringPaths {
		var req libs.Request
		req.Method = "GET"
		req.EnableChecksum = true
		//req.URL = job.URL + "/" + filterPath
		req.URL = utils.JoinURL(job.URL, filterPath)

		res, err := sender.JustSend(options, req)
		// in case of timeout or anything
		if err != nil {
			return
		}

		if res.Checksum != "" {
			utils.DebugF("[Checksum] %s - %s", req.URL, res.Checksum)
			job.Sign.Checksums = append(job.Sign.Checksums, res.Checksum)
		}
	}

	job.Sign.Checksums = funk.UniqString(job.Sign.Checksums)
}
