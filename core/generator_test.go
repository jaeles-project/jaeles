package core

import (
	"testing"

	"github.com/jaeles-project/jaeles/libs"
)

// func TestGeneratorPath(t *testing.T) {
// 	var req libs.Request

// 	req.URL = "http://example.com/rest/products/6/reviews"
// 	reqs := RunGenerator(req, ".json", `Path("{{.payload}}", "*")`)
// 	fmt.Println(reqs)
// 	// for _, r := range reqs {
// 	// 	if !strings.Contains(r.URL, ".json") {
// 	// 		t.Errorf("Error generate Path")
// 	// 	}
// 	// }
// }

func TestGeneratorMethod(t *testing.T) {
	var req libs.Request
	req.Method = "GET"
	reqs := RunGenerator(req, "", `Method("PUT")`)
	for _, r := range reqs {
		if r.Method != "PUT" {
			t.Errorf("Error generate Path")
		}
	}
}
