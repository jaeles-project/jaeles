package core

import (
	"fmt"
	"testing"
)

// See doc here: http://masterminds.github.io/sprig/
func TestResolveVariableWithFunc(t *testing.T) {
	data := make(map[string]string)
	data["var"] = "foo"
	data["sam"] = "foo bar"
	data["uu"] = "http://example.com/a?q=2"
	format := "{{.var}}"
	result := ResolveVariable(format, data)
	fmt.Println(result)
	if result == "" {
		t.Errorf("Error TestResolveVariable")
	}

	format = "{{.var | b64enc }}"
	result = ResolveVariable(format, data)
	fmt.Println(result)
	if result == "" {
		t.Errorf("Error TestResolveVariable")
	}

	format = `[[ .uu | sha1sum ]]`
	result = AltResolveVariable(format, data)
	fmt.Println(result)
	if result == "" {
		t.Errorf("Error TestResolveVariable")
	}
}
