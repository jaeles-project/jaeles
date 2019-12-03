package core

import (
	"fmt"
	"testing"

	"github.com/jaeles-project/jaeles/libs"
)

func TestVariables(t *testing.T) {
	varString := `RandomString("6")`
	data := RunVariables(varString)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `RandomString(3)`
	data = RunVariables(varString)

	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `Range(0,5)`
	data = RunVariables(varString)
	fmt.Println(varString, ":", data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `File("~/suites/contents/quick.txt")`
	data = RunVariables(varString)
	fmt.Println(varString, ":", len(data))
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `InputCmd("echo 123")`
	data = RunVariables(varString)
	fmt.Println(varString, ":", data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
}

func TestMultipleVariables(t *testing.T) {
	var sign libs.Signature
	var vars []map[string]string

	varElement := make(map[string]string)
	varElement["param"] = `[1,2,3,4]`
	vars = append(vars, varElement)

	varElement2 := make(map[string]string)
	varElement2["dest"] = `[a,b,c]`
	vars = append(vars, varElement2)

	sign.Variables = vars

	realVaris := ParseVariable(sign)
	fmt.Println(realVaris)
	if len(realVaris) <= 0 {
		t.Errorf("Error RandomString")
	}
}

func TestEncoding(t *testing.T) {
	varString := `URLEncode(" das da")`
	data := RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
	varString = `Base64Encode("das da c")`
	data = RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}

	varString = `Base64EncodeByLines('das\nda\nc')`
	data = RunVariables(varString)
	fmt.Println(data)
	if len(data) <= 0 {
		t.Errorf("Error RandomString")
	}
}
