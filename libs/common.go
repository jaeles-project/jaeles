package libs

import (
	"fmt"

	"github.com/fatih/color"
)

// GoodF print good message
func GoodF(format string, args ...interface{}) {
	good := color.HiGreenString("[+]")
	fmt.Printf("%s %s\n", good, fmt.Sprintf(format, args...))
}

// InforF print info message
func InforF(format string, args ...interface{}) {
	info := color.HiBlueString("[*]")
	fmt.Printf("%s %s\n", info, fmt.Sprintf(format, args...))
}

// WarningF print good message
func WarningF(format string, args ...interface{}) {
	good := color.YellowString("[!]")
	fmt.Printf("%s %s\n", good, fmt.Sprintf(format, args...))
}

// ErrorF print good message
func ErrorF(format string, args ...interface{}) {
	good := color.RedString("[-]")
	fmt.Printf("%s %s\n", good, fmt.Sprintf(format, args...))
}
