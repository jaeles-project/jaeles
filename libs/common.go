package libs

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var log = logrus.New()

// InitLog init log
func InitLog(options Options) {
	log.Formatter = new(prefixed.TextFormatter)
	log.SetOutput(os.Stdout)
	if options.Debug == true {
		log.SetLevel(logrus.DebugLevel)
	} else if options.Verbose == true {
		log.SetLevel(logrus.ErrorLevel)
	} else {
		log.SetOutput(ioutil.Discard)
	}
}

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

// VerboseF print info message
func VerboseF(format string, args ...interface{}) {
	log.Info(fmt.Sprintf(format, args...))
}

// WarningF print good message
func WarningF(format string, args ...interface{}) {
	good := color.YellowString("[!]")
	fmt.Printf("%s %s\n", good, fmt.Sprintf(format, args...))
}

// DebugF print debug message
func DebugF(format string, args ...interface{}) {
	log.Debug(fmt.Sprintf(format, args...))
}

// ErrorF print good message
func ErrorF(format string, args ...interface{}) {
	log.Error(fmt.Sprintf(format, args...))
}
