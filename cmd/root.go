package cmd

import (
	"fmt"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/jinzhu/gorm"
	"github.com/spf13/cobra"
	"github.com/thoas/go-funk"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var options = libs.Options{}

// DB database variables
var DB *gorm.DB

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "jaeles",
	Short: "Jaeles Scanner",
	Long:  libs.Banner(),
}

// Execute main function
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&options.ConfigFile, "config", "", "config file (default is $HOME/.jaeles/config.yaml)")
	RootCmd.PersistentFlags().StringVar(&options.RootFolder, "rootDir", "~/.jaeles/", "root Project")
	RootCmd.PersistentFlags().StringVar(&options.SignFolder, "signDir", "~/.jaeles/signatures-base/", "Folder contain default signatures")
	RootCmd.PersistentFlags().StringVar(&options.ScanID, "scanID", "", "Scan ID")

	RootCmd.PersistentFlags().StringVar(&options.Proxy, "proxy", "", "proxy")
	RootCmd.PersistentFlags().IntVar(&options.Timeout, "timeout", 20, "HTTP timeout")
	RootCmd.PersistentFlags().IntVar(&options.Delay, "delay", 100, "Milliseconds delay for polling new job")
	RootCmd.PersistentFlags().IntVar(&options.Retry, "retry", 0, "retry")

	RootCmd.PersistentFlags().BoolVar(&options.SaveRaw, "save-raw", false, "save raw request")
	RootCmd.PersistentFlags().BoolVar(&options.NoOutput, "no-output", false, "Do not store raw output")
	RootCmd.PersistentFlags().BoolVar(&options.NoBackGround, "no-background", false, "Do not run background task")
	RootCmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose")
	RootCmd.PersistentFlags().BoolVar(&options.Debug, "debug", false, "Debug")
	RootCmd.PersistentFlags().IntVar(&options.Refresh, "refresh", 10, "Refresh")

	RootCmd.PersistentFlags().BoolVarP(&options.EnablePassive, "passive", "G", false, "Turn on passive detections")
	RootCmd.PersistentFlags().StringVar(&options.SelectedPassive, "sp", "*", "Selector for passive detections")
	RootCmd.PersistentFlags().IntVarP(&options.Concurrency, "concurrency", "c", 20, "concurrency")
	RootCmd.PersistentFlags().IntVarP(&options.Threads, "threads", "t", 1, "Enable parallel in single signature")
	RootCmd.PersistentFlags().StringVarP(&options.Output, "output", "o", "out", "output folder name")
	RootCmd.PersistentFlags().StringVar(&options.PassiveOutput, "passiveOutput", "", "Passive output folder (default is passive-out)")
	RootCmd.PersistentFlags().StringVar(&options.PassiveSummary, "passiveSummary", "", "Passive Summary file")
	RootCmd.PersistentFlags().StringVarP(&options.SummaryOutput, "summaryOutput", "O", "", "Summary output file")
	RootCmd.PersistentFlags().StringVarP(&options.LogFile, "log", "l", "", "log file")
	// custom params from cli
	RootCmd.PersistentFlags().StringVarP(&options.Selectors, "selectorFile", "S", "", "Signature selector from file")
	RootCmd.PersistentFlags().StringSliceVarP(&options.Signs, "signs", "s", []string{}, "Signature selector (Multiple -s flags are accepted)")
	RootCmd.PersistentFlags().StringSliceVarP(&options.Excludes, "exclude", "x", []string{}, "Exclude Signature selector (Multiple -x flags are accepted)")
	RootCmd.PersistentFlags().StringSliceVarP(&options.Params, "params", "p", []string{}, "Custom params --params='foo=bar'")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	fmt.Printf("Jaeles %v by %v\n", libs.VERSION, libs.AUTHOR)
	if options.Debug {
		options.Verbose = true
	}
	utils.InitLog(&options)
	core.InitConfig(&options)

	// Init DB
	var err error
	DB, err = database.InitDB(utils.NormalizePath(options.Server.DBPath))
	if err != nil {
		fmt.Printf("Can't connect to DB at %v\n", options.Server.DBPath)
		os.Exit(-1)
	}
}

// SelectSign select signature
func SelectSign() {
	var selectedSigns []string
	// read selector from File
	if options.Selectors != "" {
		options.Signs = append(options.Signs, utils.ReadingFileUnique(options.Selectors)...)
	}

	// default is all signature
	if len(options.Signs) == 0 {
		selectedSigns = core.SelectSign("**")
	}

	// search signature through Signatures table
	for _, signName := range options.Signs {
		selectedSigns = append(selectedSigns, core.SelectSign(signName)...)
		Signs := database.SelectSign(signName)
		selectedSigns = append(selectedSigns, Signs...)
	}

	// exclude some signature
	if len(options.Excludes) > 0 {
		for _, exclude := range options.Excludes {
			for index, sign := range selectedSigns {
				if strings.Contains(sign, exclude) {
					selectedSigns = append(selectedSigns[:index], selectedSigns[index+1:]...)
				}
				r, err := regexp.Compile(exclude)
				if err != nil {
					continue
				}
				if r.MatchString(sign) {
					selectedSigns = append(selectedSigns[:index], selectedSigns[index+1:]...)
				}

			}
		}
	}
	options.SelectedSigns = selectedSigns

	if len(selectedSigns) == 0 {
		fmt.Println("[Error] No signature loaded")
		os.Exit(1)
	}
	selectedSigns = funk.UniqString(selectedSigns)
	utils.InforF("Signatures Loaded: %v", len(selectedSigns))
	signInfo := fmt.Sprintf("Signature Loaded: ")
	for _, signName := range selectedSigns {
		signInfo += fmt.Sprintf("%v ", filepath.Base(signName))
	}
	utils.InforF(signInfo)

	// create new scan or group with old one
	var scanID string
	if options.ScanID == "" {
		scanID = database.NewScan(options, "scan", selectedSigns)
	} else {
		scanID = options.ScanID
	}
	utils.InforF("Start Scan with ID: %v", scanID)
	options.ScanID = scanID
}
