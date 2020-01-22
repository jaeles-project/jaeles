package cmd

import (
	"fmt"
	"os"

	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/jinzhu/gorm"
	"github.com/spf13/cobra"
)

var options = libs.Options{}

// DB database variables
var DB *gorm.DB

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "jaeles",
	Short: "Jaeles Scanner",
	Long:  fmt.Sprintf(`Jaeles - The Swiss Army knife for automated Web Application Testing - %v by %v`, libs.VERSION, libs.AUTHOR),
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
	RootCmd.PersistentFlags().StringVar(&options.PassiveFolder, "passiveDir", "~/.jaeles/passives/", "Folder contain default passives")
	RootCmd.PersistentFlags().StringVar(&options.ScanID, "scanID", "", "Scan ID")

	RootCmd.PersistentFlags().StringVar(&options.Proxy, "proxy", "", "proxy")
	RootCmd.PersistentFlags().IntVar(&options.Timeout, "timeout", 20, "HTTP timeout")
	RootCmd.PersistentFlags().IntVar(&options.Delay, "delay", 100, "Milliseconds delay for polling new job")
	RootCmd.PersistentFlags().IntVar(&options.Retry, "retry", 0, "retry")

	RootCmd.PersistentFlags().BoolVar(&options.SaveRaw, "save-raw", false, "save raw request")
	RootCmd.PersistentFlags().BoolVar(&options.NoOutput, "no-output", false, "Do not store raw output")
	RootCmd.PersistentFlags().BoolVar(&options.EnablePassive, "passive", false, "Do not run passive detections")
	RootCmd.PersistentFlags().BoolVar(&options.NoBackGround, "no-background", false, "Do not run background task")
	RootCmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose")
	RootCmd.PersistentFlags().BoolVar(&options.Debug, "debug", false, "Debug")
	RootCmd.PersistentFlags().IntVar(&options.Refresh, "refresh", 10, "Refresh")

	RootCmd.PersistentFlags().IntVarP(&options.Concurrency, "concurrency", "c", 20, "concurrency")
	RootCmd.PersistentFlags().StringVarP(&options.Output, "output", "o", "out", "output folder name")
	RootCmd.PersistentFlags().StringVarP(&options.LogFile, "log", "l", "", "log file")
	// custom params from cli
	RootCmd.Flags().StringSliceVarP(&options.Params, "params", "p", []string{}, "Custom params --params='foo=bar'")
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
	DB, err = database.InitDB(options.Server.DBPath)
	if err != nil {
		fmt.Printf("Can't connect to DB at %v\n", options.Server.DBPath)
		os.Exit(-1)
	}
}
