package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/Jeffail/gabs"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var options = libs.Options{}
var config struct {
	defaultSign  string
	secretCollab string
	port         string
}

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
	RootCmd.PersistentFlags().StringVar(&options.SignFolder, "signDir", "~/.jaeles/signatures-base/", "signFolder")
	RootCmd.PersistentFlags().StringVar(&options.RootFolder, "rootDir", "~/.jaeles/", "root Project")
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

	RootCmd.PersistentFlags().IntVarP(&options.Concurrency, "concurrency", "c", 20, "concurrency")
	RootCmd.PersistentFlags().StringVarP(&options.Output, "output", "o", "out", "output folder name")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	fmt.Printf("Jaeles %v by %v\n", libs.VERSION, libs.AUTHOR)

	if options.Debug {
		options.Verbose = true
	}
	libs.InitLog(options)

	options.RootFolder, _ = homedir.Expand(options.RootFolder)
	if !core.FolderExists(options.RootFolder) {
		libs.InforF("Init new config at %v", options.RootFolder)
		os.MkdirAll(options.RootFolder, 0750)
		// cloning default repo
		core.UpdatePlugins(options)
		core.UpdateSignature(options)
	}

	// DB connect
	var username, password string
	dbPath := path.Join(options.RootFolder, "sqlite.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		db, err := database.InitDB(dbPath)
		if err != nil {
			panic("err open databases")
		}
		defer db.Close()
		// Create new user
		username = "jaeles"
		password = core.GenHash(core.GetTS())[:10]
		database.CreateUser(username, password)
		libs.GoodF("Create new credentials %v:%v", username, password)

		// reload signature
		SignFolder, _ := filepath.Abs(path.Join(options.RootFolder, "base-signatures"))
		libs.GoodF("Load Credentials from %v", SignFolder)
		allSigns := core.GetFileNames(SignFolder, ".yaml")
		if allSigns != nil {
			for _, signFile := range allSigns {
				database.ImportSign(signFile)
			}
		}
		database.InitConfigSign()
	}

	configPath := path.Join(options.RootFolder, "config.yaml")
	v := viper.New()
	v.AddConfigPath(options.RootFolder)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	if !core.FileExists(configPath) {
		libs.InforF("Write new config to: %v", configPath)
		// save default config if not exist
		bind := "http://127.0.0.1:5000"
		v.SetDefault("defaultSign", "*")
		v.SetDefault("cors", "*")
		v.SetDefault("username", username)
		v.SetDefault("password", password)
		v.SetDefault("secret", core.GenHash(core.GetTS()))
		v.SetDefault("bind", bind)
		v.WriteConfigAs(configPath)

	} else {
		if options.Debug {
			libs.InforF("Load config from: %v", configPath)
		}
		b, _ := ioutil.ReadFile(configPath)
		v.ReadConfig(bytes.NewBuffer(b))
	}
	config.defaultSign = fmt.Sprintf("%v", v.Get("defaultSign"))
	config.port = fmt.Sprintf("%v", v.Get("port"))

	// WARNING: change me if you really want to deploy on remote server
	// allow all origin
	options.Cors = fmt.Sprintf("%v", v.Get("cors"))
	options.JWTSecret = fmt.Sprintf("%v", v.Get("secret"))

	// store default credentials for Burp plugin
	burpConfigPath := path.Join(options.RootFolder, "burp.json")
	if !core.FileExists(burpConfigPath) {
		jsonObj := gabs.New()
		jsonObj.Set("", "JWT")
		jsonObj.Set(fmt.Sprintf("%v", v.Get("username")), "username")
		jsonObj.Set(fmt.Sprintf("%v", v.Get("password")), "password")
		bind := fmt.Sprintf("%v", v.Get("bind"))
		if bind == "" {
			bind = "http://127.0.0.1:5000"
		}
		jsonObj.Set(fmt.Sprintf("http://%v/api/parse", bind), "endpoint")
		core.WriteToFile(burpConfigPath, jsonObj.String())
		if options.Verbose {
			libs.InforF("Store default credentials for client at: %v", burpConfigPath)
		}
	}

}
