package core

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/Jeffail/gabs/v2"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/spf13/viper"
)

// InitConfig init config
func InitConfig(options *libs.Options) {
	options.RootFolder = utils.NormalizePath(options.RootFolder)
	// init new root folder
	if !utils.FolderExists(options.RootFolder) {
		utils.InforF("Init new config at %v", options.RootFolder)
		os.MkdirAll(options.RootFolder, 0750)
		// cloning default repo
		UpdatePlugins(*options)
		UpdateSignature(*options, "")
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
		password = utils.GenHash(utils.GetTS())[:10]
		database.CreateUser(username, password)
		utils.GoodF("Create new credentials %v:%v", username, password)

		// reload signature
		SignFolder, _ := filepath.Abs(path.Join(options.RootFolder, "base-signatures"))
		utils.GoodF("Load Credentials from %v", SignFolder)
		allSigns := utils.GetFileNames(SignFolder, ".yaml")
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
	if !utils.FileExists(configPath) {
		utils.InforF("Write new config to: %v", configPath)
		// save default config if not exist
		bind := "http://127.0.0.1:5000"
		v.SetDefault("defaultSign", "*")
		v.SetDefault("cors", "*")
		v.SetDefault("username", username)
		v.SetDefault("password", password)
		v.SetDefault("secret", utils.GenHash(utils.GetTS()))
		v.SetDefault("bind", bind)
		v.WriteConfigAs(configPath)

	} else {
		if options.Debug {
			utils.InforF("Load config from: %v", configPath)
		}
		b, _ := ioutil.ReadFile(configPath)
		v.ReadConfig(bytes.NewBuffer(b))
	}
	// config.defaultSign = fmt.Sprintf("%v", v.Get("defaultSign"))

	// WARNING: change me if you really want to deploy on remote server
	// allow all origin
	options.Server.Cors = fmt.Sprintf("%v", v.Get("cors"))
	options.Server.JWTSecret = fmt.Sprintf("%v", v.Get("secret"))

	// store default credentials for Burp plugin
	burpConfigPath := path.Join(options.RootFolder, "burp.json")
	if !utils.FileExists(burpConfigPath) {
		jsonObj := gabs.New()
		jsonObj.Set("", "JWT")
		jsonObj.Set(fmt.Sprintf("%v", v.Get("username")), "username")
		jsonObj.Set(fmt.Sprintf("%v", v.Get("password")), "password")
		bind := fmt.Sprintf("%v", v.Get("bind"))
		if bind == "" {
			bind = "http://127.0.0.1:5000"
		}
		jsonObj.Set(fmt.Sprintf("http://%v/api/parse", bind), "endpoint")
		utils.WriteToFile(burpConfigPath, jsonObj.String())
		if options.Verbose {
			utils.InforF("Store default credentials for client at: %v", burpConfigPath)
		}
	}
}
