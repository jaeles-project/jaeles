package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/spf13/cobra"
)

var configCmd *cobra.Command

func init() {
	// byeCmd represents the bye command
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configuration CLI",
		Long:  `Do some Configuration for db and signatures`,
		RunE:  runConfig,
	}
	configCmd.Flags().Bool("clean", false, "Force continued operation when wildcard found")
	configCmd.Flags().Int16P("level", "l", 1, "Provide custom header seperate by ';'")
	configCmd.Flags().StringP("action", "a", "select", "Action")
	configCmd.Flags().StringP("sign", "s", "", "Select signature")
	// load signature
	configCmd.Flags().StringP("signFolder", "F", "", "Signature Folder")
	// used for cred action
	configCmd.Flags().String("user", "", "Username")
	configCmd.Flags().String("pass", "", "Password")
	configCmd.Flags().Bool("hh", false, "More helper")
	// used for cred action
	configCmd.Flags().String("secret", "", "Secret of Burp Collab")
	configCmd.Flags().String("collab", "", "List of Burp Collab File")

	RootCmd.AddCommand(configCmd)

}

func runConfig(cmd *cobra.Command, args []string) error {
	// print more help
	helps, _ := cmd.Flags().GetBool("hh")
	if helps == true {
		HelperConfig()
		os.Exit(1)
	}

	// DB connect
	dbPath := path.Join(options.RootFolder, "sqlite.db")
	db, err := database.InitDB(dbPath)
	if err != nil {
		panic("err open databases")
	}
	defer db.Close()

	action, _ := cmd.Flags().GetString("action")

	// update plugins and signatures
	if action == "update" {
		core.UpdatePlugins(options)
		core.UpdateSignature(options)
	}

	// clean all the things
	if action == "clean" {
		database.CleanSigns()
		database.CleanRecords()
		database.CleanScans()
	}

	// create or update user
	if action == "cred" {
		// Create new user
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("pass")
		database.CreateUser(username, password)
		libs.GoodF("Create new credentials %v:%v \n", username, password)
	}

	// load oob
	if action == "oob" {
		secret, _ := cmd.Flags().GetString("secret")
		collabFile, _ := cmd.Flags().GetString("collab")
		collabs := core.ReadingFile(collabFile)
		for _, collab := range collabs {
			database.ImportCollab(secret, collab)
		}
	}

	// reload signature
	if action == "reload" {
		database.CleanSigns()
		// select folder to load signature
		SignFolder, _ := filepath.Abs(path.Join(options.RootFolder, "base-signatures"))
		signFolder, _ := cmd.Flags().GetString("signFolder")
		if signFolder != "" && core.FolderExists(signFolder) {
			SignFolder = signFolder
		}

		allSigns := core.GetFileNames(SignFolder, ".yaml")
		if allSigns != nil {
			libs.InforF("Load Signature from: %v", SignFolder)
			for _, signFile := range allSigns {
				database.ImportSign(signFile)
			}
		}
	}

	libs.GoodF("Done the config")
	return nil
}

// HelperConfig more helper message for config command
func HelperConfig() {
	h := "Config Command example:\n"
	h += "jaeles config -a clean\n"
	h += "jaeles config -a update\n"
	h += "jaeles config -a reload\n"
	h += "jaeles config -a reload -F /tmp/custom-signatures/\n"
	h += "jaeles config -a cred --user sample --pass not123456\n"
	h += "jaeles config -a oob --secret SomethingSecret --collab list_of_collabs.txt\n"
	fmt.Printf(h)
}
