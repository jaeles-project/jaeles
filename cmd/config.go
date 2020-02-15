package cmd

import (
	"fmt"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/spf13/cobra"
	"os"
	"path"
	"path/filepath"
)

var configCmd *cobra.Command

func init() {
	// byeCmd represents the bye command
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configuration CLI",
		Long:  libs.Banner(),
		RunE:  runConfig,
	}
	configCmd.Flags().Bool("clean", false, "Force continued operation when wildcard found")
	//configCmd.Flags().Int16P("level", "l", 1, "Provide custom header seperate by ';'")
	configCmd.Flags().StringP("action", "a", "", "Action")
	// load signature
	configCmd.Flags().StringP("signFolder", "F", "", "Signature Folder")
	// used for cred action
	configCmd.Flags().String("user", "", "Username")
	configCmd.Flags().String("pass", "", "Password")
	configCmd.Flags().Bool("hh", false, "More helper")
	configCmd.Flags().Bool("poll", false, "Polling all record in OOB config")
	// used for cred action
	configCmd.Flags().String("secret", "", "Secret of Burp Collab")
	configCmd.Flags().String("collab", "", "List of Burp Collab File")
	configCmd.Flags().String("repo", "", "Signature Repo")
	configCmd.SetHelpFunc(configHelp)
	RootCmd.AddCommand(configCmd)

}

func runConfig(cmd *cobra.Command, args []string) error {
	// print more help
	helps, _ := cmd.Flags().GetBool("hh")
	if helps == true {
		HelpMessage()
		os.Exit(1)
	}
	// turn on verbose by default
	options.Verbose = true

	polling, _ := cmd.Flags().GetBool("poll")
	// polling all oob
	if polling == true {
		secret, _ := cmd.Flags().GetString("secret")
		collabFile, _ := cmd.Flags().GetString("collab")
		collabs := utils.ReadingLines(collabFile)
		for _, collab := range collabs {
			database.ImportCollab(secret, collab)
		}
	}

	action, _ := cmd.Flags().GetString("action")
	switch action {
	case "update":
		// in case we want to in private repo
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("pass")
		if username != "" {
			options.Server.Username = username
			options.Server.Password = password
		}

		core.UpdatePlugins(options)
		repo, _ := cmd.Flags().GetString("repo")
		core.UpdateSignature(options, repo)
		reloadSignature(path.Join(options.RootFolder, "base-signatures"))
		break
	case "clear":
		database.CleanScans()
		database.CleanSigns()
		database.CleanRecords()
		break
	case "clean":
		os.RemoveAll(path.Join(options.RootFolder, "sqlite.db"))
		os.RemoveAll(path.Join(options.RootFolder, "config.yaml"))
		os.RemoveAll(path.Join(options.RootFolder, "burp.json"))
		break
	case "cred":
		username, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("pass")
		database.CreateUser(username, password)
		utils.GoodF("Create new credentials %v:%v \n", username, password)
		break
	case "oob":
		secret, _ := cmd.Flags().GetString("secret")
		collabFile, _ := cmd.Flags().GetString("collab")
		collabs := utils.ReadingLines(collabFile)
		for _, collab := range collabs {
			database.ImportCollab(secret, collab)
		}
		break
	case "reload":
		signFolder, _ := cmd.Flags().GetString("signFolder")
		reloadSignature(signFolder)
		break
	default:
		HelpMessage()
	}
	return nil
}

// reloadSignature signature
func reloadSignature(signFolder string) {
	if !utils.FolderExists(signFolder) {
		utils.ErrorF("Signature folder not found: %v", signFolder)
		return
	}
	utils.GoodF("Reload signature in: %v", signFolder)

	database.CleanSigns()
	SignFolder, _ := filepath.Abs(path.Join(options.RootFolder, "base-signatures"))
	if signFolder != "" && utils.FolderExists(signFolder) {
		SignFolder = signFolder
	}
	allSigns := utils.GetFileNames(SignFolder, ".yaml")
	if allSigns != nil {
		utils.InforF("Load Signature from: %v", SignFolder)
		for _, signFile := range allSigns {
			database.ImportSign(signFile)
		}
	}
}

func configHelp(cmd *cobra.Command, args []string) {
	HelpMessage()
}

// HelpMessage print help message
func HelpMessage() {
	fmt.Println(libs.Banner())
	h := "\nConfig Command example:\n\n"
	h += "  jaeles config -a update\n\n"
	h += "  jaeles config -a update --repo http://github.com/jaeles-project/another-signatures --user admin --pass admin\n"
	h += "  jaeles config -a clean\n\n"
	h += "  jaeles config -a reload\n\n"
	h += "  jaeles config -a reload -F /tmp/custom-signatures/\n\n"
	h += "  jaeles config -a cred --user sample --pass not123456\n\n"
	//h += "  jaeles config -a oob --secret SomethingSecret --collab list_of_collabs.txt\n\n"
	fmt.Printf(h)
}

func ScanHelp(cmd *cobra.Command, args []string) {
	fmt.Println(libs.Banner())
	h := "\nScan Usage example:\n"
	h += "  jaeles scan -s <signature> -u <url>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls>\n"
	h += "  jaeles scan -c 50 -s <signature> -U <list_urls> [-p 'name=value']\n"
	h += "  jaeles scan -v -c 50 -s <signature> -U list_target.txt -o /tmp/output\n"
	h += "  jaeles scan -s <signature> -s <another-selector> -u http://example.com\n"
	h += "  cat list_target.txt | jaeles scan -c 100 -s <signature>\n"

	h += "\n\nExamples:\n"
	h += "  jaeles scan -s 'jira' -s 'ruby' -u target.com\n"
	h += "  jaeles scan -c 50 -s 'java' -x 'tomcat' -U list_of_urls.txt\n"
	h += "  jaeles scan -c 50 -s '/tmp/custom-signature/.*' -U list_of_urls.txt\n"
	h += "  cat urls.txt | grep 'interesting' | jaeles scan -c 50 -s 'fuzz/.*' -U list_of_urls.txt --proxy http://127.0.0.1:8080\n"
	h += "\n"
	fmt.Printf(h)
}
