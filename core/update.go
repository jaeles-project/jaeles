package core

import (
	"fmt"
	"os"
	"path"

	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"gopkg.in/src-d/go-git.v4"
)

// UpdatePlugins update latest UI and Plugins from default repo
func UpdatePlugins(options libs.Options) {
	pluginPath := path.Join(options.RootFolder, "plugins")
	url := libs.UIREPO
	utils.GoodF("Cloning Plugins from: %v", url)
	if utils.FolderExists(pluginPath) {
		utils.InforF("Remove: %v", pluginPath)
		os.RemoveAll(pluginPath)
	}
	r, err := git.PlainClone(pluginPath, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		fmt.Println("Error to clone Plugins repo")
	} else {
		_, err = r.Head()
		if err != nil {
			fmt.Println("Error to clone Plugins repo")
		}
	}

}

// UpdateSignature update latest UI from UI repo
func UpdateSignature(options libs.Options, customRepo string) {
	signPath := path.Join(options.RootFolder, "base-signatures")
	url := libs.SIGNREPO
	if customRepo != "" {
		url = customRepo
	}
	utils.GoodF("Cloning Signature from: %v", url)
	if utils.FolderExists(signPath) {
		utils.InforF("Remove: %v", signPath)
		os.RemoveAll(signPath)
	}
	r, err := git.PlainClone(signPath, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		libs.ErrorF("Error to clone Signature repo")
	} else {
		_, err = r.Head()
		if err != nil {
			libs.ErrorF("Error to clone Signature repo")
		}
	}

	// move passive signatures to default passive
	passivePath := path.Join(signPath, "passives")
	if utils.FolderExists(passivePath) {
		utils.MoveFolder(passivePath, options.PassiveFolder)
	}
}

// // UpdateOutOfBand renew things in Out of band check
// func UpdateOutOfBand(options libs.Options) {
// 	// http
// 	// dns
// }
