package core

import (
	"fmt"
	"os"
	"path"

	"github.com/jaeles-project/jaeles/libs"
	"gopkg.in/src-d/go-git.v4"
)

// UpdatePlugins update latest UI and Plugins from default repo
func UpdatePlugins(options libs.Options) {
	pluginPath := path.Join(options.RootFolder, "plugins")
	url := libs.UIREPO
	libs.GoodF("Cloning Plugins from: %v", url)
	if FolderExists(pluginPath) {
		libs.InforF("Remove: %v", pluginPath)
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
func UpdateSignature(options libs.Options) {
	signPath := path.Join(options.RootFolder, "base-signatures")
	url := libs.SIGNREPO
	libs.GoodF("Cloning Signature from: %v", url)
	if FolderExists(signPath) {
		libs.InforF("Remove: %v", signPath)
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
}

// // UpdateOutOfBand renew things in Out of band check
// func UpdateOutOfBand(options libs.Options) {
// 	// http
// 	// dns
// }
