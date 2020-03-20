package core

import (
	"fmt"
	"os"
	"path"

	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
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
		Depth:             1,
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
		os.RemoveAll(options.PassiveFolder)
		os.RemoveAll(options.ResourcesFolder)
		os.RemoveAll(options.ThirdPartyFolder)
	}
	if options.Server.Key != "" {
		cmd := fmt.Sprintf("GIT_SSH_COMMAND='ssh -o StrictHostKeyChecking=no -i %v' git clone --depth=1 %v %v", options.Server.Key, url, signPath)
		Execution(cmd)

	} else {
		_, err := git.PlainClone(signPath, false, &git.CloneOptions{
			Auth: &http.BasicAuth{
				Username: options.Server.Username,
				Password: options.Server.Password,
			},
			URL:               url,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			Depth:             1,
			Progress:          os.Stdout,
		})
		if err != nil {
			utils.ErrorF("Error to clone Signature repo: %v - %v", url, err)
			return
		}
	}
}
