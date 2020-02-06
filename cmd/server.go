package cmd

import (
	"fmt"
	"path"
	"path/filepath"
	"sync"

	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/database"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/server"
	"github.com/jaeles-project/jaeles/utils"

	"github.com/spf13/cobra"
)

var serverCmd *cobra.Command

func init() {
	// byeCmd represents the bye command
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start API server",
		Long:  libs.Banner(), RunE: runServer,
	}
	serverCmd.Flags().StringP("sign", "s", "", "Provide custom header seperate by ','")
	serverCmd.Flags().String("host", "127.0.0.1", "IP address to bind the server")
	serverCmd.Flags().String("port", "5000", "Port")
	RootCmd.AddCommand(serverCmd)

}

func runServer(cmd *cobra.Command, args []string) error {
	// prepare DB stuff
	if options.Server.Username != "" {
		database.CreateUser(options.Server.Username, options.Server.Password)
	}
	// reload signature
	SignFolder, _ := filepath.Abs(path.Join(options.RootFolder, "base-signatures"))
	allSigns := utils.GetFileNames(SignFolder, ".yaml")
	if allSigns != nil {
		for _, signFile := range allSigns {
			database.ImportSign(signFile)
		}
	}
	database.InitConfigSign()

	result := make(chan libs.Record)
	jobs := make(chan libs.Job)

	go func() {
		for {
			Signs := []string{}
			signName, _ := cmd.Flags().GetString("sign")
			// Get exactly signature
			if signName != "" {
				signs := core.SelectSign(signName)
				Signs = append(Signs, signs...)
			} else {
				signName = database.GetDefaultSign()
			}
			Signs = append(Signs, database.SelectSign(signName)...)
			signInfo := ""
			for _, signName := range Signs {
				signInfo += fmt.Sprintf("%v ", filepath.Base(signName))
			}
			utils.InforF("Number of Signatures Loaded: %v", len(Signs))
			utils.InforF("Signatures Loaded : %v", signInfo)

			// create new scan or group with old one
			if options.ScanID == "" {
				options.ScanID = database.NewScan(options, "scan", Signs)
			}

			record := <-result
			utils.InforF("[Receive] %v %v \n", record.OriginReq.Method, record.OriginReq.URL)

			for _, signFile := range Signs {
				sign, err := core.ParseSign(signFile)
				if err != nil {
					utils.ErrorF("Error loading sign: %v\n", signFile)
					continue
				}
				// parse sign as list or single
				if sign.Type != "fuzz" {
					url := record.OriginReq.URL
					jobs <- libs.Job{URL: url, Sign: sign}

				} else {

					fuzzSign := sign
					fuzzSign.Requests = []libs.Request{}
					for _, req := range sign.Requests {
						core.ParseRequestFromServer(&record, req, sign)
						// append all requests in sign with request from api
						req.Method = record.Request.Method
						req.URL = record.Request.URL
						req.Headers = record.Request.Headers
						req.Body = record.Request.Body
						fuzzSign.Requests = append(fuzzSign.Requests, req)

					}
					url := record.OriginReq.URL
					jobs <- libs.Job{URL: url, Sign: fuzzSign}

				}
			}

		}
	}()

	/* Start sending request here */
	var wg sync.WaitGroup
	for i := 0; i < options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				sign := job.Sign
				url := job.URL
				RunJob(url, sign, options)
			}
		}()
	}

	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetString("port")
	bind := fmt.Sprintf("%v:%v", host, port)
	options.Server.Bind = bind
	utils.InforF("Start API server at %v", fmt.Sprintf("http://%v/#/", bind))

	server.InitRouter(options, result)
	// wg.Wait()
	return nil
}
