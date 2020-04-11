package cmd

import (
	"fmt"
	"github.com/panjf2000/ants"
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

func init() {
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start API server",
		Long:  libs.Banner(), RunE: runServer,
	}
	serverCmd.Flags().String("host", "127.0.0.1", "IP address to bind the server")
	serverCmd.Flags().String("port", "5000", "Port")
	RootCmd.AddCommand(serverCmd)

}

func runServer(cmd *cobra.Command, _ []string) error {
	SelectSign()
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

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(options.Concurrency, func(i interface{}) {
		startScanJob(i)
		wg.Done()
	})
	defer p.Release()

	result := make(chan libs.Record)
	go func() {
		for {
			record := <-result
			utils.InforF("[Receive] %v %v \n", record.OriginReq.Method, record.OriginReq.URL)
			for _, signFile := range options.SelectedSigns {
				sign, err := core.ParseSign(signFile)
				if err != nil {
					utils.ErrorF("Error loading sign: %v\n", signFile)
					continue
				}
				// filter signature by level
				if sign.Level > options.Level {
					continue
				}

				// parse sign as list or single
				if sign.Type != "fuzz" {
					url := record.OriginReq.URL
					wg.Add(1)
					job := libs.Job{URL: url, Sign: sign}
					_ = p.Invoke(job)
				} else {
					fuzzSign := sign
					fuzzSign.Requests = []libs.Request{}
					for _, req := range sign.Requests {
						core.ParseRequestFromServer(&record, req, sign)
						// override the original if these field defined in signature
						if req.Method == "" {
							req.Method = record.OriginReq.Method
						}
						if req.URL == "" {
							req.URL = record.OriginReq.URL
						}
						req.Headers = record.OriginReq.Headers
						if len(req.Headers) == 0 {
						}
						if req.Body == "" {
							req.Body = record.OriginReq.Body
						}
						fuzzSign.Requests = append(fuzzSign.Requests, req)
					}
					url := record.OriginReq.URL
					wg.Add(1)
					job := libs.Job{URL: url, Sign: fuzzSign}
					_ = p.Invoke(job)
				}
			}

		}
	}()

	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetString("port")
	bind := fmt.Sprintf("%v:%v", host, port)
	options.Server.Bind = bind
	utils.InforF("Start API server at %v", fmt.Sprintf("http://%v/#/", bind))

	server.InitRouter(options, result)
	wg.Wait()
	return nil
}
