package cmd

import (
	"bufio"
	"fmt"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/utils"
	"github.com/panjf2000/ants"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
)

func init() {
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan list of URLs based on selected signatures",
		Long:  libs.Banner(),
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("url", "u", "", "URL of target")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringVarP(&options.Scan.RawRequest, "raw", "r", "", "Raw request from Burp for origin")
	scanCmd.Flags().BoolVar(&options.Scan.EnableGenReport, "html", false, "Generate HTML report after the scan done")
	scanCmd.SetHelpFunc(ScanHelp)
	RootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	// fmt.Println(os.Args)
	SelectSign()
	var urls []string
	// parse URL input here
	urlFile, _ := cmd.Flags().GetString("urls")
	urlInput, _ := cmd.Flags().GetString("url")
	if urlInput != "" {
		urls = append(urls, urlInput)
	}
	// input as a file
	if urlFile != "" {
		URLs := utils.ReadingLines(urlFile)
		for _, url := range URLs {
			urls = append(urls, url)
		}
	}

	// input as stdin
	if len(urls) == 0 {
		stat, _ := os.Stdin.Stat()
		// detect if anything came from std
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				url := strings.TrimSpace(sc.Text())
				if err := sc.Err(); err == nil && url != "" {
					urls = append(urls, url)
				}
			}
			// store stdin as a temp file
			if len(urls) > options.ChunkLimit && options.ChunkRun {
				urlFile = path.Join(options.ChunkDir, fmt.Sprintf("raw-%v", core.RandomString(8)))
				utils.InforF("Write stdin data to: %v", urlFile)
				utils.WriteToFile(urlFile, strings.Join(urls, "\n"))
			}
		}
	}

	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "[Error] No input loaded\n")
		fmt.Fprintf(os.Stderr, "Use 'jaeles -h' for more information about a command.\n")
		os.Exit(1)
	}

	if len(urls) > options.ChunkLimit && !options.ChunkRun {
		utils.WarningF("Your inputs look very big.")
		utils.WarningF("Consider using --chunk options")
	}
	if len(urls) > options.ChunkLimit && options.ChunkRun {
		utils.InforF("Running Jaeles in Chunk mode")
		rawCommand := strings.Join(os.Args, " ")

		if strings.Contains(rawCommand, "-U ") {
			rawCommand = strings.ReplaceAll(rawCommand, fmt.Sprintf("-U %v", urlFile), "-U {}")
		} else {
			rawCommand += " -U {}"
		}
		urlFiles := genChunkFiles(urlFile, options)
		runChunk(rawCommand, urlFiles, options.ChunkThreads)
		for _, chunkFile := range urlFiles {
			os.RemoveAll(chunkFile)
		}
		os.Exit(0)
	}
	utils.InforF("Input Loaded: %v", len(urls))

	/* ---- Really start do something ---- */

	// run background detector
	if !options.NoBackGround {
		go func() {
			for {
				core.Background(options)
			}
		}()
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(options.Concurrency, func(i interface{}) {
		CreateRunner(i)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	for _, signFile := range options.SelectedSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign: %v", signFile)
			continue
		}
		// filter signature by level
		if sign.Level > options.Level {
			continue
		}

		// Submit tasks one by one.
		for _, url := range urls {
			wg.Add(1)
			job := libs.Job{URL: url, Sign: sign}
			_ = p.Invoke(job)
		}
	}

	wg.Wait()
	CleanOutput()

	if options.Scan.EnableGenReport && utils.FolderExists(options.Output) {
		DoGenReport(options)
	}
	return nil
}

func CreateRunner(j interface{}) {
	var jobs []libs.Job
	job := j.(libs.Job)

	// auto append http and https prefix if not present
	if !strings.HasPrefix(job.URL, "http://") && !strings.HasPrefix(job.URL, "https://") {
		withPrefixJob := job
		job.URL = "http://" + job.URL
		jobs = append(jobs, withPrefixJob)

		withPrefixJob = job
		job.URL = "https://" + job.URL
		jobs = append(jobs, withPrefixJob)
	} else {
		jobs = append(jobs, job)
	}

	if (job.Sign.Replicate.Ports != "" || job.Sign.Replicate.Prefixes != "") && !options.Mics.DisableReplicate {
		if options.Mics.BaseRoot {
			job.Sign.BasePath = true
		}
		moreJobs, err := core.ReplicationJob(job.URL, job.Sign)
		if err == nil {
			jobs = append(jobs, moreJobs...)
		}
	}

	for _, job := range jobs {
		if job.Sign.Type == "routine" {
			routine, err := core.InitRoutine(job.URL, job.Sign, options)
			if err != nil {
				utils.ErrorF("Error create new routine: %v", err)
			}
			routine.Start()
			continue
		}
		runner, err := core.InitRunner(job.URL, job.Sign, options)
		if err != nil {
			utils.ErrorF("Error create new runner: %v", err)
		}
		runner.Sending()
	}
}

/////////////////////// Chunk options (very experimental)

func genChunkFiles(urlFile string, options libs.Options) []string {
	utils.DebugF("Store tmp chunk data at: %v", options.ChunkDir)
	var divided [][]string
	var chunkFiles []string
	divided = utils.ChunkFileBySize(urlFile, options.ChunkSize)
	for index, chunk := range divided {
		outName := path.Join(options.ChunkDir, fmt.Sprintf("%v-%v", core.RandomString(6), index))
		utils.WriteToFile(outName, strings.Join(chunk, "\n"))
		chunkFiles = append(chunkFiles, outName)
	}
	return chunkFiles
}

func runChunk(command string, urlFiles []string, threads int) {
	utils.DebugF("Run chunk command with template: %v", command)

	var commands []string
	for index, urlFile := range urlFiles {
		cmd := command
		cmd = strings.Replace(cmd, "{}", urlFile, -1)
		cmd = strings.Replace(cmd, "{#}", fmt.Sprintf("%d", index), -1)
		commands = append(commands, cmd)
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(threads, func(i interface{}) {
		cmd := i.(string)
		ExecutionWithStd(cmd)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()
	for _, command := range commands {
		wg.Add(1)
		_ = p.Invoke(command)
	}
	wg.Wait()
}

// ExecutionWithStd Run a command
func ExecutionWithStd(cmd string) (string, error) {
	command := []string{
		"bash",
		"-c",
		cmd,
	}
	var output string
	realCmd := exec.Command(command[0], command[1:]...)
	// output command output to std too
	cmdReader, _ := realCmd.StdoutPipe()
	scanner := bufio.NewScanner(cmdReader)
	var out string
	go func() {
		for scanner.Scan() {
			out += scanner.Text()
			//fmt.Fprintf(os.Stderr, scanner.Text()+"\n")
			fmt.Println(scanner.Text())
		}
	}()
	if err := realCmd.Start(); err != nil {
		return "", err
	}
	if err := realCmd.Wait(); err != nil {
		return "", err
	}
	return output, nil
}
