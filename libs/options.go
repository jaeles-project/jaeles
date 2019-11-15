package libs

// Options global options
type Options struct {
	RootFolder string
	ScanID     string
	ConfigFile string
	SignFolder string
	Output     string
	Proxy      string

	Concurrency int
	Delay       int
	SaveRaw     bool
	Timeout     int
	Refresh     int
	Retry       int
	Verbose     bool
	Debug       bool
	NoOutput    bool
	Bind        string
}
