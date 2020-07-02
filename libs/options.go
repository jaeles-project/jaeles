package libs

// Options global options
type Options struct {
	RootFolder       string
	SignFolder       string
	PassiveFolder    string
	ResourcesFolder  string
	ThirdPartyFolder string
	ScanID           string
	ConfigFile       string
	FoundCmd         string
	QuietFormat      string
	PassiveOutput    string
	PassiveSummary   string
	Output           string
	SummaryOutput    string
	SummaryVuln      string
	LogFile          string
	Proxy            string
	Selectors        string
	Params           []string
	Headers          []string
	Signs            []string
	Excludes         []string
	SelectedSigns    []string
	ParallelSigns    []string
	SelectedPassive  string
	GlobalVar        map[string]string

	Level             int
	Concurrency       int
	Threads           int
	Delay             int
	SaveRaw           bool
	Timeout           int
	Refresh           int
	Retry             int
	Quiet             bool
	Verbose           bool
	Version           bool
	Debug             bool
	NoDB              bool
	NoBackGround      bool
	NoOutput          bool
	EnableFormatInput bool
	EnablePassive     bool
	DisableParallel   bool
	BaseRoot          bool
	BurpProxy         bool
	Server            Server
	Report            Report
}

// Report options for api server
type Report struct {
	ReportName   string
	TemplateFile string
	OutputPath   string
	Title        string
}

// Server options for api server
type Server struct {
	NoAuth       bool
	DBPath       string
	Bind         string
	JWTSecret    string
	Cors         string
	DefaultSign  string
	SecretCollab string
	Username     string
	Password     string
	Key          string
}

// Job define job for running routine
type Job struct {
	URL  string
	Sign Signature
}

// PJob define job for running routine
type PJob struct {
	Req  Request
	ORec Record
	Sign Signature
}
