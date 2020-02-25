package libs

// Options global options
type Options struct {
	RootFolder      string
	SignFolder      string
	PassiveFolder   string
	ResourcesFolder string
	ScanID          string
	ConfigFile      string
	PassiveOutput   string
	PassiveSummary  string
	Output          string
	SummaryOutput   string
	LogFile         string
	Proxy           string
	Selectors       string
	Params          []string
	Signs           []string
	Excludes        []string
	SelectedSigns   []string
	SelectedPassive string
	GlobalVar       map[string]string

	Concurrency   int
	Threads       int
	Delay         int
	SaveRaw       bool
	Timeout       int
	Refresh       int
	Retry         int
	Verbose       bool
	Debug         bool
	NoBackGround  bool
	NoOutput      bool
	EnablePassive bool
	Server        Server
}

// Server options for api server
type Server struct {
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
