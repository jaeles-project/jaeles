package libs

// Signature base signature struct
type Signature struct {
	ID      string
	RawPath string
	Type    string
	Level   int
	// some mics options
	Threads    int
	Passive    bool
	Parallel   bool
	Single     bool
	Serial     bool
	BasePath   bool
	CleanSlash bool
	// Detect once
	Noutput      bool
	Donce        bool
	StopOnSucces bool

	// Default variables for gen more inputs
	Replicate struct {
		Ports    string
		Prefixes string
	}

	// conditions to check before sending the whole requests
	CRequests []Request
	COutput   bool   `yaml:"coutput"` // store output for check request too
	Match     string // any, all

	Info struct {
		Name       string
		Author     string
		Risk       string
		Confidence string
		Category   string
		Tech       string
		OS         string
	}

	Origin     Request
	Origins    []Origin
	Requests   []Request
	RawRequest string
	Payloads   []string
	Params     []map[string]string
	Variables  []map[string]string
	Target     map[string]string

	// routines
	Routines []Routine
}

// Routine struct
type Routine struct {
	Signs  []map[string]string
	Names  []string
	Passed bool

	Logics []struct {
		Level  int
		Expression string   `yaml:"expr"`
		Invokes    []string `yaml:"invokes"`
	} `yaml:"logics"`
}
