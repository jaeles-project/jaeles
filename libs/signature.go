package libs

// Signature base signature struct
type Signature struct {
	ID       string
	RawPath  string
	Type     string
	Level    int
	Passive  bool
	Parallel bool
	Single   bool
	// Detect once
	Donce bool
	Info  struct {
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
}
