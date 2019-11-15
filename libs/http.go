package libs

// Record all information about request
type Record struct {
	OriginReq   Request
	OriginRes   Response
	Request     Request
	Response    Response
	timeout     int
	Proxy       string
	Sign        Signature
	RawOutput   string
	ExtraOutput string
	ScanID      string
	// Issues    map[string]string
}

// Request all information about request
type Request struct {
	Scheme            string
	Host              string
	Port              string
	Path              string
	URL               string
	Method            string
	Redirect          bool
	UseTemplateHeader bool
	Headers           []map[string]string
	Body              string
	Beautify          string
	MiddlewareOutput  string
	Raw               string
	Detections        []string
	Middlewares       []string
	Generators        []string
	Encoding          string
	Target            map[string]string
}

// Response all information about response
type Response struct {
	StatusCode   int
	Status       string
	Headers      []map[string]string
	Body         string
	ResponseTime float64
	Length       int
	Beautify     string
}
