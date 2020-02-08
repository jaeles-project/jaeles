package libs

// Record all information about request
type Record struct {
	OriginReq   Request
	OriginRes   Response
	Request     Request
	Response    Response
	Sign        Signature
	RawOutput   string
	ExtraOutput string
	ScanID      string
}

// Request all information about request
type Request struct {
	Engine            string
	Timeout           int
	Repeat            int
	Scheme            string
	Host              string
	Port              string
	Path              string
	URL               string
	Proxy             string
	Method            string
	Redirect          bool
	UseTemplateHeader bool
	Headers           []map[string]string
	Values            []map[string]string
	Body              string
	Beautify          string
	MiddlewareOutput  string
	Raw               string
	Conditions        []string
	Middlewares       []string
	Conclusions       []string
	Detections        []string
	Generators        []string
	Encoding          string
	Target            map[string]string
}

// Response all information about response
type Response struct {
	HasPopUp     bool
	StatusCode   int
	Status       string
	Headers      []map[string]string
	Body         string
	ResponseTime float64
	Length       int
	Beautify     string
}
