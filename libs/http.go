package libs

// Record all information about request
type Record struct {
	DonePassive   bool
	SelectPassive string
	OriginReq     Request
	OriginRes     Response
	Origins       []Origin
	Request       Request
	Response      Response
	Sign          Signature
	RawOutput     string
	ExtraOutput   string
	DetectString  string
	ScanID        string
}

// Origin contain map of origins
type Origin struct {
	Label     string
	ORequest  Request  `yaml:"origin_req"`
	OResponse Response `yaml:"origin_res"`
}

// Request all information about request
type Request struct {
	RawInput          string
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
