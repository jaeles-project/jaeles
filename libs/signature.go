package libs

// Signature base signature struct
type Signature struct {
	ID   string
	Type string
	Info struct {
		Name     string
		Category string
		Risk     string
		Tech     string
		OS       string
	}

	Variables []map[string]string
	Origin    Request
	Payloads  []string
	Requests  []Request
	Target    map[string]string
}
