package libs

// Passive struct for passive detection
type Passive struct {
	Name  string
	Desc  string
	Rules []Rule
}

// Rule rule for run detections
type Rule struct {
	ID         string
	Reason     string
	Detections []string
}
