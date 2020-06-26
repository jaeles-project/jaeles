package libs

// Passive struct for passive detection
type Passive struct {
	Name       string
	Desc       string
	Risk       string
	Confidence string
	Level      int
	Rules      []Rule
}

// Rule rule for run detections
type Rule struct {
	ID         string
	Risk       string
	Confidence string
	Reason     string
	Detections []string
}
