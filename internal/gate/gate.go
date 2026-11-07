// Package gate decides the scan's exit code.
package gate

import (
	"fmt"

	"kscan/internal/finding"
	"kscan/internal/scanner"
)

const (
	Pass      = 0
	Fail      = 1
	ToolError = 2
)

type Outcome struct {
	Code int `json:"code"`
	// Status is "pass", "fail" or "error".
	Status string `json:"status"`
	// Threshold is the fail_on severity, or "none".
	Threshold string `json:"threshold"`
	// Blocking counts new findings at or above the threshold.
	Blocking   int      `json:"blocking"`
	ToolErrors []string `json:"tool_errors,omitempty"`
}

// Decide returns ToolError if any scanner failed, since an incomplete scan
// cannot be trusted as a pass; otherwise Fail if a new finding reaches the
// threshold. Only findings marked New count, so baselined issues never block.
func Decide(results []scanner.Result, fs []finding.Finding, threshold finding.Severity, enabled bool) Outcome {
	o := Outcome{Threshold: "none"}
	if enabled {
		o.Threshold = threshold.String()
		for _, f := range fs {
			if f.New && f.Severity >= threshold {
				o.Blocking++
			}
		}
	}
	for _, r := range results {
		if r.Status == scanner.StatusError {
			o.ToolErrors = append(o.ToolErrors, r.Scanner)
		}
	}
	switch {
	case len(o.ToolErrors) > 0:
		o.Code, o.Status = ToolError, "error"
	case o.Blocking > 0:
		o.Code, o.Status = Fail, "fail"
	default:
		o.Code, o.Status = Pass, "pass"
	}
	return o
}

// Summary is a one-line, human-readable explanation of the outcome.
func (o Outcome) Summary() string {
	var s string
	switch o.Status {
	case "pass":
		s = "PASS: no new findings at or above " + o.Threshold
		if o.Threshold == "none" {
			s = "PASS: fail_on is none"
		}
	case "fail":
		s = fmt.Sprintf("FAIL: %d new finding(s) at or above %s", o.Blocking, o.Threshold)
	case "error":
		s = fmt.Sprintf("ERROR: scanner(s) failed: %v", o.ToolErrors)
		if o.Blocking > 0 {
			s += fmt.Sprintf("; also %d new finding(s) at or above %s", o.Blocking, o.Threshold)
		}
	}
	return s
}
