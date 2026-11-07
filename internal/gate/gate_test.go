package gate

import (
	"strings"
	"testing"

	"kscan/internal/finding"
	"kscan/internal/scanner"
)

func TestDecide(t *testing.T) {
	ok := []scanner.Result{{Scanner: "semgrep", Status: scanner.StatusOK}, {Scanner: "gosec", Status: scanner.StatusSkipped}}
	broken := append([]scanner.Result{{Scanner: "trivy", Status: scanner.StatusError}}, ok...)
	newHigh := finding.Finding{Severity: finding.High, New: true}
	oldCritical := finding.Finding{Severity: finding.Critical, New: false}
	newLow := finding.Finding{Severity: finding.Low, New: true}

	cases := []struct {
		name      string
		results   []scanner.Result
		fs        []finding.Finding
		threshold finding.Severity
		enabled   bool
		code      int
		blocking  int
	}{
		{"clean", ok, nil, finding.High, true, Pass, 0},
		{"new high blocks", ok, []finding.Finding{newHigh, newLow}, finding.High, true, Fail, 1},
		{"below threshold passes", ok, []finding.Finding{newLow}, finding.Medium, true, Pass, 0},
		{"baselined critical passes", ok, []finding.Finding{oldCritical}, finding.High, true, Pass, 0},
		{"threshold none passes", ok, []finding.Finding{newHigh}, 0, false, Pass, 0},
		{"tool error wins", broken, []finding.Finding{newHigh}, finding.High, true, ToolError, 1},
		{"tool error without findings", broken, nil, finding.High, true, ToolError, 0},
	}
	for _, c := range cases {
		o := Decide(c.results, c.fs, c.threshold, c.enabled)
		if o.Code != c.code || o.Blocking != c.blocking {
			t.Errorf("%s: got code %d blocking %d, want %d %d", c.name, o.Code, o.Blocking, c.code, c.blocking)
		}
	}
}

func TestSummary(t *testing.T) {
	o := Decide([]scanner.Result{{Scanner: "trivy", Status: scanner.StatusError}},
		[]finding.Finding{{Severity: finding.High, New: true}}, finding.High, true)
	s := o.Summary()
	if !strings.HasPrefix(s, "ERROR") || !strings.Contains(s, "trivy") || !strings.Contains(s, "1 new finding") {
		t.Errorf("unexpected summary %q", s)
	}
}
