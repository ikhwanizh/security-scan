// Package report renders scan results as terminal output, SARIF and HTML.
package report

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"kscan/internal/detect"
	"kscan/internal/filter"
	"kscan/internal/finding"
	"kscan/internal/gate"
	"kscan/internal/scanner"
)

type Data struct {
	Version   string
	Repo      string
	Stack     detect.Stack
	StartedAt time.Time
	Duration  time.Duration
	Scanners  []scanner.Result
	Findings  []finding.Finding
	Stats     filter.Stats
	Commit    string
	// Baseline is the baseline file used, or "" (then every finding is new).
	Baseline string
	Gate     gate.Outcome
}

// SeverityCount is one bucket of the severity summary, highest first.
type SeverityCount struct {
	Severity finding.Severity
	Count    int
	New      int
}

func (d Data) BySeverity() []SeverityCount {
	counts := map[finding.Severity]int{}
	news := map[finding.Severity]int{}
	for _, f := range d.Findings {
		counts[f.Severity]++
		if f.New {
			news[f.Severity]++
		}
	}
	var out []SeverityCount
	for s := finding.Critical; s >= finding.Info; s-- {
		out = append(out, SeverityCount{s, counts[s], news[s]})
	}
	return out
}

// NewCount counts findings not in the baseline.
func (d Data) NewCount() int {
	n := 0
	for _, f := range d.Findings {
		if f.New {
			n++
		}
	}
	return n
}

type ToolCount struct {
	Tool  string
	Count int
}

// ByTool counts findings per tool. A finding merged from several tools
// counts once for each.
func (d Data) ByTool() []ToolCount {
	counts := map[string]int{}
	for _, f := range d.Findings {
		for _, t := range strings.Split(f.Tool, ",") {
			counts[t]++
		}
	}
	var out []ToolCount
	for t, c := range counts {
		out = append(out, ToolCount{t, c})
	}
	slices.SortFunc(out, func(a, b ToolCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Tool, b.Tool))
	})
	return out
}

func (d Data) Languages() string {
	var ls []string
	for _, l := range d.Stack.Languages {
		ls = append(ls, string(l))
	}
	if len(ls) == 0 {
		return "no known stack"
	}
	return strings.Join(ls, ", ")
}

func primaryTool(tool string) string {
	t, _, _ := strings.Cut(tool, ",")
	return t
}
