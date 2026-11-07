package report

import (
	"encoding/json"
	"io"
	"time"

	"kscan/internal/filter"
	"kscan/internal/finding"
	"kscan/internal/gate"
)

type jsonScanner struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Findings   int    `json:"raw_findings"`
}

type jsonCounts struct {
	Total map[string]int `json:"total"`
	New   map[string]int `json:"new"`
}

type jsonSummary struct {
	Version    string            `json:"version"`
	Repo       string            `json:"repo"`
	Commit     string            `json:"commit,omitempty"`
	Baseline   string            `json:"baseline,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	DurationMS int64             `json:"duration_ms"`
	Gate       gate.Outcome      `json:"gate"`
	Counts     jsonCounts        `json:"counts"`
	Scanners   []jsonScanner     `json:"scanners"`
	Stats      filter.Stats      `json:"stats"`
	Findings   []finding.Finding `json:"findings"`
}

// JSON writes a machine-readable summary. Secret findings never carry a
// snippet (see scanner.finalize), so this file holds no secret values.
func JSON(w io.Writer, d Data) error {
	s := jsonSummary{
		Version: d.Version, Repo: d.Repo, Commit: d.Commit, Baseline: d.Baseline,
		StartedAt: d.StartedAt.UTC(), DurationMS: d.Duration.Milliseconds(),
		Gate: d.Gate, Stats: d.Stats, Findings: d.Findings,
		Counts:   jsonCounts{Total: map[string]int{}, New: map[string]int{}},
		Scanners: []jsonScanner{},
	}
	if s.Findings == nil {
		s.Findings = []finding.Finding{}
	}
	for _, sc := range d.BySeverity() {
		s.Counts.Total[sc.Severity.String()] = sc.Count
		s.Counts.New[sc.Severity.String()] = sc.New
	}
	for _, r := range d.Scanners {
		s.Scanners = append(s.Scanners, jsonScanner{
			Name: r.Scanner, Status: string(r.Status), Reason: r.Reason,
			DurationMS: r.Duration.Milliseconds(), Findings: len(r.Findings),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
