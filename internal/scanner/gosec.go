package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Gosec is the Go-specific SAST scanner.
type Gosec struct{}

func (Gosec) Name() string                 { return "gosec" }
func (Gosec) Applies(st detect.Stack) bool { return st.Has(detect.Go) }
func (Gosec) Available() (string, error)   { return lookPath("gosec") }

func (g Gosec) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := g.Available()
	if err != nil {
		return nil, err
	}
	var all []finding.Finding
	for _, root := range opts.Stack.Roots[detect.Go] {
		out, cleanup, err := tempOutput("gosec")
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(repo, root)
		_, runErr := execTool(ctx, dir, bin, "-fmt", "json", "-out", out, "-no-fail", "-quiet", "./...")
		data, err := readOutput(out, runErr)
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("gosec in %s: %w", root, err)
		}
		fs, err := parseGosec(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		all = append(all, fs...)
	}
	for i := range all {
		all[i].File = relPath(repo, all[i].File)
	}
	return finalize(repo, all), nil
}

type gosecOutput struct {
	Issues []struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		RuleID     string `json:"rule_id"`
		Details    string `json:"details"`
		File       string `json:"file"`
		Line       string `json:"line"` // "12" or "12-14"
		Code       string `json:"code"`
	} `json:"Issues"`
}

func parseGosec(r io.Reader) ([]finding.Finding, error) {
	var o gosecOutput
	if err := json.NewDecoder(r).Decode(&o); err != nil {
		return nil, fmt.Errorf("parse gosec: %w", err)
	}
	fs := make([]finding.Finding, 0, len(o.Issues))
	for _, x := range o.Issues {
		sev, _ := finding.ParseSeverity(x.Severity)
		start, _, _ := strings.Cut(x.Line, "-")
		line, _ := strconv.Atoi(start)
		fs = append(fs, finding.Finding{
			Tool:     "gosec",
			RuleID:   x.RuleID,
			Category: finding.SAST,
			Severity: withConfidence(sev, x.Confidence),
			File:     x.File,
			Line:     line,
			Message:  x.Details,
		})
	}
	return fs, nil
}

// withConfidence drops a severity one level when the tool itself has low
// confidence in the finding.
func withConfidence(sev finding.Severity, confidence string) finding.Severity {
	if strings.EqualFold(confidence, "low") && sev > finding.Info {
		return sev - 1
	}
	return sev
}
