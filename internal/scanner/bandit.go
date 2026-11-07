package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Bandit is the Python-specific SAST scanner.
type Bandit struct{}

func (Bandit) Name() string                 { return "bandit" }
func (Bandit) Applies(st detect.Stack) bool { return st.Has(detect.Python) }
func (Bandit) Available() (string, error)   { return lookPath("bandit") }

func (b Bandit) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := b.Available()
	if err != nil {
		return nil, err
	}
	paths, err := targets(opts, func(p string) bool {
		return strings.HasSuffix(p, ".py") && !slices.Contains(strings.Split(p, "/"), "tests")
	})
	if err != nil {
		return nil, err
	}
	out, cleanup, err := tempOutput("bandit")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var excludes []string
	for _, d := range append(append([]string{}, detect.SkipDirs...), "tests") {
		excludes = append(excludes, "*/"+d+"/*")
	}
	args := append([]string{"-r", "-f", "json", "-q", "-o", out, "-x", strings.Join(excludes, ",")}, paths...)
	_, runErr := execTool(ctx, repo, bin, args...)
	data, err := readOutput(out, runErr)
	if err != nil {
		return nil, err
	}
	fs, err := parseBandit(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for i := range fs {
		fs[i].File = relPath(repo, fs[i].File)
	}
	return finalize(repo, fs), nil
}

type banditOutput struct {
	Results []struct {
		Filename        string `json:"filename"`
		LineNumber      int    `json:"line_number"`
		TestID          string `json:"test_id"`
		TestName        string `json:"test_name"`
		IssueText       string `json:"issue_text"`
		IssueSeverity   string `json:"issue_severity"`
		IssueConfidence string `json:"issue_confidence"`
	} `json:"results"`
}

func parseBandit(r io.Reader) ([]finding.Finding, error) {
	var o banditOutput
	if err := json.NewDecoder(r).Decode(&o); err != nil {
		return nil, fmt.Errorf("parse bandit: %w", err)
	}
	fs := make([]finding.Finding, 0, len(o.Results))
	for _, x := range o.Results {
		sev, _ := finding.ParseSeverity(x.IssueSeverity)
		fs = append(fs, finding.Finding{
			Tool:     "bandit",
			RuleID:   x.TestID + "-" + x.TestName,
			Category: finding.SAST,
			Severity: withConfidence(sev, x.IssueConfidence),
			File:     x.Filename,
			Line:     x.LineNumber,
			Message:  x.IssueText,
		})
	}
	return fs, nil
}
