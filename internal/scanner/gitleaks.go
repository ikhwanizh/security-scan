package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Gitleaks finds hardcoded secrets in the working tree and optionally git history.
type Gitleaks struct{}

func (Gitleaks) Name() string               { return "gitleaks" }
func (Gitleaks) Applies(detect.Stack) bool  { return true }
func (Gitleaks) Available() (string, error) { return lookPath("gitleaks") }

func (g Gitleaks) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := g.Available()
	if err != nil {
		return nil, err
	}
	// Each entry is one gitleaks invocation: a subcommand plus extra flags.
	modes := [][]string{{"dir"}}
	switch {
	case opts.BaseRef != "":
		// Only the PR's own commits. This also catches a secret that was
		// added and removed again inside the PR.
		modes = [][]string{{"git", "--log-opts=" + opts.BaseRef + "..HEAD"}}
	case opts.History:
		modes = append(modes, []string{"git"})
	}
	var all []finding.Finding
	for _, mode := range modes {
		out, cleanup, err := tempOutput("gitleaks")
		if err != nil {
			return nil, err
		}
		args := append([]string{mode[0], ".", "--redact", "--no-banner", "--exit-code", "0",
			"--report-format", "json", "--report-path", out}, mode[1:]...)
		_, runErr := execTool(ctx, repo, bin, args...)
		data, err := readOutput(out, runErr)
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("gitleaks %s: %w", mode[0], err)
		}
		fs, err := parseGitleaks(bytes.NewReader(data))
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

type gitleaksResult struct {
	RuleID      string
	Description string
	File        string
	StartLine   int
	Commit      string
	Date        string
}

func parseGitleaks(r io.Reader) ([]finding.Finding, error) {
	var rs []gitleaksResult
	if err := json.NewDecoder(r).Decode(&rs); err != nil {
		return nil, fmt.Errorf("parse gitleaks: %w", err)
	}
	fs := make([]finding.Finding, 0, len(rs))
	for _, x := range rs {
		msg := x.Description
		if x.Commit != "" {
			short := x.Commit
			if len(short) > 8 {
				short = short[:8]
			}
			msg += fmt.Sprintf(" (git history: commit %s", short)
			if len(x.Date) >= 10 {
				msg += ", " + x.Date[:10]
			}
			msg += ")"
		}
		fs = append(fs, finding.Finding{
			Tool:     "gitleaks",
			RuleID:   x.RuleID,
			Category: finding.Secret,
			Severity: finding.High,
			File:     x.File,
			Line:     x.StartLine,
			Message:  msg,
		})
	}
	return fs, nil
}
