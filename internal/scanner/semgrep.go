package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Semgrep runs pattern-based SAST with registry rulesets plus kscan's custom rules.
type Semgrep struct{}

func (Semgrep) Name() string               { return "semgrep" }
func (Semgrep) Applies(detect.Stack) bool  { return true }
func (Semgrep) Available() (string, error) { return lookPath("semgrep") }

// registryConfigs picks semgrep registry rulesets for the detected stack.
// Secrets rulesets are left out on purpose: gitleaks covers them.
func registryConfigs(st detect.Stack) []string {
	cfgs := []string{"p/owasp-top-ten"}
	perLang := map[detect.Lang][]string{
		detect.Go:     {"p/golang"},
		detect.Python: {"p/python"},
		detect.Rust:   {"p/rust"},
		detect.PHP:    {"p/php"},
		detect.Node:   {"p/javascript", "p/typescript"},
	}
	for _, l := range st.Languages {
		cfgs = append(cfgs, perLang[l]...)
	}
	return cfgs
}

func (s Semgrep) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := s.Available()
	if err != nil {
		return nil, err
	}
	// Semgrep picks rules by file extension, so every changed file is a target.
	paths, err := targets(opts, func(string) bool { return true })
	if err != nil {
		return nil, err
	}
	out, cleanup, err := tempOutput("semgrep")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{"scan", "--json", "--metrics", "off", "--quiet", "--output", out}
	var cfgs []string
	if !opts.Offline {
		cfgs = registryConfigs(opts.Stack)
	}
	if opts.RulesDir != "" {
		cfgs = append(cfgs, opts.RulesDir)
	}
	if len(cfgs) == 0 {
		return nil, fmt.Errorf("no semgrep rules to run (offline without custom rules)")
	}
	for _, c := range cfgs {
		args = append(args, "--config", c)
	}
	for _, d := range detect.SkipDirs {
		args = append(args, "--exclude", d)
	}
	args = append(args, paths...)

	_, runErr := execTool(ctx, repo, bin, args...)
	data, err := readOutput(out, runErr)
	if err != nil {
		return nil, err
	}
	fs, err := parseSemgrep(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for i := range fs {
		fs[i].File = relPath(repo, fs[i].File)
	}
	return finalize(repo, fs), nil
}

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
		} `json:"extra"`
	} `json:"results"`
}

func parseSemgrep(r io.Reader) ([]finding.Finding, error) {
	var o semgrepOutput
	if err := json.NewDecoder(r).Decode(&o); err != nil {
		return nil, fmt.Errorf("parse semgrep: %w", err)
	}
	fs := make([]finding.Finding, 0, len(o.Results))
	for _, x := range o.Results {
		cat := finding.SAST
		if strings.Contains(x.CheckID, ".secrets.") {
			cat = finding.Secret
		}
		snippet := strings.TrimSpace(x.Extra.Lines)
		if snippet == "requires login" { // semgrep OSS hides source lines
			snippet = ""
		}
		fs = append(fs, finding.Finding{
			Tool:     "semgrep",
			RuleID:   shortRuleID(x.CheckID),
			Category: cat,
			Severity: semgrepSeverity(x.Extra.Severity),
			File:     x.Path,
			Line:     x.Start.Line,
			Message:  strings.TrimSpace(x.Extra.Message),
			Snippet:  firstLine(snippet),
		})
	}
	return fs, nil
}

func semgrepSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.Critical
	case "ERROR", "HIGH":
		return finding.High
	case "WARNING", "MEDIUM":
		return finding.Medium
	default:
		return finding.Low
	}
}

// shortRuleID strips the directory prefix semgrep adds to local rule ids
// (e.g. "kscan-rules-123.python.kscan-fstring-sql" -> "kscan-fstring-sql").
// Registry rule ids are kept as they are.
func shortRuleID(id string) string {
	last := id[strings.LastIndex(id, ".")+1:]
	if strings.HasPrefix(last, "kscan-") {
		return last
	}
	return id
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}
