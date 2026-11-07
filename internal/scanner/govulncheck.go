package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Govulncheck reports Go dependency vulnerabilities and whether the
// vulnerable code is actually reachable from the module.
type Govulncheck struct{}

func (Govulncheck) Name() string                 { return "govulncheck" }
func (Govulncheck) Applies(st detect.Stack) bool { return st.Has(detect.Go) }
func (Govulncheck) Available() (string, error)   { return lookPath("govulncheck") }

func (g Govulncheck) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := g.Available()
	if err != nil {
		return nil, err
	}
	var all []finding.Finding
	for _, root := range opts.Stack.Roots[detect.Go] {
		// In JSON mode govulncheck exits 0 even when it finds vulnerabilities,
		// so any non-zero exit means the scan itself failed (e.g. packages did
		// not load), even if a partial config message was printed.
		stdout, runErr := execTool(ctx, filepath.Join(repo, root), bin, "-format", "json", "./...")
		if runErr == nil && len(bytes.TrimSpace(stdout)) == 0 {
			runErr = errors.New("no output")
		}
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck in %s: %w", root, runErr)
		}
		fs, err := parseGovulncheck(bytes.NewReader(stdout), path.Join(filepath.ToSlash(root), "go.mod"))
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

type govulnMessage struct {
	OSV *struct {
		ID      string   `json:"id"`
		Summary string   `json:"summary"`
		Aliases []string `json:"aliases"`
	} `json:"osv"`
	Finding *struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding"`
}

// parseGovulncheck reads govulncheck's stream of JSON messages. One OSV can
// produce findings at module, package and symbol level; the deepest level
// decides severity: called symbol = high, imported package = medium,
// module only = low.
func parseGovulncheck(r io.Reader, gomod string) ([]finding.Finding, error) {
	type osvInfo struct {
		summary string
		cve     string
	}
	osvs := map[string]osvInfo{}
	type key struct{ osv, module string }
	best := map[key]finding.Finding{}
	var order []key

	dec := json.NewDecoder(r)
	for {
		var m govulnMessage
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse govulncheck: %w", err)
		}
		if m.OSV != nil {
			info := osvInfo{summary: m.OSV.Summary}
			for _, a := range m.OSV.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					info.cve = a
					break
				}
			}
			osvs[m.OSV.ID] = info
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		t := m.Finding.Trace[0]
		sev := finding.Low
		switch {
		case t.Function != "":
			sev = finding.High
		case t.Package != "":
			sev = finding.Medium
		}
		k := key{m.Finding.OSV, t.Module}
		prev, seen := best[k]
		if !seen {
			order = append(order, k)
		}
		if !seen || sev > prev.Severity {
			best[k] = finding.Finding{
				Tool:             "govulncheck",
				RuleID:           m.Finding.OSV,
				Category:         finding.Dependency,
				Severity:         sev,
				File:             gomod,
				Package:          t.Module,
				InstalledVersion: t.Version,
				FixedVersion:     m.Finding.FixedVersion,
			}
		}
	}

	fs := make([]finding.Finding, 0, len(order))
	for _, k := range order {
		f := best[k]
		info := osvs[f.RuleID]
		f.CVE = info.cve
		if f.CVE == "" {
			f.CVE = f.RuleID
		}
		reach := map[finding.Severity]string{
			finding.High:   "vulnerable function is called",
			finding.Medium: "vulnerable package is imported",
			finding.Low:    "module required, vulnerable code not reached",
		}[f.Severity]
		f.Message = fmt.Sprintf("%s (%s)", info.summary, reach)
		fs = append(fs, f)
	}
	return fs, nil
}
