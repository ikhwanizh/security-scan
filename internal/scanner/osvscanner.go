package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// OSVScanner checks dependency manifests and lockfiles against the OSV
// database. It overlaps with trivy on purpose: the databases differ, and
// duplicates collapse through the dependency fingerprint.
type OSVScanner struct{}

func (OSVScanner) Name() string               { return "osv-scanner" }
func (OSVScanner) Applies(detect.Stack) bool  { return true }
func (OSVScanner) Available() (string, error) { return lookPath("osv-scanner") }

func (o OSVScanner) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := o.Available()
	if err != nil {
		return nil, err
	}
	// Exit 1 means vulnerabilities were found and 128 that no packages were
	// found; both still produce valid JSON on stdout.
	stdout, runErr := execTool(ctx, repo, bin, "scan", "source", "-r", "--format", "json", ".")
	if len(bytes.TrimSpace(stdout)) == 0 {
		if runErr != nil {
			return nil, runErr
		}
		return nil, fmt.Errorf("osv-scanner produced no output")
	}
	fs, err := parseOSV(bytes.NewReader(stdout))
	if err != nil {
		return nil, err
	}
	for i := range fs {
		fs[i].File = relPath(repo, fs[i].File)
	}
	return finalize(repo, fs), nil
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
			// Groups merge one advisory published under several IDs.
			Groups []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
				Analysis    map[string]struct {
					Called bool `json:"called"`
				} `json:"experimental_analysis"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

func parseOSV(r io.Reader) ([]finding.Finding, error) {
	var o osvOutput
	if err := json.NewDecoder(r).Decode(&o); err != nil {
		return nil, fmt.Errorf("parse osv-scanner: %w", err)
	}
	var fs []finding.Finding
	for _, res := range o.Results {
		for _, p := range res.Packages {
			byID := map[string]osvVuln{}
			for _, v := range p.Vulnerabilities {
				byID[v.ID] = v
			}
			for _, g := range p.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				id := advisoryID(g.IDs, g.Aliases)
				v := byID[g.IDs[0]]
				msg := strings.TrimSpace(v.Summary)
				if msg == "" {
					msg = firstLine(v.Details)
				}
				if msg == "" {
					msg = g.IDs[0]
				}
				if a, ok := g.Analysis[g.IDs[0]]; ok {
					if a.Called {
						msg += " (vulnerable code is called)"
					} else {
						msg += " (vulnerable code not called)"
					}
				}
				fs = append(fs, finding.Finding{
					Tool:             "osv-scanner",
					RuleID:           id,
					Category:         finding.Dependency,
					Severity:         cvssSeverity(g.MaxSeverity),
					File:             res.Source.Path,
					Message:          msg,
					CVE:              id,
					Package:          p.Package.Name,
					InstalledVersion: p.Package.Version,
					FixedVersion:     fixedVersions(v, p.Package.Name),
				})
			}
		}
	}
	return fs, nil
}

// advisoryID prefers a CVE, then a GHSA ID, so the finding merges with
// trivy's, which uses the same order.
func advisoryID(ids, aliases []string) string {
	all := slices.Concat(ids, aliases)
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		for _, a := range all {
			if strings.HasPrefix(a, prefix) {
				return a
			}
		}
	}
	return ids[0]
}

// cvssSeverity maps a CVSS base score to kscan's levels. An advisory without
// a score is still a known vulnerability, so it counts as medium.
func cvssSeverity(score string) finding.Severity {
	s, err := strconv.ParseFloat(score, 64)
	switch {
	case err != nil:
		return finding.Medium
	case s >= 9:
		return finding.Critical
	case s >= 7:
		return finding.High
	case s >= 4:
		return finding.Medium
	case s > 0:
		return finding.Low
	}
	return finding.Info
}

// fixedVersions lists the fix versions of the package's affected ranges.
// OSV ranges can cover several release branches, so there may be more than one.
func fixedVersions(v osvVuln, pkg string) string {
	var fixed []string
	for _, a := range v.Affected {
		if !strings.EqualFold(a.Package.Name, pkg) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !slices.Contains(fixed, e.Fixed) {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	return strings.Join(fixed, ", ")
}
