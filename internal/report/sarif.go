package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"kscan/internal/finding"
)

// Minimal SARIF 2.1.0 model: only the fields kscan fills and GitHub Code
// Scanning reads.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	BaselineState       string            `json:"baselineState,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

var toolURIs = map[string]string{
	"gitleaks":    "https://github.com/gitleaks/gitleaks",
	"semgrep":     "https://semgrep.dev",
	"trivy":       "https://trivy.dev",
	"osv-scanner": "https://google.github.io/osv-scanner",
	"gosec":       "https://github.com/securego/gosec",
	"bandit":      "https://bandit.readthedocs.io",
	"govulncheck": "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
}

func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the CVSS-like score GitHub uses to label alerts.
func securitySeverity(s finding.Severity) string {
	return [...]string{"0.0", "3.0", "5.5", "8.0", "9.5"}[s]
}

func sarifMessage(f finding.Finding) string {
	if f.Category == finding.Dependency {
		fix := f.FixedVersion
		if fix == "" {
			fix = "none available"
		}
		return fmt.Sprintf("%s %s: %s (%s). Fixed in: %s", f.Package, f.InstalledVersion, f.Message, f.CVE, fix)
	}
	return f.Message
}

// SARIF writes one run per tool. Findings merged from several tools are
// attributed to the first tool that reported them.
func SARIF(w io.Writer, d Data) error {
	runs := map[string]*sarifRun{}
	var order []string
	seenRule := map[string]map[string]bool{}
	for _, f := range d.Findings {
		tool := primaryTool(f.Tool)
		run, ok := runs[tool]
		if !ok {
			run = &sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: tool, InformationURI: toolURIs[tool], Rules: []sarifRule{}}}, Results: []sarifResult{}}
			runs[tool] = run
			order = append(order, tool)
			seenRule[tool] = map[string]bool{}
		}
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.CVE
		}
		if !seenRule[tool][ruleID] {
			seenRule[tool][ruleID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               ruleID,
				ShortDescription: sarifText{truncate(f.Message, 200)},
				Properties: map[string]any{
					"security-severity": securitySeverity(f.Severity),
					"tags":              []string{"security", string(f.Category)},
				},
			})
		}
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}}
		if f.Line > 0 {
			loc.Region = &sarifRegion{StartLine: f.Line}
		}
		res := sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{sarifMessage(f)},
			Locations:           []sarifLocation{{PhysicalLocation: loc}},
			PartialFingerprints: map[string]string{"kscan/v1": f.Fingerprint},
			Properties:          map[string]any{"kscan-severity": f.Severity.String(), "kscan-tools": f.Tool},
		}
		if d.Baseline != "" {
			res.BaselineState = "unchanged"
			if f.New {
				res.BaselineState = "new"
			}
		}
		run.Results = append(run.Results, res)
	}
	slices.Sort(order)
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{},
	}
	for _, t := range order {
		log.Runs = append(log.Runs, *runs[t])
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
