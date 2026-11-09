package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"kscan/internal/finding"
)

// DefectDojo "Generic Findings Import" JSON. Only fields the parser accepts
// are emitted; it rejects unknown keys.
type ddReport struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Version     string      `json:"version,omitempty"`
	Description string      `json:"description,omitempty"`
	StaticTool  bool        `json:"static_tool"`
	DynamicTool bool        `json:"dynamic_tool"`
	Findings    []ddFinding `json:"findings"`
}

type ddFinding struct {
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Date             string   `json:"date"`
	FilePath         string   `json:"file_path,omitempty"`
	Line             int      `json:"line,omitempty"`
	ComponentName    string   `json:"component_name,omitempty"`
	ComponentVersion string   `json:"component_version,omitempty"`
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	Mitigation       string   `json:"mitigation,omitempty"`
	FixAvailable     bool     `json:"fix_available"`
	FixVersion       string   `json:"fix_version,omitempty"`
	References       string   `json:"references,omitempty"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	VulnIDFromTool   string   `json:"vuln_id_from_tool,omitempty"`
	StaticFinding    bool     `json:"static_finding"`
	DynamicFinding   bool     `json:"dynamic_finding"`
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	Tags             []string `json:"tags"`
}

// DefectDojo writes findings for DefectDojo's reimport-scan API. The kscan
// fingerprint becomes unique_id_from_tool, so DefectDojo can track a finding
// across scans when its dedupe algorithm for test type "kscan" is
// unique_id_from_tool. Secret findings carry no snippet, so no secret values
// are sent.
//
// The description holds only stable text (no new/existing state, no date),
// because DefectDojo's fallback hash_code includes it.
func DefectDojo(w io.Writer, d Data) error {
	r := ddReport{
		Name: "kscan", Type: "kscan", Version: d.Version, StaticTool: true,
		Description: "kscan: gitleaks, semgrep, trivy, osv-scanner, bandit, gosec, govulncheck",
		Findings:    []ddFinding{},
	}
	date := d.StartedAt.UTC().Format("2006-01-02")
	for _, f := range d.Findings {
		r.Findings = append(r.Findings, ddFindingFrom(f, date))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func ddFindingFrom(f finding.Finding, date string) ddFinding {
	tools := strings.Split(f.Tool, ",")
	out := ddFinding{
		Severity: ddSeverity(f.Severity), Date: date,
		FilePath: f.File, Line: f.Line,
		UniqueIDFromTool: f.Fingerprint, VulnIDFromTool: f.RuleID,
		StaticFinding: true, Active: true,
		Tags: append([]string{string(f.Category)}, tools...),
	}
	var refs []string
	for _, t := range tools {
		if u := toolURIs[t]; u != "" {
			refs = append(refs, u)
		}
	}
	out.References = strings.Join(refs, "\n")

	var desc strings.Builder
	desc.WriteString(f.Message + "\n\n")
	fmt.Fprintf(&desc, "- Tool: %s\n- Rule: %s\n- Category: %s\n- kscan fingerprint: %s\n", f.Tool, f.RuleID, f.Category, f.Fingerprint)

	if f.Category == finding.Dependency {
		out.Title = truncate(fmt.Sprintf("%s %s: %s", f.Package, f.InstalledVersion, f.CVE), 500)
		out.ComponentName, out.ComponentVersion = f.Package, f.InstalledVersion
		if f.CVE != "" {
			out.VulnerabilityIDs = []string{f.CVE}
			if out.VulnIDFromTool == "" {
				out.VulnIDFromTool = f.CVE
			}
		}
		if f.FixedVersion != "" {
			out.FixAvailable, out.FixVersion = true, f.FixedVersion
			out.Mitigation = fmt.Sprintf("Upgrade %s to %s.", f.Package, f.FixedVersion)
		}
	} else {
		out.Title = truncate(fmt.Sprintf("%s: %s", f.RuleID, firstLine(f.Message)), 500)
	}
	if f.Snippet != "" {
		fmt.Fprintf(&desc, "\n```\n%s\n```\n", f.Snippet)
	}
	out.Description = desc.String()
	return out
}

func ddSeverity(s finding.Severity) string {
	return [...]string{"Info", "Low", "Medium", "High", "Critical"}[s]
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
