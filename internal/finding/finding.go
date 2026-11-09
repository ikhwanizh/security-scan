// Package finding defines the normalized result model shared by all scanners.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	sev, err := ParseSeverity(v)
	*s = sev
	return err
}

// ParseSeverity accepts common severity spellings from different tools
// (CRITICAL, high, ERROR, WARNING, MODERATE, ...).
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return Critical, nil
	case "high", "error":
		return High, nil
	case "medium", "moderate", "warning":
		return Medium, nil
	case "low":
		return Low, nil
	case "info", "informational", "note", "unknown", "":
		return Info, nil
	}
	return Info, fmt.Errorf("unknown severity %q", v)
}

// Category groups findings by kind of problem.
type Category string

const (
	Secret     Category = "secret"
	SAST       Category = "sast"
	Dependency Category = "dependency"
	Misconfig  Category = "misconfig"
)

type Finding struct {
	Tool     string   `json:"tool"`
	RuleID   string   `json:"rule_id"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Message  string   `json:"message"`
	// Snippet is the offending source line. Always empty for secrets.
	Snippet string `json:"snippet,omitempty"`

	// Dependency fields.
	CVE              string `json:"cve,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`

	Fingerprint string `json:"fingerprint"`
	// New is false when the fingerprint is in the baseline or the finding
	// was triaged in DefectDojo.
	New bool `json:"new"`
	// Triage is the DefectDojo decision (false_positive, risk_accepted,
	// out_of_scope), or empty.
	Triage string `json:"triage,omitempty"`
}

// ComputeFingerprint returns a hash that stays stable when code moves to a
// different line. Dependency findings are keyed by package and advisory so
// the same CVE reported by two tools collapses into one.
func (f *Finding) ComputeFingerprint() string {
	var key string
	if f.Category == Dependency {
		// Tools disagree on a leading "v" (Go modules), so drop it.
		version := strings.TrimPrefix(f.InstalledVersion, "v")
		key = strings.Join([]string{"dep", strings.ToLower(f.Package), version, f.CVE}, "|")
	} else {
		key = strings.Join([]string{f.Tool, f.RuleID, f.File, normalize(f.Snippet)}, "|")
		if f.Snippet == "" {
			// Without content (e.g. redacted secrets) the line is the best anchor we have.
			key += fmt.Sprintf("|%d", f.Line)
		}
	}
	sum := sha256.Sum256([]byte(key))
	f.Fingerprint = hex.EncodeToString(sum[:])[:16]
	return f.Fingerprint
}

func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
