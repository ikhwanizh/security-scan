// Package baseline records known findings so that only new ones fail a scan.
package baseline

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"

	"kscan/internal/finding"
)

// DefaultFile is the conventional name, committed at the scanned repo's root.
const DefaultFile = ".security-baseline.json"

const version = 1

// Entry identifies one accepted finding. It holds no snippet or message, so
// the file is safe to commit.
type Entry struct {
	Fingerprint string           `json:"fingerprint"`
	Rule        string           `json:"rule"`
	File        string           `json:"file"`
	Severity    finding.Severity `json:"severity"`
}

type File struct {
	Version  int       `json:"version"`
	Created  time.Time `json:"created"`
	Findings []Entry   `json:"findings"`
}

// Write saves fs as the new baseline, sorted for stable diffs.
func Write(path string, fs []finding.Finding, now time.Time) error {
	b := File{Version: version, Created: now.UTC().Truncate(time.Second), Findings: []Entry{}}
	for _, f := range fs {
		rule := f.RuleID
		if rule == "" {
			rule = f.CVE
		}
		b.Findings = append(b.Findings, Entry{Fingerprint: f.Fingerprint, Rule: rule, File: f.File, Severity: f.Severity})
	}
	slices.SortFunc(b.Findings, func(x, y Entry) int {
		return cmp.Or(cmp.Compare(x.File, y.File), cmp.Compare(x.Rule, y.Rule), cmp.Compare(x.Fingerprint, y.Fingerprint))
	})
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Load returns the set of baselined fingerprints.
func Load(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b File
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Version != version {
		return nil, fmt.Errorf("%s: unsupported baseline version %d", path, b.Version)
	}
	known := make(map[string]bool, len(b.Findings))
	for _, e := range b.Findings {
		known[e.Fingerprint] = true
	}
	return known, nil
}

// Mark sets New on every finding whose fingerprint is not in known.
func Mark(fs []finding.Finding, known map[string]bool) {
	for i := range fs {
		fs[i].New = !known[fs[i].Fingerprint]
	}
}
