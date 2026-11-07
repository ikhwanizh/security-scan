// Package filter dedupes findings and applies .security-scan.yml suppressions.
package filter

import (
	"cmp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"kscan/internal/config"
	"kscan/internal/finding"
)

type Stats struct {
	Total      int `json:"total"`
	Duplicates int `json:"duplicates"`
	Ignored    int `json:"ignored"`
	Suppressed int `json:"suppressed"`
	Demoted    int `json:"demoted"`
	BelowMin   int `json:"below_min"`
}

func matchAny(globs []string, path string) bool {
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, path); ok {
			return true
		}
	}
	return false
}

func suppressed(rules []config.Suppress, f finding.Finding) bool {
	for _, s := range rules {
		if s.Matches(f) {
			return true
		}
	}
	return false
}

// Apply returns the findings to report, sorted by severity (highest first),
// then file and line.
func Apply(in []finding.Finding, cfg *config.Config) ([]finding.Finding, Stats) {
	st := Stats{Total: len(in)}
	byFP := map[string]int{}
	var out []finding.Finding
	for _, f := range in {
		if matchAny(cfg.IgnorePaths, f.File) {
			st.Ignored++
			continue
		}
		if suppressed(cfg.Suppress, f) {
			st.Suppressed++
			continue
		}
		if f.Category == finding.Secret && f.Severity > finding.Info && matchAny(cfg.SecretDemotePaths, f.File) {
			f.Severity = finding.Info
			f.Message += " [demoted: likely example value in docs/tests]"
			st.Demoted++
		}
		if i, ok := byFP[f.Fingerprint]; ok {
			st.Duplicates++
			mergeInto(&out[i], f)
			continue
		}
		byFP[f.Fingerprint] = len(out)
		out = append(out, f)
	}

	kept := out[:0]
	for _, f := range out {
		if f.Severity < cfg.Min() {
			st.BelowMin++
			continue
		}
		kept = append(kept, f)
	}
	slices.SortStableFunc(kept, func(a, b finding.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
		)
	})
	return kept, st
}

// mergeInto combines a duplicate reported by another tool: tool names are
// joined, the higher severity wins and missing dependency details are filled.
func mergeInto(dst *finding.Finding, src finding.Finding) {
	if !slices.Contains(strings.Split(dst.Tool, ","), src.Tool) {
		dst.Tool += "," + src.Tool
	}
	if src.Severity > dst.Severity {
		dst.Severity = src.Severity
	}
	if dst.FixedVersion == "" {
		dst.FixedVersion = src.FixedVersion
	}
}
