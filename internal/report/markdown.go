package report

import (
	"fmt"
	"io"
	"strings"

	"kscan/internal/finding"
)

// markdownTop caps the findings table so the CI job summary stays readable.
const markdownTop = 25

func mdCell(s string) string {
	return strings.ReplaceAll(truncate(s, 120), "|", `\|`)
}

// Markdown writes a short summary for CI job pages such as
// $GITHUB_STEP_SUMMARY. It lists new findings only and no source snippets.
func Markdown(w io.Writer, d Data) error {
	var b strings.Builder
	fmt.Fprintf(&b, "### kscan: %s\n\n", d.Gate.Summary())
	if d.Commit != "" {
		fmt.Fprintf(&b, "Commit `%s`", d.Commit)
		if d.Baseline != "" {
			fmt.Fprintf(&b, ", baseline `%s`", d.Baseline)
		}
		b.WriteString("\n\n")
	}
	b.WriteString("| Severity | New | Total |\n|---|---:|---:|\n")
	for _, sc := range d.BySeverity() {
		fmt.Fprintf(&b, "| %s | %d | %d |\n", sc.Severity, sc.New, sc.Count)
	}

	var news []finding.Finding
	for _, f := range d.Findings {
		if f.New {
			news = append(news, f)
		}
	}
	if len(news) > 0 {
		n := min(markdownTop, len(news))
		fmt.Fprintf(&b, "\n#### New findings (%d of %d)\n\n| Severity | Location | Rule | Message |\n|---|---|---|---|\n", n, len(news))
		for _, f := range news[:n] {
			msg := f.Message
			if f.Category == finding.Dependency {
				msg = fmt.Sprintf("%s %s (fix: %s) %s", f.Package, f.InstalledVersion, or(f.FixedVersion, "none"), f.Message)
			}
			rule := or(f.RuleID, f.CVE)
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n", f.Severity, mdCell(location(f)), mdCell(rule), mdCell(msg))
		}
	}

	b.WriteString("\n<details><summary>Scanners</summary>\n\n| Scanner | Status | Time | Note |\n|---|---|---:|---|\n")
	for _, r := range d.Scanners {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.Scanner, r.Status, r.Duration.Round(100_000_000), mdCell(r.Reason))
	}
	b.WriteString("\n</details>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
