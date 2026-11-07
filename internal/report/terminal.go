package report

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"kscan/internal/finding"
	"kscan/internal/scanner"
)

type palette struct{ reset, bold, dim, red, yellow, blue, magenta string }

func colors(w io.Writer) palette {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	if st, err := f.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return palette{}
	}
	return palette{"\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[34m", "\033[35m"}
}

func (p palette) severity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return p.magenta + p.bold
	case finding.High:
		return p.red
	case finding.Medium:
		return p.yellow
	case finding.Low:
		return p.blue
	}
	return p.dim
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func location(f finding.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// Terminal prints a summary and the top findings.
func Terminal(w io.Writer, d Data, top int) {
	c := colors(w)
	fmt.Fprintf(w, "%skscan %s%s  %s  (%s)  %s\n\n", c.bold, d.Version, c.reset, d.Repo, d.Languages(), d.Duration.Round(100_000_000))

	var sev []string
	for _, sc := range d.BySeverity() {
		sev = append(sev, fmt.Sprintf("%s%s %d%s", c.severity(sc.Severity), sc.Severity, sc.Count, c.reset))
	}
	fmt.Fprintf(w, "  Severity  %s\n", strings.Join(sev, "  "))
	if d.Baseline != "" {
		fmt.Fprintf(w, "  Baseline  %d new / %d existing (%s)\n", d.NewCount(), len(d.Findings)-d.NewCount(), d.Baseline)
	}
	var tools []string
	for _, tc := range d.ByTool() {
		tools = append(tools, fmt.Sprintf("%s %d", tc.Tool, tc.Count))
	}
	if len(tools) > 0 {
		fmt.Fprintf(w, "  By tool   %s\n", strings.Join(tools, "  "))
	}
	st := d.Stats
	fmt.Fprintf(w, "  Filtered  %d raw → %d shown (%d duplicate, %d ignored path, %d suppressed, %d below min severity; %d secrets demoted)\n\n",
		st.Total, len(d.Findings), st.Duplicates, st.Ignored, st.Suppressed, st.BelowMin, st.Demoted)

	if len(d.Findings) > 0 {
		// New findings first: those are the ones that can block.
		ordered := slices.Concat(
			slices.DeleteFunc(slices.Clone(d.Findings), func(f finding.Finding) bool { return !f.New }),
			slices.DeleteFunc(slices.Clone(d.Findings), func(f finding.Finding) bool { return f.New }))
		n := min(top, len(ordered))
		fmt.Fprintf(w, "%sTop findings%s (%d of %d)\n", c.bold, c.reset, n, len(ordered))
		for _, f := range ordered[:n] {
			label := fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))
			if d.Baseline != "" && !f.New {
				label = fmt.Sprintf("%-8s", "existing")
			}
			var what string
			if f.Category == finding.Dependency {
				fix := f.FixedVersion
				if fix == "" {
					fix = "no fix yet"
				}
				what = fmt.Sprintf("%s %s → %s  %s  %s", f.Package, f.InstalledVersion, fix, f.CVE, truncate(f.Message, 60))
			} else {
				what = fmt.Sprintf("%s  %s%s%s", f.RuleID, c.dim, truncate(f.Message, 90), c.reset)
			}
			fmt.Fprintf(w, "  %s%s%s %-10s %s\n           %s\n", c.severity(f.Severity), label, c.reset, f.Category, location(f), what)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%sScanners%s\n", c.bold, c.reset)
	for _, r := range d.Scanners {
		switch r.Status {
		case scanner.StatusOK:
			fmt.Fprintf(w, "  ok     %-12s %6s  %d raw findings\n", r.Scanner, r.Duration.Round(100_000_000), len(r.Findings))
		case scanner.StatusSkipped:
			fmt.Fprintf(w, "  %sskip   %-12s %s%s\n", c.dim, r.Scanner, r.Reason, c.reset)
		case scanner.StatusError:
			fmt.Fprintf(w, "  %serror  %-12s %s%s\n", c.red, r.Scanner, truncate(r.Reason, 160), c.reset)
		}
	}
	if d.Gate.Status != "" {
		color := c.red
		if d.Gate.Status == "pass" {
			color = ""
		}
		fmt.Fprintf(w, "\n%s%s%s%s\n", c.bold, color, d.Gate.Summary(), c.reset)
	}
}
