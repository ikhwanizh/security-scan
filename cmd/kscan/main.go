// Command kscan runs several security scanners over a repository and merges
// their results into one report.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"kscan/internal/baseline"
	"kscan/internal/config"
	"kscan/internal/detect"
	"kscan/internal/filter"
	"kscan/internal/finding"
	"kscan/internal/gate"
	"kscan/internal/gitdiff"
	"kscan/internal/report"
	"kscan/internal/scanner"
	"kscan/rules"
)

var version = "0.1.0-dev"

// exitError carries a specific exit code (e.g. --fail-on) without printing usage.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	root := &cobra.Command{
		Use:           "kscan",
		Short:         "Run security scanners on a repository and merge the results",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCmd(), doctorCmd(), rulesCmd())
	if err := root.ExecuteContext(ctx); err != nil {
		if e, ok := err.(exitError); ok {
			os.Exit(e.code)
		}
		fmt.Fprintln(os.Stderr, "kscan:", err)
		os.Exit(2)
	}
}

type scanFlags struct {
	formats    []string
	out        string
	configPath string
	failOn     string
	timeout    time.Duration
	history    bool
	offline    bool
	only, skip []string
	top        int
	baseline   string
	writeBase  string
	changed    string
}

func scanCmd() *cobra.Command {
	var fl scanFlags
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a repository (default: current directory)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo := "."
			if len(args) == 1 {
				repo = args[0]
			}
			return runScan(cmd.Context(), repo, fl)
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&fl.formats, "format", []string{"terminal", "sarif", "json", "html"}, "outputs: terminal, sarif, json, html, markdown, defectdojo")
	f.StringVar(&fl.out, "out", "kscan-report", "directory for sarif/html reports")
	f.StringVar(&fl.configPath, "config", "", "config file (default <repo>/"+config.FileName+")")
	f.StringVar(&fl.failOn, "fail-on", "", "exit 1 if a new finding is at or above this severity: none, info, low, medium, high, critical (default from config, else high)")
	f.DurationVar(&fl.timeout, "timeout", 10*time.Minute, "timeout per scanner")
	f.BoolVar(&fl.history, "history", false, "also scan git history for secrets")
	f.BoolVar(&fl.offline, "offline", false, "skip semgrep registry rules (custom rules only)")
	f.StringSliceVar(&fl.only, "only", nil, "run only these scanners")
	f.StringSliceVar(&fl.skip, "skip", nil, "skip these scanners")
	f.IntVar(&fl.top, "top", 20, "findings to print in the terminal")
	f.StringVar(&fl.baseline, "baseline", "", "baseline file; only findings not in it are new and can fail the scan (missing file = everything is new)")
	f.StringVar(&fl.changed, "changed-since", "", "diff mode for pull requests: scan only files changed since this git ref (semgrep, bandit) and only its new commits (gitleaks); dependency scanners still scan everything")
	f.StringVar(&fl.writeBase, "write-baseline", "", "save the current findings as the baseline to this file (e.g. "+baseline.DefaultFile+")")
	return cmd
}

// selectScanners applies --only/--skip, falling back to the config's
// scanners.enable/disable. Scanners named in an enable list (flag or config)
// are required: if one is missing, the scan reports a tool error.
func selectScanners(only, skip []string, cfg config.Scanners) (sel []scanner.Scanner, required map[string]bool, err error) {
	all := scanner.All()
	known := map[string]bool{}
	for _, s := range all {
		known[s.Name()] = true
	}
	for _, n := range slices.Concat(only, skip, cfg.Enable, cfg.Disable) {
		if !known[n] {
			return nil, nil, fmt.Errorf("unknown scanner %q", n)
		}
	}
	if len(only) == 0 && len(skip) == 0 {
		only, skip = cfg.Enable, cfg.Disable
	}
	required = map[string]bool{}
	for _, s := range all {
		if (len(only) > 0 && !slices.Contains(only, s.Name())) || slices.Contains(skip, s.Name()) {
			continue
		}
		sel = append(sel, s)
		required[s.Name()] = len(only) > 0
	}
	return sel, required, nil
}

func runScan(ctx context.Context, repo string, fl scanFlags) error {
	repo, err := filepath.Abs(repo)
	if err != nil {
		return err
	}
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", repo)
	}
	for _, f := range fl.formats {
		if !slices.Contains([]string{"terminal", "sarif", "json", "html", "markdown", "defectdojo"}, f) {
			return fmt.Errorf("unknown format %q", f)
		}
	}
	cfgPath := fl.configPath
	if cfgPath == "" {
		cfgPath = filepath.Join(repo, config.FileName)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if fl.failOn != "" {
		if err := cfg.SetFailOn(fl.failOn); err != nil {
			return fmt.Errorf("--fail-on: %w", err)
		}
	}
	scanners, required, err := selectScanners(fl.only, fl.skip, cfg.Scanners)
	if err != nil {
		return err
	}
	stack, err := detect.Detect(repo)
	if err != nil {
		return err
	}
	rulesDir, cleanup, err := rules.Extract()
	if err != nil {
		return fmt.Errorf("extract custom rules: %w", err)
	}
	defer cleanup()

	opts := scanner.Options{
		Stack: stack, History: fl.history, Offline: fl.offline, RulesDir: rulesDir, Required: required,
	}
	if fl.changed != "" {
		if fl.writeBase != "" {
			return errors.New("--write-baseline needs a full scan; drop --changed-since")
		}
		if opts.ChangedFiles, err = gitdiff.Changed(ctx, repo, fl.changed); err != nil {
			return fmt.Errorf("--changed-since: %w", err)
		}
		opts.BaseRef = fl.changed
		fmt.Fprintf(os.Stderr, "kscan: diff mode, %d files changed since %s\n", len(opts.ChangedFiles), fl.changed)
	}

	start := time.Now()
	fmt.Fprintf(os.Stderr, "kscan: scanning %s (%s) with %d scanners…\n", repo, report.Data{Stack: stack}.Languages(), len(scanners))
	results := scanner.RunAll(ctx, repo, scanners, opts, fl.timeout)

	var raw []finding.Finding
	for _, r := range results {
		raw = append(raw, r.Findings...)
	}
	kept, stats := filter.Apply(raw, cfg)
	baselinePath, err := applyBaseline(kept, fl.baseline)
	if err != nil {
		return err
	}
	threshold, enabled := cfg.Threshold()
	data := report.Data{
		Version: version, Repo: repo, Stack: stack, StartedAt: start,
		Duration: time.Since(start).Round(time.Millisecond), Scanners: results, Findings: kept, Stats: stats,
		Commit: gitdiff.Head(ctx, repo), Baseline: baselinePath,
	}
	if fl.writeBase != "" {
		if err := writeBaseline(fl.writeBase, &data); err != nil {
			return err
		}
	}
	data.Gate = gate.Decide(results, kept, threshold, enabled)

	var written []string
	for _, f := range fl.formats {
		switch f {
		case "terminal":
			report.Terminal(os.Stdout, data, fl.top)
		default:
			p, err := writeReport(fl.out, f, data)
			if err != nil {
				return err
			}
			written = append(written, p)
		}
	}
	if len(written) > 0 {
		fmt.Printf("\nReports: %s\n", strings.Join(written, ", "))
	}
	if data.Gate.Code != gate.Pass {
		return exitError{data.Gate.Code}
	}
	return nil
}

// applyBaseline marks findings as new or existing. A missing baseline file
// is not an error, so CI works before the first baseline is committed.
func applyBaseline(findings []finding.Finding, path string) (used string, err error) {
	known := map[string]bool{}
	if path != "" {
		known, err = baseline.Load(path)
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "kscan: baseline %s not found; every finding counts as new\n", path)
			known, path = map[string]bool{}, ""
		} else if err != nil {
			return "", err
		}
	}
	baseline.Mark(findings, known)
	return path, nil
}

// writeBaseline accepts every current finding. It refuses when a scanner
// failed, because the baseline would silently miss that scanner's findings.
func writeBaseline(path string, d *report.Data) error {
	for _, r := range d.Scanners {
		if r.Status == scanner.StatusError {
			return fmt.Errorf("not writing baseline: scanner %s failed: %s", r.Scanner, r.Reason)
		}
	}
	if err := baseline.Write(path, d.Findings, d.StartedAt); err != nil {
		return err
	}
	for i := range d.Findings {
		d.Findings[i].New = false
	}
	d.Baseline = path
	fmt.Fprintf(os.Stderr, "kscan: wrote baseline with %d findings to %s\n", len(d.Findings), path)
	return nil
}

func writeReport(dir, format string, d report.Data) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := map[string]string{"sarif": "kscan.sarif", "json": "kscan.json", "html": "kscan.html",
		"markdown": "kscan.md", "defectdojo": "kscan.defectdojo.json"}[format]
	p := filepath.Join(dir, name)
	// Reports can contain source snippets: keep them private to the user.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch format {
	case "sarif":
		err = report.SARIF(f, d)
	case "json":
		err = report.JSON(f, d)
	case "markdown":
		err = report.Markdown(f, d)
	case "defectdojo":
		err = report.DefectDojo(f, d)
	default:
		err = report.HTML(f, d)
	}
	if err != nil {
		return "", fmt.Errorf("write %s: %w", p, err)
	}
	return p, f.Close()
}

// versionArgs is how each tool prints its version.
var versionArgs = map[string][]string{
	"gitleaks":    {"version"},
	"semgrep":     {"--version"},
	"trivy":       {"--version"},
	"osv-scanner": {"--version"},
	"gosec":       {"-version"},
	"bandit":      {"--version"},
	"govulncheck": {"-version"},
}

var installHints = map[string]string{
	"gitleaks":    "brew install gitleaks",
	"semgrep":     "uv tool install semgrep",
	"trivy":       "brew install trivy",
	"osv-scanner": "brew install osv-scanner",
	"gosec":       "brew install gosec",
	"bandit":      "uv tool install bandit",
	"govulncheck": "go install golang.org/x/vuln/cmd/govulncheck@latest",
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check which scanners are installed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "SCANNER\tSTATUS\tPATH / INSTALL\tVERSION")
			missing := 0
			for _, s := range scanner.All() {
				p, err := s.Available()
				if err != nil {
					missing++
					fmt.Fprintf(w, "%s\tmissing\t%s\t\n", s.Name(), installHints[s.Name()])
					continue
				}
				fmt.Fprintf(w, "%s\tok\t%s\t%s\n", s.Name(), p, scanner.Version(cmd.Context(), p, versionArgs[s.Name()]...))
			}
			w.Flush()
			if missing > 0 {
				fmt.Printf("\n%d scanner(s) missing; kscan skips them during scans.\n", missing)
			}
			return nil
		},
	}
}

func rulesCmd() *cobra.Command {
	rc := &cobra.Command{Use: "rules", Short: "Inspect kscan's custom semgrep rules"}
	rc.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List custom rules",
		RunE: func(*cobra.Command, []string) error {
			rs, err := rules.List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tLANG\tSEVERITY\tSUMMARY")
			for _, r := range rs {
				summary, _, _ := strings.Cut(r.Message, ". ")
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, strings.Join(r.Languages, ","), r.Severity, summary)
			}
			return w.Flush()
		},
	})
	return rc
}
