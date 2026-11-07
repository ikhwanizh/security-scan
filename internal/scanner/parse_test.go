package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kscan/internal/finding"
)

// Golden outputs in testdata/ were produced by running each tool on
// test-fixtures/, with the absolute fixture path rewritten to /repo.
func golden(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func count(fs []finding.Finding, pred func(finding.Finding) bool) int {
	n := 0
	for _, f := range fs {
		if pred(f) {
			n++
		}
	}
	return n
}

func TestParseGitleaks(t *testing.T) {
	fs, err := parseGitleaks(golden(t, "gitleaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3", len(fs))
	}
	for _, f := range fs {
		if f.Category != finding.Secret || f.Severity != finding.High || f.Line == 0 || f.Snippet != "" {
			t.Errorf("unexpected secret finding: %+v", f)
		}
	}
	if count(fs, func(f finding.Finding) bool { return f.File == ".env.test" }) != 1 {
		t.Error("expected one secret in .env.test")
	}
}

func TestParseSemgrep(t *testing.T) {
	fs, err := parseSemgrep(golden(t, "semgrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"kscan-fstring-sql":            4,
		"kscan-sql-startswith-select":  3,
		"kscan-ssrf-unvalidated-host":  2,
		"kscan-unsafe-deserialization": 4,
		"kscan-go-sql-sprintf":         1,
	}
	// Semgrep can report the same location twice when several pattern-either
	// branches match; the fingerprint dedupe collapses those, so count locations.
	got := map[string]int{}
	seen := map[string]bool{}
	for _, f := range fs {
		loc := fmt.Sprintf("%s:%s:%d", f.RuleID, f.File, f.Line)
		if !seen[loc] {
			seen[loc] = true
			got[f.RuleID]++
		}
		if f.Snippet == "requires login" {
			t.Errorf("placeholder snippet leaked through: %+v", f)
		}
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s: got %d findings, want %d", id, got[id], n)
		}
	}
	if fs[0].Severity == finding.Info {
		t.Error("semgrep severities should never map to info")
	}
}

func TestParseTrivy(t *testing.T) {
	fs, err := parseTrivy(golden(t, "trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	deps := count(fs, func(f finding.Finding) bool {
		return f.Category == finding.Dependency && f.Package != "" && f.InstalledVersion != "" && f.CVE != ""
	})
	misconf := count(fs, func(f finding.Finding) bool { return f.Category == finding.Misconfig && f.File == "Dockerfile" })
	if deps == 0 || misconf == 0 {
		t.Fatalf("deps=%d misconfig=%d, want both > 0: %+v", deps, misconf, fs)
	}
}

func TestParseGosec(t *testing.T) {
	fs, err := parseGosec(golden(t, "gosec.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 7 {
		t.Fatalf("got %d, want 7", len(fs))
	}
	if fs[0].RuleID != "G701" || fs[0].Severity != finding.High || fs[0].Line != 15 {
		t.Errorf("unexpected first finding: %+v", fs[0])
	}
}

func TestParseBandit(t *testing.T) {
	fs, err := parseBandit(golden(t, "bandit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("no bandit findings")
	}
	if count(fs, func(f finding.Finding) bool { return f.RuleID == "B301-blacklist" }) == 0 {
		t.Errorf("expected pickle finding B301, got %+v", fs)
	}
}

func TestParseGovulncheck(t *testing.T) {
	fs, err := parseGovulncheck(golden(t, "govulncheck.json"), "gosvc/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	// One finding per OSV+module, severity from the deepest trace level.
	want := map[string]finding.Severity{
		"GO-2021-0113": finding.High,   // language.Parse is called
		"GO-2022-1059": finding.Medium, // package imported only
		"GO-2026-5970": finding.Low,    // module only
		"GO-2026-6629": finding.Low,
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	for _, f := range fs {
		if sev, ok := want[f.RuleID]; !ok || f.Severity != sev {
			t.Errorf("%s: severity %v, want %v", f.RuleID, f.Severity, sev)
		}
		if f.File != "gosvc/go.mod" || f.Package != "golang.org/x/text" || f.InstalledVersion != "v0.3.5" {
			t.Errorf("unexpected location/package: %+v", f)
		}
	}
	if fs[0].CVE != "CVE-2021-38561" {
		t.Errorf("CVE alias not used: %q", fs[0].CVE)
	}
}

func TestShortRuleID(t *testing.T) {
	cases := map[string]string{
		"kscan-rules-123.python.kscan-fstring-sql":                 "kscan-fstring-sql",
		"python.lang.security.audit.formatted-sql-query":           "python.lang.security.audit.formatted-sql-query",
		"go.lang.security.injection.tainted-sql-string.tainted-sq": "go.lang.security.injection.tainted-sql-string.tainted-sq",
	}
	for in, want := range cases {
		if got := shortRuleID(in); got != want {
			t.Errorf("shortRuleID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTargets(t *testing.T) {
	full, err := targets(Options{}, nil)
	if err != nil || len(full) != 1 || full[0] != "." {
		t.Fatalf("full scan targets = %v, %v", full, err)
	}
	opts := Options{BaseRef: "main", ChangedFiles: []string{"app/db.py", "README.md", "vendor/x/y.py", "web/node_modules/a.js"}}
	py, err := targets(opts, func(p string) bool { return filepath.Ext(p) == ".py" })
	if err != nil || len(py) != 1 || py[0] != "app/db.py" {
		t.Errorf("diff targets = %v, %v", py, err)
	}
	if _, err := targets(opts, func(p string) bool { return filepath.Ext(p) == ".go" }); err != ErrNoTargets {
		t.Errorf("want ErrNoTargets, got %v", err)
	}
}

func TestParseOSV(t *testing.T) {
	fs, err := parseOSV(golden(t, "osv-scanner.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("no osv findings")
	}
	var text *finding.Finding
	for i, f := range fs {
		if f.Category != finding.Dependency || f.Package == "" || f.InstalledVersion == "" || f.CVE == "" || f.CVE != f.RuleID {
			t.Errorf("incomplete dependency finding: %+v", f)
		}
		if f.Package == "golang.org/x/text" && f.CVE == "CVE-2021-38561" {
			text = &fs[i]
		}
	}
	if text == nil {
		t.Fatal("GO-2021-0113 should be reported under its CVE alias")
	}
	if text.Severity != finding.High || text.FixedVersion != "0.3.7" || !strings.Contains(text.Message, "called") {
		t.Errorf("unexpected x/text finding: %+v", *text)
	}
	// The same advisory from govulncheck (v-prefixed version) must merge with it.
	gv := finding.Finding{Category: finding.Dependency, Package: "golang.org/x/text", InstalledVersion: "v0.3.5", CVE: "CVE-2021-38561"}
	if gv.ComputeFingerprint() != text.ComputeFingerprint() {
		t.Error("osv-scanner and govulncheck findings should share a fingerprint")
	}
}

func TestCVSSSeverity(t *testing.T) {
	cases := map[string]finding.Severity{"9.8": finding.Critical, "7.0": finding.High, "5.3": finding.Medium, "2.1": finding.Low, "0": finding.Info, "": finding.Medium}
	for in, want := range cases {
		if got := cvssSeverity(in); got != want {
			t.Errorf("cvssSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}
