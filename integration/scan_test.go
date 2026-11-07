//go:build integration

// Package integration runs the real scanners on test-fixtures/ and checks
// that each one catches the issue planted for it.
//
//	KSCAN_BIN      command to run (default ../bin/kscan); scripts/kscan-docker runs the image
//	KSCAN_REQUIRE  scanners that must succeed (default gitleaks,semgrep,trivy,osv-scanner,bandit)
//	KSCAN_OFFLINE  set to 1 to skip semgrep registry rules everywhere
package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fixtureSecret is the marker shared by every fake secret in test-fixtures.
// It must never appear in any output.
const fixtureSecret = "kscanfixture-"

type finding struct {
	Tool     string `json:"tool"`
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	CVE      string `json:"cve"`
	New      bool   `json:"new"`
}

type summary struct {
	Gate struct {
		Code     int `json:"code"`
		Blocking int `json:"blocking"`
	} `json:"gate"`
	Scanners []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"scanners"`
	Findings []finding `json:"findings"`
}

func (s summary) status(name string) string {
	for _, sc := range s.Scanners {
		if sc.Name == name {
			return sc.Status
		}
	}
	return ""
}

func (f finding) from(tool string) bool { return slices.Contains(strings.Split(f.Tool, ","), tool) }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func kscanBin(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(env("KSCAN_BIN", "../bin/kscan"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("%s not found; run make build first", bin)
	}
	return bin
}

// workspace copies test-fixtures into a temp dir. kscan runs inside it with
// relative paths, so the docker wrapper only needs to mount that one dir.
func workspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	if err := os.CopyFS(filepath.Join(ws, "repo"), os.DirFS("../test-fixtures")); err != nil {
		t.Fatal(err)
	}
	return ws
}

// kscan runs a scan in ws and returns the exit code, combined output and
// the parsed JSON summary from ws/<out>/kscan.json.
func kscan(t *testing.T, ws, out string, args ...string) (int, string, summary) {
	t.Helper()
	full := append([]string{"scan", "repo", "--out", out, "--format", "terminal,json,sarif,html,markdown"}, args...)
	if os.Getenv("KSCAN_OFFLINE") == "1" && !slices.Contains(args, "--offline") {
		full = append(full, "--offline")
	}
	cmd := exec.Command(kscanBin(t), full...)
	cmd.Dir = ws
	output, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var s summary
	data, err := os.ReadFile(filepath.Join(ws, out, "kscan.json"))
	if err != nil {
		t.Fatalf("no JSON summary (exit %d):\n%s", code, output)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return code, string(output), s
}

// assertNoSecret fails if the fixture secret leaked into output or any report.
func assertNoSecret(t *testing.T, ws, output string) {
	t.Helper()
	if strings.Contains(output, fixtureSecret) {
		t.Error("secret value printed to the console")
	}
	filepath.WalkDir(ws, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, filepath.Join(ws, "repo")+string(filepath.Separator)) {
			return err
		}
		if data, _ := os.ReadFile(p); strings.Contains(string(data), fixtureSecret) {
			t.Errorf("secret value written to %s", p)
		}
		return nil
	})
}

func TestEachScannerCatchesItsIssue(t *testing.T) {
	ws := workspace(t)
	code, output, s := kscan(t, ws, "out")
	assertNoSecret(t, ws, output)
	if code != 1 {
		t.Errorf("exit = %d, want 1 (fixture has new high findings)\n%s", code, output)
	}

	required := strings.Split(env("KSCAN_REQUIRE", "gitleaks,semgrep,trivy,osv-scanner,bandit"), ",")
	for _, name := range required {
		if st := s.status(name); st != "ok" {
			t.Errorf("required scanner %s: status %q", name, st)
		}
	}

	checks := []struct {
		scanner, what string
		match         func(finding) bool
	}{
		{"gitleaks", "hardcoded secret in .env.test (high)", func(f finding) bool {
			return f.Category == "secret" && f.File == ".env.test" && f.Severity == "high"
		}},
		{"gitleaks", "example secret in docs demoted to info", func(f finding) bool {
			return f.Category == "secret" && f.File == "docs/API.md" && f.Severity == "info"
		}},
		{"semgrep", "SQL injection (kscan-fstring-sql)", func(f finding) bool { return f.RuleID == "kscan-fstring-sql" }},
		{"semgrep", "unsafe pickle load (kscan-unsafe-deserialization)", func(f finding) bool { return f.RuleID == "kscan-unsafe-deserialization" }},
		{"trivy", "vulnerable dependency in requirements.txt", func(f finding) bool {
			return f.Category == "dependency" && f.File == "requirements.txt"
		}},
		{"trivy", "Dockerfile misconfiguration", func(f finding) bool { return f.Category == "misconfig" && f.File == "Dockerfile" }},
		{"osv-scanner", "vulnerable dependency in requirements.txt", func(f finding) bool {
			return f.Category == "dependency" && f.File == "requirements.txt"
		}},
		{"bandit", "pickle use (B301)", func(f finding) bool { return f.RuleID == "B301-blacklist" }},
		{"gosec", "SQL string formatting (G201/G701)", func(f finding) bool { return f.RuleID == "G201" || f.RuleID == "G701" }},
		{"govulncheck", "called vulnerable x/text (CVE-2021-38561)", func(f finding) bool { return f.CVE == "CVE-2021-38561" }},
	}
	for _, c := range checks {
		if s.status(c.scanner) != "ok" {
			t.Logf("skip %s check (%s): scanner %s", c.scanner, c.what, s.status(c.scanner))
			continue
		}
		found := slices.ContainsFunc(s.Findings, func(f finding) bool { return f.from(c.scanner) && c.match(f) })
		if !found {
			t.Errorf("%s did not report: %s", c.scanner, c.what)
		}
	}
}

func TestBaselineOnlyFailsOnNewFindings(t *testing.T) {
	ws := workspace(t)
	code, output, _ := kscan(t, ws, "out1", "--offline", "--write-baseline", "baseline.json")
	if code != 0 {
		t.Fatalf("writing a baseline should pass, got exit %d\n%s", code, output)
	}
	code, output, s := kscan(t, ws, "out2", "--offline", "--baseline", "baseline.json")
	if code != 0 || slices.ContainsFunc(s.Findings, func(f finding) bool { return f.New }) {
		t.Fatalf("rescan against its own baseline: exit %d, want 0 and no new findings\n%s", code, output)
	}

	// A new SQL injection is new and blocks; everything else stays baselined.
	sqli := "def lookup(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
	if err := os.WriteFile(filepath.Join(ws, "repo", "app", "lookup.py"), []byte(sqli), 0o644); err != nil {
		t.Fatal(err)
	}
	code, output, s = kscan(t, ws, "out3", "--offline", "--baseline", "baseline.json")
	if code != 1 {
		t.Fatalf("new SQL injection: exit %d, want 1\n%s", code, output)
	}
	for _, f := range s.Findings {
		if f.New && f.File != "app/lookup.py" {
			t.Errorf("only app/lookup.py should be new, got %+v", f)
		}
	}
}

func TestScannerErrorExitsTwo(t *testing.T) {
	ws := workspace(t)
	code, output, s := kscan(t, ws, "out", "--only", "semgrep,gitleaks", "--timeout", "1ms", "--fail-on", "none")
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, output)
	}
	if s.status("semgrep") != "error" {
		t.Errorf("semgrep status = %q, want error", s.status("semgrep"))
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=kscan", "GIT_AUTHOR_EMAIL=kscan@example.com",
		"GIT_COMMITTER_NAME=kscan", "GIT_COMMITTER_EMAIL=kscan@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestDiffModeScansOnlyThePullRequest(t *testing.T) {
	ws := workspace(t)
	repo := filepath.Join(ws, "repo")
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "base")
	git(t, repo, "checkout", "-qb", "feature")
	// A secret added and removed again inside the PR still counts.
	os.WriteFile(filepath.Join(repo, "app", "local.py"), []byte("payment_api_key = \"kscanfixture-Lm2Wx8Tn5Rv3Hd7Pb9Zq4\"\n"), 0o644)
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "add key")
	os.WriteFile(filepath.Join(repo, "app", "local.py"), []byte("payment_api_key = None\n"), 0o644)
	git(t, repo, "commit", "-qam", "remove key")

	code, output, s := kscan(t, ws, "out", "--offline", "--changed-since", "main", "--only", "gitleaks,semgrep,bandit")
	assertNoSecret(t, ws, output)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, output)
	}
	var secret bool
	for _, f := range s.Findings {
		if f.Category == "secret" && f.File == "app/local.py" {
			secret = true
		}
		if f.File != "app/local.py" {
			t.Errorf("diff mode reported an unchanged file: %+v", f)
		}
	}
	if !secret {
		t.Errorf("secret from the PR's history not found\n%s", output)
	}
}
