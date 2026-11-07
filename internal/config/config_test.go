package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kscan/internal/finding"
)

func load(t *testing.T, yml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if sev, ok := cfg.Threshold(); !ok || sev != finding.High {
		t.Errorf("default fail_on = %v %v, want high", sev, ok)
	}
	if cfg.Min() != finding.Info || len(cfg.SecretDemotePaths) == 0 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadFull(t *testing.T) {
	cfg, err := load(t, `
scanners:
  disable: [bandit]
fail_on: none
ignore_paths: ["evals/**"]
suppress:
  - rule: B324
    path: "app/**"
    reason: cache key
min_severity: low
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Threshold(); ok {
		t.Error("fail_on none should disable the threshold")
	}
	if cfg.Min() != finding.Low || cfg.Scanners.Disable[0] != "bandit" || len(cfg.Suppress) != 1 {
		t.Errorf("unexpected config: %+v", cfg)
	}
	if err := cfg.SetFailOn("medium"); err != nil {
		t.Fatal(err)
	}
	if sev, _ := cfg.Threshold(); sev != finding.Medium {
		t.Errorf("SetFailOn: got %v", sev)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"min_severity: urgent\n":            "min_severity",
		"fail_on: sometimes\n":              "fail_on",
		"allow: []\n":                       "field allow not found",
		"suppress:\n  - fingerprint: abc\n": "reason is required",
		"suppress:\n  - reason: x\n":        "set fingerprint",
		"suppress:\n  - fingerprint: a\n    rule: r\n    reason: x\n": "cannot be combined",
		"scanners:\n  enable: [semgrep]\n  disable: [trivy]\n":        "either enable or disable",
		"ignore_paths: [\"[\"]\n":                                     "invalid glob",
	}
	for yml, want := range cases {
		_, err := load(t, yml)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", yml, err, want)
		}
	}
}

func TestSuppressMatches(t *testing.T) {
	f := finding.Finding{RuleID: "trivy-x", CVE: "CVE-1", File: "app/a/b.py", Fingerprint: "ff"}
	cases := []struct {
		s    Suppress
		want bool
	}{
		{Suppress{Fingerprint: "ff"}, true},
		{Suppress{Fingerprint: "ee"}, false},
		{Suppress{Rule: "CVE-1"}, true},
		{Suppress{Rule: "trivy-x", Path: "app/**"}, true},
		{Suppress{Rule: "trivy-x", Path: "lib/**"}, false},
		{Suppress{Path: "app/a/*.py"}, true},
		{Suppress{Rule: "other"}, false},
	}
	for _, c := range cases {
		if got := c.s.Matches(f); got != c.want {
			t.Errorf("%+v: got %v, want %v", c.s, got, c.want)
		}
	}
}
