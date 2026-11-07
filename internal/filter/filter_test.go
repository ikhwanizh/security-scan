package filter

import (
	"os"
	"path/filepath"
	"testing"

	"kscan/internal/config"
	"kscan/internal/finding"
)

func fp(f finding.Finding) finding.Finding {
	f.ComputeFingerprint()
	return f
}

func TestApply(t *testing.T) {
	envSecret := fp(finding.Finding{Tool: "gitleaks", RuleID: "generic-api-key", Category: finding.Secret, Severity: finding.High, File: ".env", Line: 3})
	docSecret := fp(finding.Finding{Tool: "gitleaks", RuleID: "generic-api-key", Category: finding.Secret, Severity: finding.High, File: "docs/API.md", Line: 9})
	ignored := fp(finding.Finding{Tool: "semgrep", RuleID: "r", Category: finding.SAST, Severity: finding.High, File: "evals/x.py", Line: 1, Snippet: "a"})
	allowed := fp(finding.Finding{Tool: "bandit", RuleID: "B324", Category: finding.SAST, Severity: finding.High, File: "app/v.py", Line: 5, Snippet: "md5()"})
	ruleSup := fp(finding.Finding{Tool: "semgrep", RuleID: "kscan-ssrf-unvalidated-host", Category: finding.SAST, Severity: finding.Medium, File: "app/admin/hosts.py", Line: 7, Snippet: "connect(host)"})
	low := fp(finding.Finding{Tool: "bandit", RuleID: "B101", Category: finding.SAST, Severity: finding.Low, File: "app/a.py", Line: 2, Snippet: "assert x"})
	depTrivy := fp(finding.Finding{Tool: "trivy", Category: finding.Dependency, Severity: finding.Medium, Package: "golang.org/x/net", InstalledVersion: "v0.1.0", CVE: "CVE-9", File: "go.mod"})
	depGovuln := fp(finding.Finding{Tool: "govulncheck", Category: finding.Dependency, Severity: finding.High, Package: "golang.org/x/net", InstalledVersion: "v0.1.0", CVE: "CVE-9", FixedVersion: "v0.2.0", File: "go.mod"})

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.FileName)
	yml := "ignore_paths: [\"evals/**\"]\nmin_severity: low\nsuppress:\n  - fingerprint: " + allowed.Fingerprint + "\n    reason: checksum only\n  - rule: kscan-ssrf-unvalidated-host\n    path: app/admin/**\n    reason: admin only\n"
	if err := os.WriteFile(cfgPath, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	out, st := Apply([]finding.Finding{envSecret, docSecret, ignored, allowed, ruleSup, low, depTrivy, depGovuln}, cfg)

	want := Stats{Total: 8, Duplicates: 1, Ignored: 1, Suppressed: 2, Demoted: 1, BelowMin: 1}
	if st != want {
		t.Fatalf("stats = %+v, want %+v", st, want)
	}
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(out), out)
	}
	// Highest severity first, ties by file; the merged dependency took govulncheck's severity.
	if out[0].File != ".env" {
		t.Errorf("expected .env secret first, got %+v", out[0])
	}
	if out[1].Category != finding.Dependency || out[1].Severity != finding.High || out[1].Tool != "trivy,govulncheck" || out[1].FixedVersion != "v0.2.0" {
		t.Errorf("merged dependency wrong: %+v", out[1])
	}
	if out[2].File != "app/a.py" {
		t.Errorf("expected low finding last, got %+v", out[2])
	}
}
