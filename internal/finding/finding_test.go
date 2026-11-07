package finding

import "testing"

func TestFingerprintIgnoresLineMove(t *testing.T) {
	a := Finding{Tool: "semgrep", RuleID: "r1", File: "a.py", Line: 10, Snippet: "x = pickle.load(f)"}
	b := a
	b.Line = 42
	b.Snippet = "    x  =  pickle.load(f)"
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Fatal("fingerprint changed when only line/whitespace changed")
	}
}

func TestFingerprintSnippetlessUsesLine(t *testing.T) {
	a := Finding{Tool: "gitleaks", RuleID: "generic-api-key", File: ".env", Line: 1, Category: Secret}
	b := a
	b.Line = 2
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Fatal("two secrets on different lines must not collapse")
	}
}

func TestFingerprintDependencyAcrossTools(t *testing.T) {
	a := Finding{Tool: "trivy", Category: Dependency, Package: "PyJWT", InstalledVersion: "2.10.1", CVE: "CVE-1"}
	b := Finding{Tool: "pip-audit", Category: Dependency, Package: "pyjwt", InstalledVersion: "2.10.1", CVE: "CVE-1", File: "other"}
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Fatal("same CVE from two tools should share a fingerprint")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{"CRITICAL": Critical, "ERROR": High, "WARNING": Medium, "moderate": Medium, "LOW": Low, "": Info}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("expected error for unknown severity")
	}
}

func TestFingerprintDependencyIgnoresVPrefix(t *testing.T) {
	a := Finding{Tool: "govulncheck", Category: Dependency, Package: "golang.org/x/text", InstalledVersion: "v0.3.5", CVE: "CVE-2021-38561"}
	b := Finding{Tool: "osv-scanner", Category: Dependency, Package: "golang.org/x/text", InstalledVersion: "0.3.5", CVE: "CVE-2021-38561"}
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Error("v-prefixed and plain versions should share a fingerprint")
	}
}
