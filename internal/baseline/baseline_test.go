package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kscan/internal/finding"
)

func TestWriteLoadMark(t *testing.T) {
	old := finding.Finding{Tool: "semgrep", RuleID: "kscan-fstring-sql", Category: finding.SAST, Severity: finding.High, File: "app/db.py", Line: 7, Snippet: `q = f"select {x}"`}
	dep := finding.Finding{Tool: "trivy", Category: finding.Dependency, Severity: finding.Critical, File: "requirements.txt", Package: "pillow", InstalledVersion: "11.2.1", CVE: "CVE-1"}
	old.ComputeFingerprint()
	dep.ComputeFingerprint()

	p := filepath.Join(t.TempDir(), DefaultFile)
	if err := Write(p, []finding.Finding{old, dep}, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), "select") {
		t.Errorf("baseline must not contain snippets:\n%s", data)
	}
	known, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}

	// The same code moved 30 lines down is still the same finding.
	moved := old
	moved.Line = 37
	moved.ComputeFingerprint()
	fresh := finding.Finding{Tool: "semgrep", RuleID: "kscan-fstring-sql", Category: finding.SAST, Severity: finding.High, File: "app/db.py", Line: 9, Snippet: `q = f"delete {x}"`}
	fresh.ComputeFingerprint()

	fs := []finding.Finding{moved, dep, fresh}
	Mark(fs, known)
	if fs[0].New || fs[1].New || !fs[2].New {
		t.Errorf("new flags = %v %v %v, want false false true", fs[0].New, fs[1].New, fs[2].New)
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), DefaultFile)
	os.WriteFile(p, []byte(`{"version": 9, "findings": []}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error")
	}
}
