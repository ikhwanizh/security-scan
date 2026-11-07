package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListAndExtract(t *testing.T) {
	rs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) < 5 {
		t.Fatalf("expected at least 5 rules, got %d", len(rs))
	}
	for _, r := range rs {
		if !strings.HasPrefix(r.ID, "kscan-") {
			t.Errorf("rule %q must start with kscan- (the semgrep adapter relies on it)", r.ID)
		}
		if r.Message == "" || r.Severity == "" {
			t.Errorf("rule %q missing message or severity", r.ID)
		}
	}

	dir, cleanup, err := Extract()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	yamls, _ := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
	if len(yamls) != len(rs) {
		t.Fatalf("extracted %d files, want %d", len(yamls), len(rs))
	}
	// Test targets must not be shipped as rules.
	if py, _ := filepath.Glob(filepath.Join(dir, "*", "*.py")); len(py) > 0 {
		t.Fatalf("test targets were extracted: %v", py)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("cleanup did not remove dir")
	}
}
