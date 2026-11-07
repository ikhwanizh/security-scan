package gitdiff

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestChanged(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	run(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "keep.py", "a = 1\n")
	write(t, dir, "gone.py", "b = 1\n")
	write(t, dir, "edit.py", "c = 1\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "base")
	base := Head(ctx, dir)

	run(t, dir, "checkout", "-qb", "feature")
	write(t, dir, "edit.py", "c = 2\n")
	write(t, dir, "app/new file.py", "d = 1\n")
	run(t, dir, "rm", "-q", "gone.py")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "change")

	got, err := Changed(ctx, dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"app/new file.py", "edit.py"}; !slices.Equal(got, want) {
		t.Errorf("Changed = %q, want %q", got, want)
	}
	if base == "" || Head(ctx, dir) == base {
		t.Error("Head should return the current commit")
	}
	if _, err := Changed(ctx, dir, "no-such-ref"); err == nil {
		t.Error("expected error for unknown ref")
	}
	if Head(ctx, t.TempDir()) != "" {
		t.Error("Head outside a repo should be empty")
	}
}
