package detect

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func touch(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetect(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "go.mod")
	touch(t, root, "services/api/requirements-dev.txt")
	touch(t, root, "web/package.json")
	touch(t, root, "node_modules/x/package.json") // skipped dir
	touch(t, root, "venv/lib/Cargo.toml")         // skipped dir
	touch(t, root, "a/b/c/d/composer.json")       // too deep

	st, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Lang{Go, Node, Python}
	if !slices.Equal(st.Languages, want) {
		t.Fatalf("languages = %v, want %v", st.Languages, want)
	}
	if got := st.Roots[Python]; !slices.Equal(got, []string{filepath.Join("services", "api")}) {
		t.Fatalf("python roots = %v", got)
	}
	if got := st.Roots[Node]; !slices.Equal(got, []string{"web"}) {
		t.Fatalf("node roots = %v", got)
	}
}
