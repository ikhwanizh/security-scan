// Package scanner wraps external security tools and normalizes their output.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

type Options struct {
	Stack detect.Stack
	// History also scans git history for secrets.
	History bool
	// Offline skips anything that needs the network (semgrep registry rules).
	Offline bool
	// RulesDir holds the extracted custom semgrep rules.
	RulesDir string
	// Required scanners are reported as errors, not skipped, when missing.
	Required map[string]bool
	// BaseRef turns on diff mode (pull requests): file-level scanners only
	// look at ChangedFiles, and gitleaks only at commits after BaseRef.
	BaseRef      string
	ChangedFiles []string
}

// ErrNoTargets means diff mode found no changed files the scanner handles.
var ErrNoTargets = errors.New("no changed files to scan")

// targets returns what a file-level scanner should scan: "." normally, or the
// changed files accepted by keep in diff mode. Files under SkipDirs are dropped.
func targets(opts Options, keep func(path string) bool) ([]string, error) {
	if opts.BaseRef == "" {
		return []string{"."}, nil
	}
	var out []string
	for _, f := range opts.ChangedFiles {
		if !inSkipDir(f) && keep(f) {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoTargets
	}
	return out, nil
}

func inSkipDir(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if slices.Contains(detect.SkipDirs, part) {
			return true
		}
	}
	return false
}

type Scanner interface {
	Name() string
	Applies(detect.Stack) bool
	// Available returns the resolved binary path, or an error if the tool is missing.
	Available() (string, error)
	Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error)
}

// All returns every scanner kscan knows about, in report order.
func All() []Scanner {
	return []Scanner{
		Gitleaks{}, Semgrep{}, Trivy{}, OSVScanner{}, Gosec{}, Bandit{}, Govulncheck{},
	}
}

// lookPath finds a binary on PATH, falling back to the usual install
// locations of `go install` and `uv tool`/`pipx`, which are often not on PATH.
func lookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	home, _ := os.UserHomeDir()
	var dirs []string
	if gp := os.Getenv("GOPATH"); gp != "" {
		dirs = append(dirs, filepath.Join(gp, "bin"))
	}
	dirs = append(dirs, filepath.Join(home, "go", "bin"), filepath.Join(home, ".local", "bin"))
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found on PATH, ~/go/bin or ~/.local/bin", name)
}

// Version runs `<bin> <args>` and returns the line naming the tool
// (govulncheck prints the Go version first), else the first line.
func Version(ctx context.Context, bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, l := range lines {
		if strings.Contains(l, filepath.Base(bin)+"@") {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(lines[0])
}

// execTool runs a scanner binary in dir. Most scanners exit non-zero when
// they find something, so the exit code alone is not treated as failure;
// callers decide based on whether usable output was produced.
func execTool(ctx context.Context, dir, bin string, args ...string) (stdout []byte, runErr error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("%s: %w", filepath.Base(bin), ctx.Err())
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return out.Bytes(), err
	}
	if err != nil {
		runErr = fmt.Errorf("%s exited %d: %s", filepath.Base(bin), exitErr.ExitCode(), tail(errb.String()))
	}
	return out.Bytes(), runErr
}

// readOutput reads a tool's JSON report file. If the tool produced nothing,
// the tool's own error is the more useful message.
func readOutput(path string, runErr error) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		if runErr != nil {
			return nil, runErr
		}
		return nil, fmt.Errorf("no output produced at %s", path)
	}
	return data, nil
}

func tempOutput(name string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "kscan-"+name+"-")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "out.json"), func() { os.RemoveAll(dir) }, nil
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.Join(lines, " | ")
}

// relPath turns a tool-reported path into a slash-separated path relative to repo.
func relPath(repo, p string) string {
	if filepath.IsAbs(p) {
		if r, err := filepath.Rel(repo, p); err == nil {
			p = r
		}
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// sourceLine reads one line of a file in repo. Used to fill snippets
// because some tools (semgrep OSS) no longer return source lines.
func sourceLine(repo, file string, line int) string {
	if line <= 0 {
		return ""
	}
	f, err := os.Open(filepath.Join(repo, filepath.FromSlash(file)))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		if n == line {
			s := strings.TrimSpace(sc.Text())
			if len(s) > 300 {
				s = s[:300] + "…"
			}
			return s
		}
	}
	return ""
}

// finalize fills missing snippets from source, strips snippets from secrets
// and computes fingerprints.
func finalize(repo string, fs []finding.Finding) []finding.Finding {
	for i := range fs {
		f := &fs[i]
		if f.Category != finding.Secret && f.Category != finding.Dependency && f.Snippet == "" {
			f.Snippet = sourceLine(repo, f.File, f.Line)
		}
		if f.Category == finding.Secret {
			f.Snippet = ""
		}
		f.ComputeFingerprint()
	}
	return fs
}
