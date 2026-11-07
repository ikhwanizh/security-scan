// Package gitdiff reads commit and changed-file information from git.
package gitdiff

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func git(ctx context.Context, repo string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Head returns the current commit SHA, or "" when repo is not a git checkout.
func Head(ctx context.Context, repo string) string {
	sha, err := git(ctx, repo, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return sha
}

// Changed lists files added, copied, modified or renamed on HEAD since it
// diverged from base (the PR's merge base), relative to the repo root.
func Changed(ctx context.Context, repo, base string) ([]string, error) {
	out, err := git(ctx, repo, "diff", "--name-only", "--diff-filter=ACMR", "-z", base+"...HEAD")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}
