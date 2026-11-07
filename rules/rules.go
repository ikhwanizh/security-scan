// Package rules embeds kscan's custom semgrep rules.
//
// Each rule <lang>/<id>.yaml has a test target next to it (<id>.py, <id>.go)
// annotated with `ruleid:` / `ok:` comments; run `make rules-test`.
package rules

import (
	"embed"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

//go:embed python/*.yaml go/*.yaml
var files embed.FS

type Rule struct {
	ID        string   `yaml:"id"`
	Languages []string `yaml:"languages"`
	Severity  string   `yaml:"severity"`
	Message   string   `yaml:"message"`
}

// Extract writes the rule files to a temporary directory for semgrep --config.
func Extract() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "kscan-rules-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	err = fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// List returns all embedded rules sorted by id.
func List() ([]Rule, error) {
	var out []Rule
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".yaml" {
			return err
		}
		data, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		var doc struct {
			Rules []Rule `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return err
		}
		out = append(out, doc.Rules...)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}
