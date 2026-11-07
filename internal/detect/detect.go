// Package detect finds which language ecosystems a repository uses.
package detect

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

type Lang string

const (
	Go     Lang = "go"
	Python Lang = "python"
	Rust   Lang = "rust"
	PHP    Lang = "php"
	Node   Lang = "node"
)

const maxDepth = 3

// SkipDirs are never descended into, by detection or by scanners.
var SkipDirs = []string{".git", "vendor", "node_modules", "venv", ".venv", "target", "__pycache__", "dist", "build"}

type Stack struct {
	Languages []Lang
	// Roots maps each language to the directories (relative to the repo)
	// containing its marker file.
	Roots map[Lang][]string
}

func (s Stack) Has(l Lang) bool { return slices.Contains(s.Languages, l) }

func markerLang(name string) (Lang, bool) {
	switch {
	case name == "go.mod":
		return Go, true
	case name == "pyproject.toml", strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
		return Python, true
	case name == "Cargo.toml":
		return Rust, true
	case name == "composer.json":
		return PHP, true
	case name == "package.json":
		return Node, true
	}
	return "", false
}

func Detect(repo string) (Stack, error) {
	st := Stack{Roots: map[Lang][]string{}}
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are not fatal for detection
		}
		rel, _ := filepath.Rel(repo, path)
		if d.IsDir() {
			if rel != "." && (slices.Contains(SkipDirs, d.Name()) || strings.Count(rel, string(filepath.Separator)) >= maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		lang, ok := markerLang(d.Name())
		if !ok {
			return nil
		}
		dir := filepath.Dir(rel)
		if !slices.Contains(st.Roots[lang], dir) {
			st.Roots[lang] = append(st.Roots[lang], dir)
		}
		if !st.Has(lang) {
			st.Languages = append(st.Languages, lang)
		}
		return nil
	})
	slices.Sort(st.Languages)
	return st, err
}
