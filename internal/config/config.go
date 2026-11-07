// Package config loads the per-repo .security-scan.yml file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"kscan/internal/finding"
)

const FileName = ".security-scan.yml"

// DefaultSecretDemotePaths are places where "secrets" are almost always
// examples (docs, tests, templates). Matching secret findings are kept but
// demoted to info.
var DefaultSecretDemotePaths = []string{
	"**/*.md",
	"docs/**",
	"**/docs/**",
	"tests/**",
	"**/tests/**",
	"**/test_*.py",
	"**/*_test.go",
	"**/*example*",
	"**/*.template",
}

// Scanners selects which scanners run. Enable, when set, is an exact list;
// a scanner listed there but not installed is reported as a tool error.
type Scanners struct {
	Enable  []string `yaml:"enable"`
	Disable []string `yaml:"disable"`
}

// Suppress hides findings. It matches either one exact fingerprint, or every
// finding of Rule (rule ID or CVE) under the Path glob. Reason is required.
type Suppress struct {
	Fingerprint string `yaml:"fingerprint"`
	Rule        string `yaml:"rule"`
	Path        string `yaml:"path"`
	Reason      string `yaml:"reason"`
}

func (s Suppress) Matches(f finding.Finding) bool {
	if s.Fingerprint != "" {
		return s.Fingerprint == f.Fingerprint
	}
	if s.Rule != "" && s.Rule != f.RuleID && s.Rule != f.CVE {
		return false
	}
	if s.Path != "" {
		if ok, _ := doublestar.Match(s.Path, f.File); !ok {
			return false
		}
	}
	return true
}

type Config struct {
	Scanners Scanners `yaml:"scanners"`
	// FailOn is the lowest severity of a new finding that fails the scan,
	// or "none".
	FailOn string `yaml:"fail_on"`
	// IgnorePaths drops every finding under these globs.
	IgnorePaths []string `yaml:"ignore_paths"`
	// SecretDemotePaths replaces DefaultSecretDemotePaths when set.
	SecretDemotePaths []string   `yaml:"secret_demote_paths"`
	Suppress          []Suppress `yaml:"suppress"`
	MinSeverity       string     `yaml:"min_severity"`

	minSeverity finding.Severity
	failOn      finding.Severity
}

func Default() *Config {
	c := &Config{SecretDemotePaths: DefaultSecretDemotePaths, MinSeverity: "info", FailOn: "high"}
	if err := c.validate(); err != nil {
		panic(err)
	}
	return c
}

// Load reads path. A missing file yields the defaults.
func Load(path string) (*Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var fileCfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&fileCfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Scanners = fileCfg.Scanners
	c.IgnorePaths = fileCfg.IgnorePaths
	c.Suppress = fileCfg.Suppress
	if fileCfg.SecretDemotePaths != nil {
		c.SecretDemotePaths = fileCfg.SecretDemotePaths
	}
	if fileCfg.MinSeverity != "" {
		c.MinSeverity = fileCfg.MinSeverity
	}
	if fileCfg.FailOn != "" {
		c.FailOn = fileCfg.FailOn
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// SetFailOn overrides the threshold (used for the --fail-on flag).
func (c *Config) SetFailOn(v string) error {
	c.FailOn = v
	return c.validate()
}

func (c *Config) validate() error {
	sev, err := finding.ParseSeverity(c.MinSeverity)
	if err != nil {
		return fmt.Errorf("min_severity: %w", err)
	}
	c.minSeverity = sev
	if c.FailOn == "none" {
		c.failOn = -1
	} else if c.failOn, err = finding.ParseSeverity(c.FailOn); err != nil {
		return fmt.Errorf("fail_on: %w", err)
	}
	if len(c.Scanners.Enable) > 0 && len(c.Scanners.Disable) > 0 {
		return errors.New("scanners: set either enable or disable, not both")
	}
	for _, g := range append(append([]string{}, c.IgnorePaths...), c.SecretDemotePaths...) {
		if !doublestar.ValidatePattern(g) {
			return fmt.Errorf("invalid glob %q", g)
		}
	}
	for i, s := range c.Suppress {
		switch {
		case s.Reason == "":
			return fmt.Errorf("suppress[%d]: reason is required", i)
		case s.Fingerprint == "" && s.Rule == "" && s.Path == "":
			return fmt.Errorf("suppress[%d]: set fingerprint, or rule and/or path", i)
		case s.Fingerprint != "" && (s.Rule != "" || s.Path != ""):
			return fmt.Errorf("suppress[%d]: fingerprint cannot be combined with rule/path", i)
		case s.Path != "" && !doublestar.ValidatePattern(s.Path):
			return fmt.Errorf("suppress[%d]: invalid glob %q", i, s.Path)
		}
	}
	return nil
}

func (c *Config) Min() finding.Severity { return c.minSeverity }

// Threshold returns the fail_on severity; ok is false for "none".
func (c *Config) Threshold() (sev finding.Severity, ok bool) {
	return c.failOn, c.failOn >= 0
}
