package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"kscan/internal/detect"
	"kscan/internal/finding"
)

// Trivy finds vulnerable dependencies (SCA) and IaC/Dockerfile misconfigurations.
type Trivy struct{}

func (Trivy) Name() string               { return "trivy" }
func (Trivy) Applies(detect.Stack) bool  { return true }
func (Trivy) Available() (string, error) { return lookPath("trivy") }

func (t Trivy) Run(ctx context.Context, repo string, opts Options) ([]finding.Finding, error) {
	bin, err := t.Available()
	if err != nil {
		return nil, err
	}
	out, cleanup, err := tempOutput("trivy")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Secrets are left to gitleaks.
	args := []string{"fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet", "--output", out}
	for _, d := range detect.SkipDirs {
		if d == ".git" {
			continue
		}
		args = append(args, "--skip-dirs", "**/"+d)
	}
	args = append(args, ".")

	_, runErr := execTool(ctx, repo, bin, args...)
	data, err := readOutput(out, runErr)
	if err != nil {
		return nil, err
	}
	fs, err := parseTrivy(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for i := range fs {
		fs[i].File = relPath(repo, fs[i].File)
	}
	return finalize(repo, fs), nil
}

type trivyOutput struct {
	Results []struct {
		Target          string
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
		}
		Misconfigurations []struct {
			ID            string
			Title         string
			Message       string
			Severity      string
			CauseMetadata struct {
				StartLine int
			}
		}
	}
}

func parseTrivy(r io.Reader) ([]finding.Finding, error) {
	var o trivyOutput
	if err := json.NewDecoder(r).Decode(&o); err != nil {
		return nil, fmt.Errorf("parse trivy: %w", err)
	}
	var fs []finding.Finding
	for _, res := range o.Results {
		for _, v := range res.Vulnerabilities {
			sev, _ := finding.ParseSeverity(v.Severity)
			msg := v.Title
			if msg == "" {
				msg = v.VulnerabilityID
			}
			fs = append(fs, finding.Finding{
				Tool:             "trivy",
				RuleID:           v.VulnerabilityID,
				Category:         finding.Dependency,
				Severity:         sev,
				File:             res.Target,
				Message:          msg,
				CVE:              v.VulnerabilityID,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
			})
		}
		for _, m := range res.Misconfigurations {
			sev, _ := finding.ParseSeverity(m.Severity)
			msg := m.Title
			if m.Message != "" {
				msg += ": " + m.Message
			}
			fs = append(fs, finding.Finding{
				Tool:     "trivy",
				RuleID:   m.ID,
				Category: finding.Misconfig,
				Severity: sev,
				File:     res.Target,
				Line:     m.CauseMetadata.StartLine,
				Message:  msg,
			})
		}
	}
	return fs, nil
}
