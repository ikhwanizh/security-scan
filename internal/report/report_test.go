package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kscan/internal/finding"
	"kscan/internal/gate"
	"kscan/internal/scanner"
)

func sample() Data {
	fs := []finding.Finding{
		{Tool: "trivy,govulncheck", RuleID: "CVE-1", Category: finding.Dependency, Severity: finding.Critical, File: "go.mod", Package: "x/net", InstalledVersion: "v0.1.0", FixedVersion: "v0.2.0", CVE: "CVE-1", Message: "bad"},
		{Tool: "semgrep", RuleID: "kscan-fstring-sql", Category: finding.SAST, Severity: finding.High, File: "app/db.py", Line: 7, Message: "SQL built with formatting", Snippet: `q = f"<script>alert(1)</script> {x}"`},
		{Tool: "gitleaks", RuleID: "generic-api-key", Category: finding.Secret, Severity: finding.Info, File: "docs/a.md", Line: 3, Message: "key"},
	}
	for i := range fs {
		fs[i].ComputeFingerprint()
	}
	return Data{
		Version: "test", Repo: "/repo", StartedAt: time.Unix(0, 0), Duration: time.Second, Findings: fs,
		Scanners: []scanner.Result{{Scanner: "semgrep", Status: scanner.StatusOK}, {Scanner: "gosec", Status: scanner.StatusSkipped, Reason: "not applicable"}},
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 3 {
		t.Fatalf("version %q, %d runs", log.Version, len(log.Runs))
	}
	byTool := map[string]sarifRun{}
	for _, r := range log.Runs {
		byTool[r.Tool.Driver.Name] = r
	}
	trivy, ok := byTool["trivy"]
	if !ok {
		t.Fatal("merged finding should be attributed to trivy")
	}
	res := trivy.Results[0]
	if res.Level != "error" || res.Locations[0].PhysicalLocation.Region != nil || res.PartialFingerprints["kscan/v1"] == "" {
		t.Errorf("unexpected trivy result: %+v", res)
	}
	sem := byTool["semgrep"].Results[0]
	if sem.Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Errorf("semgrep line lost: %+v", sem)
	}
	if byTool["gitleaks"].Results[0].Level != "note" {
		t.Error("info severity should map to note")
	}
}

func TestHTMLEscapes(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)") {
		t.Fatal("snippet was not escaped")
	}
	for _, want := range []string{"&lt;script&gt;alert(1)", "kscan-fstring-sql", "x/net", "v0.2.0", "not applicable"} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestTerminal(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, sample(), 2)
	out := buf.String()
	for _, want := range []string{"critical 1", "Top findings (2 of 3)", "x/net v0.1.0 → v0.2.0", "app/db.py:7", "skip   gosec"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("colors must be off when not writing to a terminal")
	}
}

// withBaseline marks the semgrep finding as new and the rest as existing.
func withBaseline() Data {
	d := sample()
	d.Baseline = ".security-baseline.json"
	d.Findings[1].New = true
	d.Gate = gate.Decide(d.Scanners, d.Findings, finding.High, true)
	return d
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, withBaseline()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Gate   gate.Outcome `json:"gate"`
		Counts struct {
			Total map[string]int `json:"total"`
			New   map[string]int `json:"new"`
		} `json:"counts"`
		Scanners []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"scanners"`
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Gate.Code != gate.Fail || got.Gate.Blocking != 1 {
		t.Errorf("gate = %+v", got.Gate)
	}
	if got.Counts.Total["critical"] != 1 || got.Counts.New["critical"] != 0 || got.Counts.New["high"] != 1 {
		t.Errorf("counts = %+v", got.Counts)
	}
	if len(got.Scanners) != 2 || got.Scanners[1].Status != "skipped" || len(got.Findings) != 3 {
		t.Errorf("unexpected summary: %s", buf.String())
	}
}

func TestMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, withBaseline()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"FAIL: 1 new finding(s) at or above high", "| high | 1 | 1 |", "New findings (1 of 1)", "`app/db.py:7`"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "x/net") || strings.Contains(out, "alert(1)") {
		t.Errorf("markdown must list new findings only and no snippets:\n%s", out)
	}
}

func TestTerminalBaseline(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, withBaseline(), 1)
	out := buf.String()
	for _, want := range []string{"1 new / 2 existing", "app/db.py:7", "FAIL: 1 new finding"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal missing %q:\n%s", want, out)
		}
	}
}

func TestDefectDojo(t *testing.T) {
	var buf bytes.Buffer
	if err := DefectDojo(&buf, withBaseline()); err != nil {
		t.Fatal(err)
	}
	var got ddReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "kscan" || len(got.Findings) != 3 {
		t.Fatalf("unexpected report: %s", buf.String())
	}
	dep, sast, secret := got.Findings[0], got.Findings[1], got.Findings[2]
	if dep.Severity != "Critical" || dep.ComponentName != "x/net" || dep.FixVersion != "v0.2.0" ||
		len(dep.VulnerabilityIDs) != 1 || dep.VulnerabilityIDs[0] != "CVE-1" || dep.Title != "x/net v0.1.0: CVE-1" {
		t.Errorf("dependency finding = %+v", dep)
	}
	if sast.Severity != "High" || sast.Line != 7 || sast.Title != "kscan-fstring-sql: SQL built with formatting" ||
		sast.UniqueIDFromTool == "" || !strings.Contains(sast.Description, "alert(1)") {
		t.Errorf("sast finding = %+v", sast)
	}
	if secret.Severity != "Info" || strings.Contains(secret.Description, "```") {
		t.Errorf("secret finding must carry no snippet: %+v", secret)
	}
	// DefectDojo's fallback hash includes the description, so baseline state
	// (new vs existing) must not change it.
	var plain bytes.Buffer
	if err := DefectDojo(&plain, sample()); err != nil {
		t.Fatal(err)
	}
	if plain.String() != buf.String() {
		t.Error("output must not depend on baseline state")
	}
}

func TestDefectDojoAcceptedFields(t *testing.T) {
	// Keys the DefectDojo 3.4 generic JSON parser accepts on a finding (plus
	// the ones it pops before checking). Anything else fails the import.
	allowed := map[string]bool{}
	for _, k := range strings.Fields(`title severity description date file_path line component_name
		component_version vulnerability_ids mitigation fix_available fix_version references
		unique_id_from_tool vuln_id_from_tool static_finding dynamic_finding active verified tags`) {
		allowed[k] = true
	}
	var buf bytes.Buffer
	if err := DefectDojo(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, f := range raw.Findings {
		for k := range f {
			if !allowed[k] {
				t.Errorf("field %q is not accepted by DefectDojo", k)
			}
		}
	}
}

func TestTerminalTriage(t *testing.T) {
	d := sample()
	d.DefectDojo = "my-repo"
	d.Findings[0].Triage = "risk_accepted"
	var buf bytes.Buffer
	Terminal(&buf, d, 10)
	out := buf.String()
	for _, want := range []string{`Triaged   1 in DefectDojo product "my-repo"`, "accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal missing %q:\n%s", want, out)
		}
	}
}
