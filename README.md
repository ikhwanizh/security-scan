# kscan

One command that runs several security scanners on a repository, merges their results into one report, and decides pass or fail for CI.

kscan has **no detection engine of its own**. It orchestrates proven open source tools and adds what they lack together:

- **Stack detection** (Go, Python, Rust, PHP, Node), so only relevant scanners run.
- **Normalization**: every tool's output becomes one `Finding` model with one severity scale (critical, high, medium, low, info).
- **Dedupe**: the same CVE reported by trivy, osv-scanner and govulncheck becomes one finding.
- **False-positive control**: "secrets" in docs, tests and templates are demoted to info; suppressions with a required reason.
- **Baseline mode**: only *new* findings fail a build, so legacy issues don't block every pull request.
- **Custom Semgrep rules** for bug patterns found in real code.

| Category | What it looks for | Tools |
|---|---|---|
| Secret | Hardcoded API keys, tokens, private keys | gitleaks |
| SAST | Dangerous code patterns: SQL injection, unsafe deserialization, SSRF | semgrep, bandit (Python), gosec (Go, local only) |
| Dependency (SCA) | Libraries with known CVEs | trivy, osv-scanner, govulncheck (Go, local only; reports whether the vulnerable function is actually called) |
| Misconfig | Dockerfile/IaC problems, e.g. container running as root | trivy |

Not covered: DAST (attacking a running app, as OWASP ZAP or Burp do) and business-logic bugs such as missing ownership checks (IDOR). Those still need manual review and tests.

Flowcharts of the release, CI and scan pipeline: [docs/architecture.md](docs/architecture.md).

## Install

### Docker image (recommended, used by CI)

```bash
docker pull ghcr.io/ikhwanizh/kscan:1.0.0
docker run --rm -v "$PWD:/src" ghcr.io/ikhwanizh/kscan:1.0.0 scan /src --out /src/kscan-report
```

The image contains kscan, semgrep, gitleaks, trivy, osv-scanner and bandit, all pinned. It does not contain gosec or govulncheck: both need the full Go toolchain at scan time (~250 MB more). Inside the image they show as "skipped"; semgrep's Go rules plus trivy and osv-scanner still cover Go code and dependencies.

### Local binary

Requires Go 1.25+.

```bash
make build                       # -> bin/kscan

# scanners (any that are missing are skipped)
brew install gitleaks trivy osv-scanner gosec
uv tool install semgrep
uv tool install bandit
go install golang.org/x/vuln/cmd/govulncheck@latest

bin/kscan doctor                 # shows what is installed
```

## Run locally

```bash
kscan scan ~/dev/project --out ~/kscan-reports/project
kscan scan . --format terminal --top 50       # console only
kscan scan . --only semgrep,gitleaks          # selected scanners
kscan scan . --offline                        # no semgrep registry, custom rules only
kscan scan . --history                        # also search git history for secrets
kscan scan . --fail-on critical               # override the threshold
kscan rules list                              # custom semgrep rules
```

Outputs (`--format`, default `terminal,sarif,json,html`):

| Format | File | Use |
|---|---|---|
| terminal | stdout | Summary, top findings, scanner status, PASS/FAIL line |
| sarif | `kscan.sarif` | SARIF 2.1.0, one run per tool; GitHub code scanning |
| json | `kscan.json` | Machine-readable summary: gate result, counts, scanners, findings |
| html | `kscan.html` | Self-contained page with severity filter and search |
| markdown | `kscan.md` | Short summary for CI job pages (new findings only, no code) |
| defectdojo | `kscan.defectdojo.json` | DefectDojo "Generic Findings Import" (see [DefectDojo](#defectdojo)) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass: no new finding at or above the threshold |
| 1 | Fail: new finding(s) at or above the threshold |
| 2 | Tool or usage error: a scanner crashed or timed out, an enabled scanner is missing, bad config or flags |

If one scanner fails, the others still run and every report is still written; the failing scanner is listed with its error. Exit 2 wins over 1, because an incomplete scan cannot be trusted as a pass.

## Configure

Put `.security-scan.yml` at the root of the scanned repo (see [`.security-scan.example.yml`](.security-scan.example.yml)):

```yaml
scanners:
  disable: [bandit]            # or enable: [...] (exact list; missing = exit 2)
fail_on: high                  # info|low|medium|high|critical|none; --fail-on overrides
ignore_paths: ["evals/**"]     # vendor/, node_modules/, venv/ ... are always skipped
suppress:
  - fingerprint: 0123456789abcdef
    reason: MD5 used as a cache key, not for security
  - rule: kscan-ssrf-unvalidated-host
    path: "app/admin/**"
    reason: admin-only endpoint, hosts come from a fixed allowlist
min_severity: low
```

Every suppression needs a `reason`. Fingerprints appear in the HTML, JSON and SARIF reports. A fingerprint hashes the tool, rule, file and normalized source line, not the line number, so it survives code moving around. Dependency findings are keyed by package, version and advisory, so the same CVE from different tools merges.

## Baseline workflow

```bash
# 1. Accept today's findings (run on the default branch, full scan)
kscan scan . --write-baseline .security-baseline.json
git add .security-baseline.json && git commit -m "Add security baseline"

# 2. Every later scan compares against it
kscan scan . --baseline .security-baseline.json
```

- The baseline stores only fingerprint, rule, file and severity. It contains no code or secret values, so it is safe to commit.
- Only findings not in the baseline count toward `fail_on`. The terminal shows "N new / M existing"; SARIF marks results `new` or `unchanged`.
- kscan refuses to write a baseline when a scanner failed, since the baseline would silently miss that scanner's findings.
- Refresh it after fixing a batch of old issues, so fixed issues cannot return unnoticed.
- Secret findings are fingerprinted by line (the value is redacted), so a moved secret shows up as new. Rotate it either way.
- A missing baseline file is not an error: every finding is new.

## DefectDojo

[DefectDojo](https://github.com/DefectDojo/django-DefectDojo) keeps finding history, triage (false positive, risk acceptance), SLAs and Jira sync. kscan stays the scanner and the CI gate; DefectDojo stores and manages the results.

1. On the DefectDojo server, make it track kscan findings by kscan's fingerprint instead of its default hash, which includes the line number (so moved code would show up as new findings). Set this env var on the `uwsgi`, `celeryworker` and `celerybeat` containers:

   ```
   DD_DEDUPLICATION_ALGORITHM_PER_PARSER={"kscan Scan (Generic Findings Import)": "unique_id_from_tool"}
   ```

   The key is the test type name DefectDojo derives from kscan's report type; it must match exactly.

2. Scan and reimport, from a **full scan of the default branch only**:

   ```bash
   kscan scan . --format terminal,defectdojo --out kscan-report
   curl -fsS -X POST "$DD_URL/api/v2/reimport-scan/" \
     -H "Authorization: Token $DD_API_KEY" \
     -F scan_type="Generic Findings Import" \
     -F file=@kscan-report/kscan.defectdojo.json \
     -F product_type_name="Team" -F product_name="my-repo" \
     -F engagement_name="CI/CD main" -F test_title="kscan" \
     -F auto_create_context=true -F close_old_findings=true \
     -F deduplication_on_engagement=true -F minimum_severity=Info
   ```

   Never upload a `--changed-since` scan: `close_old_findings` would close every finding outside the changed files.

What reimport does with the fingerprint (verified against DefectDojo 3.4.202 on `test-fixtures/`):

| Change between scans | DefectDojo result |
|---|---|
| Nothing | 0 created, all untouched |
| Code moved to other lines | 0 created, untouched (the line number shown stays the first-seen one) |
| Issue removed | that finding closed (mitigated) |

The export holds the same data as `kscan.json`, so it includes source snippets of non-secret findings, but never secret values.

## CI setup (GitHub Actions)

1. Copy [`ci/github/security-scan.yml`](ci/github/security-scan.yml) to `.github/workflows/security-scan.yml`.
2. Optionally add `.security-scan.yml` and commit a baseline (see above).

What it does:

- **Push to main**: full scan.
- **Pull request**: diff mode (`--changed-since origin/<base>`). semgrep and bandit scan only changed files, gitleaks scans only the PR's commits (catching a secret added and removed inside the PR), dependency scanners scan everything. Set `KSCAN_PR_DIFF: "false"` for full PR scans.
- Pulls the pinned image; it never builds it.
- Caches the trivy vulnerability DB per day.
- Uploads SARIF to code scanning, writes the markdown summary to the job page, and keeps the reports as an artifact for 7 days.
- **Optional DefectDojo upload**: when the secrets `DD_URL` and `DD_API_KEY` exist, full scans of the default branch are reimported into DefectDojo (product = repo name, product type = `DD_PRODUCT_TYPE` or the repo owner, engagement `CI/CD <branch>`, with commit, branch and run ID on the test). It is skipped for pull requests, other branches and scans where a scanner failed (exit 2), since `close_old_findings` would wrongly close findings. An upload failure shows on the step but does not change the gate. The API key's user needs permission to create products when they don't exist yet, and the DefectDojo server must be reachable from the runner.
- Fails the job with kscan's exit code.

Notes:

- **Code scanning (SARIF upload) is free on public repos but needs GitHub Advanced Security on private ones.** Without it, the upload step warns and is skipped; the job summary and artifact still work.
- In diff mode, code scanning may list alerts outside the changed files as "fixed" in the PR view, because those files were not scanned. The gate is unaffected. Use full PR scans if that is confusing.
- A private image needs `packages: read` and access for the consuming repo (package settings → Manage Actions access).

## Add a new scanner

1. Create `internal/scanner/<name>.go` implementing `Scanner`: `Name`, `Applies(stack)`, `Available` (via `lookPath`), and `Run`. Keep parsing in a `parse<Name>(io.Reader)` function, map severities to the five levels, and finish with `finalize(repo, findings)` (snippets, secret stripping, fingerprints).
2. Register it in `scanner.All()`, and add its version flag and install hint in `cmd/kscan/main.go` (`versionArgs`, `installHints`) and its URL in `report/sarif.go` (`toolURIs`).
3. Run the tool on `test-fixtures/`, rewrite absolute paths to `/repo`, save the output in `internal/scanner/testdata/`, and add a golden test in `parse_test.go`. Never create fixtures from real repositories.
4. If the fixture lacks an issue the tool should catch, add one to `test-fixtures/`, and add a check in `integration/scan_test.go`.
5. Add the binary to the `Dockerfile` (pinned version and sha256) and to `KSCAN_REQUIRE` defaults if it ships in the image.

## Update tool versions

- **Go-based tools** (gitleaks, trivy, osv-scanner): change the `*_VERSION` and both `*_SHA256_*` ARGs in the `Dockerfile`. Take the checksums from the release's checksum file.
- **Python tools** (semgrep, bandit): edit `docker/requirements.in`, then `make image-deps` to re-lock `docker/requirements.txt` with hashes.
- **Base images**: `GO_IMAGE` and `PYTHON_IMAGE` ARGs.
- Prefer releases that are at least two weeks old.

Then:

```bash
make image image-test      # build locally; integration tests through the image
git tag v1.0.1 && git push origin v1.0.1
```

The `release-image` workflow builds `linux/amd64` and `linux/arm64`, pushes `ghcr.io/<owner>/kscan:1.0.1`, and refuses to overwrite an existing version. Finally bump `KSCAN_IMAGE` in the CI template, and in consumer repos.

## Custom rules

Rules live in `rules/<lang>/<id>.yaml` and are embedded in the binary. Each rule has a test file next to it with `# ruleid:` (must match) and `# ok:` (must not match) annotations.

| Rule | Catches |
|---|---|
| `kscan-sql-startswith-select` | "Read-only" SQL checks via `startswith('SELECT')`, which are bypassable |
| `kscan-fstring-sql` | SQL built with f-strings or `.format` |
| `kscan-unsafe-deserialization` | `pickle.load`, `joblib.load`, `torch.load` without `weights_only` |
| `kscan-ssrf-unvalidated-host` | DB/HTTP connections to user-supplied hosts without a private-IP check (heuristic) |
| `kscan-go-sql-sprintf` | `fmt.Sprintf` passed to `Query`/`Exec`/`Raw` |

To add one: write vulnerable and safe examples in `rules/<lang>/kscan-<name>.<ext>`, write `kscan-<name>.yaml` (IDs start with `kscan-`), run `make rules-test` until it passes, then try it on real code and cut false positives with `pattern-not` and `metavariable-regex`. `metavariable-regex` is anchored at the start of the string, so prefix `.*` when the keyword can appear mid-string.

## Development

```bash
make test           # unit tests, including golden parser tests
make rules-test     # semgrep --test for custom rules
make integration    # real scanners on test-fixtures/, each must catch its issue
make lint
make image          # build the image, print its size
make image-test     # integration tests through the image
make scan-fixture   # scan test-fixtures/ and write kscan-report/
```

`test-fixtures/` is a small, deliberately vulnerable project: SQL injection, unsafe pickle, SSRF, outdated dependencies, a vulnerable Go module, a root Dockerfile, and fake secrets. Every fake secret contains the marker `kscanfixture-`; the integration tests check the marker never appears in any output. (gitleaks ignores values containing words like "fake" or "example", so those can't be used.)

## Security notes

- **Reports contain file paths and snippets of the scanned code.** They are written with mode `0600`, and `kscan-report/` is gitignored. Do not commit reports or upload them outside the scanned repo's own CI.
- Secret values are never printed: gitleaks runs with `--redact`, and secret findings carry no snippet in any report.
- Scan only code you are authorized to scan.

## Roadmap

- Results server and dashboard (Phase 2), or import into DefectDojo.
- Optional LLM triage (`--triage`), opt-in only, since code would be sent to an external API.
- More scanners: cargo-audit, composer audit, hadolint, checkov; an image variant with the Go toolchain for gosec and govulncheck.
