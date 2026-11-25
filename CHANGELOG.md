# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased] - 0.2.0

### Added
- **Autonomous evaluation engine** (`cmd/sentinel-autoeval`, `internal/redteam`): adaptive evasion search
  guided by the WAF's verdicts, backend oracle (`internal/testapp`), auto-tuning across paranoia levels,
  evidence chain, run history and a PDF-ready report. Runs in CI as a regression gate (fails on any bypass).
- High-resolution clock (`internal/hrclock`) for accurate microsecond latency on Windows.
- **Parser-differential guard** (`internal/parsediff`). Every request body is read the way several parsers
  would read it: Go's own standard library (identical to what a Go backend receives), a strict RFC reading,
  and the lenient behaviours other frameworks are known to have. All values from all readings are
  inspected, and requests whose meaning depends on the parser are scored (rule ids 7xxx): duplicate and
  case-variant JSON keys, trailing JSON documents, comment-style JSON, multiple or prefix multipart
  boundaries, parts after the closing delimiter, LF-only multipart, quoted-printable parts,
  filename/filename* conflicts, duplicate Content-Type headers, Content-Type/body mismatch, exotic
  charsets (ibm037, utf-16, utf-7), `;` parameter separators, and HTTP parameter pollution
  (comma-joined duplicates).
- **Evidence vault** (`-evidence file.jsonl`). Every blocked or flagged request is preserved with its full
  request, SHA-256 digests and verdict in an append-only SHA-256 hash chain; editing, deleting or
  reordering any record is detected. Cookie and Authorization values are stored only as digests.
- **Built-in analyst**: `/report` (HTML), `/report.md`, `/evidence` and `/verify` on the admin port, and the
  offline `sentinel-report verify|report` command. Reports name each technique with CWE, CAPEC and
  MITRE ATT&CK ids, explain how it works, show exactly which field and value were detected, why the
  request was blocked, how to fix the application, the raw request, the hashes and a reproduction command.
- **Attack lab** (`bench/compare/attacklab`): runs a campaign against a real Go application, Coraza + OWASP
  CRS and Sentinel side by side and writes an evidence pack (verified evidence chain, incident report,
  results table). Runs in CI on every push.
- Release engineering: SECURITY.md, threat model, goreleaser builds, keyless cosign signatures and SLSA
  build provenance on releases, OpenSSF Scorecard, Dependabot, native Go fuzzing in CI, CRS comparison at
  paranoia levels 1-4.

### Fixed
- Rule 3004 (reverse shell) missed `nc host port -e /bin/sh` when host and port come before `-e`, and its
  prefilter was case-sensitive. Found by the autonomous engine (12 confirmed bypasses); four regression
  payloads added.

## [0.1.0] - 2026-11-24

### Added
- Reverse-proxy WAF: SQL tokenizer evaluated in three quote contexts, XSS / command injection / traversal
  analysers, multi-pass normalization, Aho-Corasick rule prefilter, CRS-compatible anomaly scoring,
  rate limiting, Prometheus metrics, live dashboard, head-to-head benchmark against Coraza + CRS and
  GoTestWAF in CI.
