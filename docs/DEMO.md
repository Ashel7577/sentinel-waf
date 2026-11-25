# Live demo (10 minutes)

Everything shown is produced live by the running binary. Nothing on the dashboard or in the report is
simulated, and the evidence can be re-verified by anyone with the file.

## 0. Before the call (2 min)

```bash
go build -o bin/ ./cmd/...
bash scripts/demo.sh          # builds, starts app + Sentinel, sends traffic, writes the report
```

Keep three tabs open: `http://127.0.0.1:9090/` (dashboard), `demo-out/incident-report.html`, and the
GitHub Actions run of the latest commit (attack lab + CRS comparison artifacts).

## 1. The problem (1 min)

"Most WAF bypasses of the last two years don't hide the payload, they hide the request's *structure*.
WAFFLED (ACSAC 2025) found 1,207 of them in AWS, Azure, Cloudflare, Cloud Armor and ModSecurity: the WAF
parses the body one way, the framework another, and the payload rides in the part only the app reads."

## 2. What Sentinel does differently (2 min)

Open `internal/parsediff/`. Every body is read several ways:

- with **Go's own parsers** (`mime/multipart`, `encoding/json`, `net/url`), so for a Go backend the WAF
  inspects exactly what the handler receives;
- strictly by the RFCs;
- the lenient ways other frameworks read it (LF-only multipart, parts after the closing delimiter,
  duplicate keys first/last, `;` separators, comma-joined duplicate parameters, relaxed JSON).

Every value from every reading is inspected, and if the readings disagree the request is scored
(rule ids 7xxx). Show `TestBypassClasses` and `TestGoReadingMatchesNetHTTP`.

## 3. Attack it live (3 min)

In a terminal, send one classic and one structural attack and watch the dashboard update:

```bash
curl -i "localhost:8080/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"
curl -i -X POST localhost:8080/api -H 'Content-Type: application/json' \
  -d '{"role":"user","ROLE":"admin'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

The second one is a Go-specific trick: `encoding/json` matches struct fields case-insensitively, so
`ROLE` overwrites `role`. The 403 body carries the request id and the evidence hash.

Click the row in the threat feed and open the analyst's report. Walk through technique (CWE / CAPEC /
ATT&CK), exactly which field and value triggered which rule, why the score crossed the threshold, the
raw request, and the reproduction command.

## 4. Prove the evidence is real (1 min)

```bash
./bin/sentinel-report verify -evidence demo-out/evidence.jsonl     # OK, N records
sed -i '3s/"action":"blocked"/"action":"flagged"/' demo-out/evidence.jsonl
./bin/sentinel-report verify -evidence demo-out/evidence.jsonl     # FAILED at record 3 (exit 2)
```

Every record is SHA-256 chained to the previous one; editing, deleting or reordering any of them is
detected. Cookies and Authorization headers are stored only as digests.

## 5. Head to head, measured in CI (2 min)

Open the latest Actions run:

- **attacklab**: the same campaign against a real Go app, Coraza + OWASP CRS v4.25, and Sentinel. The
  artifact is a full evidence pack (verified chain, report, results table).
- **compare (PL1-PL4)**: detection, false positives and latency against CRS at every paranoia level
  on third-party payloads (SecLists) and 37k real benign lines.
- **fuzz**, **gotestwaf**, unit and regression tests on every push.

Be precise about limits (docs/THREAT_MODEL.md): structural tricks only matter if the backend's parser
accepts them; Sentinel models Go exactly and other frameworks' known behaviours, not every custom parser.
