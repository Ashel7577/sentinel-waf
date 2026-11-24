# Sentinel WAF

![ci](https://github.com/Ashel7577/sentinel-waf/actions/workflows/ci.yml/badge.svg)

I built Sentinel because my first WAF project didn't hold up when I looked at it honestly. It was mostly regexes, the "ML" part never actually ran, and I had no idea how good or bad it really was. So this time the rule was simple: every claim has to come with a number, and the number has to come from data I didn't write myself.

Sentinel is a reverse proxy written in Go that sits in front of a web app and blocks attacks before they reach it. Instead of matching keywords, it tokenizes input the way a database would. That is the difference between blocking `' OR 1=1--` and letting `O'Reilly and sons` through. To keep myself honest, I benchmarked it head to head against **OWASP Coraza + Core Rule Set v4**, the open-source WAF most people actually deploy, on the exact same requests.

![Live dashboard](docs/dashboard.png)

**New here? Read [How it works](docs/HOW-IT-WORKS.md)** for a step-by-step walkthrough with diagrams and screenshots.

## Results

These are GitHub CI numbers on Linux, regenerated on every push. Download them from the `compare-results` and `gotestwaf-report` artifacts of any run.

**Third-party corpus vs OWASP Coraza + CRS v4.25.** Attacks come from [SecLists](https://github.com/danielmiessler/SecLists) (SQLi, XSS, LFI, commix command injection). Benign traffic is 37,728 lines: two full public-domain novels, 2,454 real browser User-Agents, 4,751 web paths and 10,735 names. Every payload is tested in the query string, form body, JSON body and a header, at paranoia level 1 with a block threshold of 5 for both WAFs. The sample is 400 per category.

| | Sentinel WAF | Coraza + OWASP CRS v4.25 |
|---|---|---|
| Command injection | **100.0%** | 43.1% |
| SQL injection | **76.1%** | 46.4% |
| Path traversal / LFI | 64.5% | **69.6%** |
| XSS | **98.6%** | 94.4% |
| **Detection, query + form + JSON** | **83.1%** | 71.1% |
| **False positives** | **0.0%** | 0.3% |
| Latency per request, mean / p99 | **46 µs / 193 µs** | 1.19 ms / 4.93 ms |

On the full unsampled set, Sentinel wrongly blocks **4 of 150,912** benign requests.

**Independent test: [GoTestWAF](https://github.com/wallarm/gotestwaf)** (Wallarm), run against the live proxy in CI:

| Attacks blocked | API attacks blocked | Normal requests passed | Overall |
|---|---|---|---|
| 46% | 57% | 97.9% | **64.5%** |

This is the weakest result, and I'm leaving it visible on purpose. GoTestWAF re-encodes payloads (Base64, JS Unicode) and sends them through gRPC, GraphQL and SOAP. It also found a real padding-bypass bug, which is now fixed with a regression test. The [known gaps](docs/HOW-IT-WORKS.md#5-known-gaps-the-honest-list) section lists what's next.

**Caveats:**
- At paranoia level 1, CRS deliberately does not inspect arbitrary custom headers, so the headline row excludes headers.
- CRS ships far more than injection rules (protocol enforcement, response inspection). Sentinel only inspects requests.
- Path traversal is the one category where CRS wins.

## How it works

```
client ─► Sentinel (reverse proxy) ─► upstream app
            │
            ├─ size limit, per-IP token bucket rate limit
            ├─ extract every input: path + segments, query, form, nested JSON,
            │   XML text/attributes, multipart fields + raw filenames, headers,
            │   cookies (lenient parser), parameter / JSON key names
            ├─ normalize: bounded multi-pass URL / %u / HTML entity / \x \u decoding,
            │   overlong UTF-8, Unicode confusables (∕ ʼ ＜), fullwidth folding,
            │   NUL stripping, whitespace canonicalization, SQL comment unwrapping
            ├─ analyse each value
            │   ├─ SQLi: tokenizer, evaluated in 3 contexts (raw / inside '…' / inside "…")
            │   ├─ XSS: tag, event-handler, attribute and JS-string break-out analysis
            │   ├─ command injection: separator scan + shell-word lookup
            │   ├─ traversal / LFI: dot-dot sequences, sensitive files, stream wrappers
            │   └─ rule file: JSON regex rules behind an Aho-Corasick literal prefilter
            ├─ anomaly score (CRS-compatible severities) ≥ threshold → 403
            └─ JSON logs, request IDs, Prometheus metrics, live dashboard
```

The SQLi engine tokenizes input instead of matching keywords. Injection means the token stream breaks out of its assumed context into SQL structure: a closing quote followed by a real condition, a comment terminator, `UNION SELECT`, a stacked statement, a tautology like `x=x`, or a time-delay function. That is why `O'Reilly and sons`, `select a plan from the list` and real novel prose such as `"And he is admirably suited for it"` pass, while `x' AND email IS NULL; --` and `/*!50000UNION*/ /*!50000SELECT*/` are blocked.

There are no external dependencies: the WAF uses only the Go standard library.

## Run it

```bash
go build -o bin/ ./cmd/...
./bin/target -listen 127.0.0.1:8000                       # demo upstream (simulates sinks, executes nothing)
./bin/waf -listen :8080 -upstream http://127.0.0.1:8000   # dashboard on http://127.0.0.1:9090
./bin/trafficgen -url http://127.0.0.1:8080 -rps 20       # optional: live mixed traffic for the dashboard

curl "localhost:8080/search?q=1'%20UNION%20SELECT%20password%20FROM%20users--"   # 403
curl "localhost:8080/search?q=O'Reilly"                                          # 200
```

| Flag | Default | Description |
|---|---|---|
| `-monitor` | off | Shadow mode: log and score, never block. Use it to roll out safely. |
| `-threshold` | 5 | Anomaly score that blocks. One critical finding is enough. |
| `-paranoia` | 1 | 1–4. Higher enables noisier checks. |
| `-rules file.json` | embedded | Rule file, hot-reloaded on change. Invalid edits are rejected. |
| `-rate` / `-burst` | off | Per-IP rate limit. |
| `-max-body` | 1 MiB | Request body limit (413 above it). |
| `-log file` | stdout | Structured JSON logs. |

Admin endpoints are on `-admin` (localhost only): `/` dashboard, `/stats` JSON, `/metrics` Prometheus, `/healthz`.

## Reproduce the numbers

```bash
go test -race ./...                                        # unit + corpus regression tests
go test -bench . -benchmem ./internal/waf/                 # engine benchmarks
go run ./cmd/eval -corpus eval/corpus                      # built-in corpus
bash scripts/fetch-external.sh                             # download third-party corpora
go run ./cmd/eval -corpus eval/external -misses misses.tsv # every miss / false positive listed
cd bench/compare && go run . -corpus ../../eval/external -max 400   # head-to-head vs Coraza + CRS
```

CI runs all of the above on every push. It also runs **[GoTestWAF](https://github.com/wallarm/gotestwaf)** (Wallarm's independent WAF test suite) against the live proxy, and publishes the report as a build artifact.

## Layout

```
cmd/waf            proxy binary            internal/detect      SQLi / XSS / cmdi / traversal analysers
cmd/target         safe demo upstream      internal/normalize   decoding + canonicalization
cmd/eval           detection / FP harness  internal/waf         input extraction, rules, scoring engine
bench/compare      vs Coraza + CRS         internal/ahocorasick multi-pattern prefilter (DFA)
eval/corpus        regression corpus       internal/server      proxy, rate limit, metrics, dashboard
```

## Limitations and next steps

- Response inspection and outbound data-leak detection are not implemented.
- Path traversal (64.5%, the one category where CRS wins) needs work. The next step is a path canonicalizer that resolves `..` sequences against a virtual root.
- The ML stage from the original plan is not built yet: a character n-gram model trained on CSIC 2010, evaluated with a source-disjoint split.
- GoTestWAF coverage: NoSQL, mail-header injection, Base64-encoded payloads, GraphQL and gRPC bodies.

## License

MIT
