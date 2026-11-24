# Sentinel WAF

![ci](https://github.com/Ashel7577/sentinel-waf/actions/workflows/ci.yml/badge.svg)

I built Sentinel because my first WAF project didn't hold up when I looked at it honestly. It was mostly regexes, the "ML" part never actually ran, and I had no idea how good or bad it really was. So this time the rule was simple: every claim has to come with a number, and the number has to come from data I didn't write myself.

Sentinel is a reverse proxy written in Go that sits in front of a web app and blocks attacks before they reach it. Instead of matching keywords, it tokenizes input the way a database would. That is the difference between blocking `' OR 1=1--` and letting `O'Reilly and sons` through. To keep myself honest, I benchmarked it head to head against **OWASP Coraza + Core Rule Set v4**, the open-source WAF most people actually deploy, on the exact same requests.

![Live dashboard](docs/dashboard.png)

![Real requests through the proxy](docs/demo.png)

## Results

**Third-party corpus.** Attacks come from [SecLists](https://github.com/danielmiessler/SecLists) (SQLi, XSS, LFI, commix command injection). Benign traffic is 37,728 lines: two full public-domain novels, 2,454 real browser User-Agents, 4,751 web paths and 10,735 names. Every payload is tested in 4 places (query string, form body, JSON body, header) at paranoia level 1 with a block threshold of 5 for both WAFs. The sample is 400 per category; see [`results-compare-external.md`](results-compare-external.md).

| | Sentinel WAF | Coraza + OWASP CRS v4.25 |
|---|---|---|
| Command injection | **100.0%** | 43.1% |
| SQL injection | **76.1%** | 46.4% |
| Path traversal / LFI | **64.5%** | 28.9% |
| XSS | **98.6%** | 94.4% |
| **Detection, query + form + JSON** | **83.1%** | 55.7% |
| **False positives** | **0.00%** | 0.20% |
| Mean inspection latency | **0.18 ms** | 4.6 ms |

On the full unsampled third-party set, Sentinel blocks 37,468 of 39,188 attack requests and wrongly blocks **4 of 150,912** benign ones (`go run ./cmd/eval -corpus eval/external`).

Latency was measured in-process on a 2012 Intel i3-3217U laptop, and covers request parsing plus inspection for both WAFs. CI reruns everything on GitHub's Linux runners.

**Caveats, stated plainly:**
- At paranoia level 1, CRS deliberately does not inspect arbitrary custom headers. The query + form + JSON row above excludes headers for that reason.
- CRS ships hundreds of rules covering protocol enforcement, response inspection and more. Sentinel covers request-side injection classes only.
- SecLists traversal lists contain many entries that are not attacks in any context (such as `..2f..2f`, with the `%` missing). Both WAFs are scored on them unchanged.

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
- Traversal detection on raw wordlists (64.5%) is the weakest category. The next step is a path canonicalizer that resolves `..` sequences against a virtual root.
- The ML stage from the original plan is not built yet: a character n-gram model trained on CSIC 2010, evaluated with a source-disjoint split.
- Benchmarks come from a low-end laptop, so absolute latency on server hardware will be lower.

## License

MIT
