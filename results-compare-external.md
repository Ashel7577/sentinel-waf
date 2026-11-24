## Sentinel WAF vs Coraza + OWASP CRS v4

Paranoia level 1 · block threshold 5 (both) · 4 placements per payload (query, form, JSON, header) · corpus `../../eval/external`

| Category | Payloads | Sentinel WAF | Coraza + OWASP CRS v4 |
|---|---|---|---|
| cmdi | 400 | 100.0% | 43.1% |
| sqli | 385 | 76.1% | 46.4% |
| traversal | 400 | 64.5% | 28.9% |
| xss | 220 | 98.6% | 94.4% |
| **all attacks** | | **83.1%** | **48.0%** |
| **false positives** (benign) | 1600 | **0.0%** (0) | **0.2%** (12) |

**By placement** (detection / false positives):

| Placement | Sentinel WAF | Coraza + OWASP CRS v4 |
|---|---|---|
| query | 83.1% / 0.0% | 55.7% / 0.2% |
| form | 83.1% / 0.0% | 55.7% / 0.2% |
| json | 83.1% / 0.0% | 55.7% / 0.2% |
| header | 83.1% / 0.0% | 25.0% / 0.0% |
| **query+form+json only** | **83.1% / 0.0%** | **55.7% / 0.2%** |

CRS at paranoia 1 does not inspect arbitrary custom request headers by design, which lowers its header column; the query+form+json row excludes that.

| Latency per request (in-process, parse + inspect) | mean | p50 | p99 |
|---|---|---|---|
| Sentinel WAF | 177µs | 0s | 8.022ms |
| Coraza + OWASP CRS v4 | 4.613ms | 3.612ms | 15.822ms |
