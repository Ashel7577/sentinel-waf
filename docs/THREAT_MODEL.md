# Threat model

This document states what Sentinel defends, against whom, where its guarantees end, and how each claim is
tested. It uses STRIDE for the WAF itself and an attacker-capability model for the traffic it inspects.

## 1. System and trust boundaries

```
 internet (untrusted)          Sentinel host (trusted)                      private network
┌──────────┐   :8080   ┌─────────────────────────────────────────┐   ┌─────────────────────┐
│  client  │ ────────► │ proxy: size limit → rate limit →        │──►│ upstream application │
└──────────┘           │ extract (parsediff readings) → normalize│   └─────────────────────┘
                       │ → analysers + rules → score → allow/403 │
                       │        │                                 │
                       │        ▼ evidence vault (hash chain)     │
                       │ admin :9090 (127.0.0.1 only):            │
                       │ dashboard, /stats, /metrics, /report     │
                       └─────────────────────────────────────────┘
```

| Boundary | Crossing | Trust |
|---|---|---|
| B1 client → proxy | every byte of the request | none: fully attacker-controlled |
| B2 proxy → upstream | the request Sentinel re-serialises | upstream trusts Sentinel's verdict |
| B3 operator → admin port | dashboard, reports, evidence | localhost only; no authentication of its own |
| B4 evidence file at rest | append-only JSONL | integrity checked by hash chain, not confidentiality |

## 2. Assets

1. The upstream application and its data (the thing being protected).
2. The availability of the proxy (it is in the request path).
3. The integrity of the evidence vault (it is what incident reports and disclosure rely on).
4. Secrets that pass through (cookies, Authorization headers): never written to evidence in clear.

## 3. Attacker model (traffic)

| Capability | In scope |
|---|---|
| Send arbitrary HTTP/1.1 requests: any method, path, headers, body, encoding | yes |
| Know Sentinel's source, rules and thresholds (open source, Kerckhoffs) | yes |
| Adaptively probe: observe 403 vs pass-through and mutate | yes |
| Choose the body structure to exploit parser differences (WAFFLED class) | yes, the parsediff guard's purpose |
| Smuggle via framing (CL/TE desync) | partly: Go's server resolves framing itself (Transfer-Encoding over Content-Length, RFC 9112), Sentinel reads the whole body before deciding, and the reverse proxy re-frames every request with its own Content-Length, so the upstream never sees the client's framing. Front-end proxies placed *before* Sentinel are outside this guarantee |
| Attack through HTTP/2-only features, gRPC, WebSockets after upgrade | not inspected (known gap) |
| Compromise the Sentinel host or the upstream directly | out of scope |

## 4. STRIDE for Sentinel itself

| Threat | Example | Mitigation | Test |
|---|---|---|---|
| **S**poofing | Fake client IP via `X-Forwarded-For` to dodge rate limits | XFF ignored unless `-trust-xff` (only behind a trusted LB) | `internal/server` tests |
| **T**ampering | Edit evidence to hide or invent an incident | SHA-256 hash chain, `Open` refuses to append to a broken chain, `sentinel-report verify` | `internal/evidence` tests (edit, delete, reorder) |
| **R**epudiation | "That request was never blocked" | Request ID returned to the client, evidence hash returned in the 403 body, chained record | attack lab evidence pack |
| **I**nformation disclosure | Evidence or logs leak session cookies | Cookie / Authorization stored only as truncated SHA-256 digests; admin port on localhost | `internal/evidence` test |
| **D**enial of service | Huge bodies, deep JSON, pathological multipart | body limit (413), `maxInputs` 512, JSON depth 32, part read cap, per-IP token bucket, bounded normalization passes | fuzzing (`FuzzBody`), unit tests |
| **E**levation of privilege | Reach the admin endpoints from outside | admin listener separate and bound to 127.0.0.1 by default | deployment docs |

## 5. Detection guarantees and their limits

Sentinel blocks a request when the anomaly score reaches the threshold (default 5 = one critical finding).

What is claimed, with the evidence behind it:

- **Union inspection**: a body field produced by any implemented reading (Go stdlib, strict, lenient
  multipart, relaxed JSON, `;`-split and comma-joined parameters) is inspected. Tested in
  `internal/parsediff` (`TestBypassClasses`, `TestGoReadingMatchesNetHTTP`).
- **Go fidelity**: the Go reading uses `mime/multipart`, `encoding/json` and `net/url` themselves, so for a
  Go upstream the WAF inspects exactly what the handler receives.
- **Detection rates** are measured, not asserted: built-in corpus, SecLists, GoTestWAF and the attack lab in
  CI, each against Coraza + OWASP CRS on identical requests.

Not claimed:

- Fidelity to parsers that are **not** modelled (custom parsers in application code, PHP's `$_POST` name
  mangling, Windows "best-fit" conversions after the WAF). The guard reduces, it does not remove,
  parser-differential risk for non-Go upstreams. A per-framework differential harness is the next step.
- Response-side inspection (data leaks, error pages): not implemented.
- Payloads delivered via channels Sentinel does not parse (WebSocket frames, gRPC, GraphQL field-level
  semantics beyond the JSON body).
- Resistance to a fully adaptive attacker with unlimited queries: no WAF has demonstrated this; Sentinel's
  adaptive evaluation is ongoing work.

## 6. Residual risks and operator responsibilities

- Run the admin port on localhost or behind authentication; it has none of its own.
- Use `-monitor` first on new applications, read `/report`, then enable blocking.
- Keep the upstream patched: a WAF is a compensating control, not a fix.
- Protect the evidence file's confidentiality (it holds request bodies); the hash chain proves integrity,
  not secrecy. Copy the head hash somewhere separate (ticket, chat) to make truncation of the tail
  detectable too.
