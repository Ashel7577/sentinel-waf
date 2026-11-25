# Security policy

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/Ashel7577/sentinel-waf/security/advisories/new).
Include the request (raw HTTP is best), the Sentinel version (`waf -version` or the release tag), the
flags you ran it with, and what you expected to happen.

What to expect:

| Step | Target time |
|---|---|
| Acknowledgement | 3 working days |
| Triage and severity (CVSS v4) | 7 days |
| Fix or mitigation for critical / high issues | 30 days |
| Coordinated public advisory (GHSA, CVE where applicable) | with the fix release |

A **WAF bypass is in scope**: any request that delivers a payload Sentinel is documented to detect to the
upstream application without being blocked (at the default threshold and paranoia level 1), including
parser-differential and encoding bypasses. So are crashes, unbounded memory or CPU use triggered by a
request, evidence-chain forgery, and anything that lets an unauthenticated client reach the admin port.

Out of scope: payload classes listed under *Known gaps* in [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md),
findings that need the admin port exposed to the internet against the documented deployment, and
volumetric DoS.

Reporters are credited in the advisory unless they ask not to be.
