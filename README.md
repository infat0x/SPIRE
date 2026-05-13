<div align="center">
  <img src="https://i.imgur.com/8PjFlfW.png" width="280" alt="SPIRE logo"/>

  # SPIRE

  **Spec Path Inspector & Recon Engine**

  ![Shell](https://img.shields.io/badge/shell-sh%2Fbash%2Fzsh-4c1d95?style=flat-square)
  ![Python](https://img.shields.io/badge/python-3.8%2B-10b981?style=flat-square)
  ![License](https://img.shields.io/badge/license-MIT-6d28d9?style=flat-square)
  ![Version](https://img.shields.io/badge/version-2.4-f59e0b?style=flat-square)

</div>

---

SPIRE automates the discovery and analysis of exposed Swagger, OpenAPI, and Spring Actuator endpoints across a target scope. It fuzzes for known spec and actuator paths, validates true positives through strict Content-Type and JSON structure checks, downloads the specs, parses every declared endpoint, and performs both static security analysis and live authentication probing — producing a full Markdown report.

Designed for API attack-surface enumeration during penetration tests and bug bounty assessments. Unlike source-code scanners such as Snyk, SPIRE operates entirely on runtime-observable artifacts: live HTTP responses, spec metadata, and response headers. It finds what static analysis cannot.

---

## Requirements

| Tool | Purpose |
|------|---------|
| `curl` | HTTP probing and spec retrieval |
| `python3` | Validation, parsing, reporting (stdlib only) |
| `ffuf` | Path fuzzing |
| `httpx` | Live host probing |
| `jq` | JSON input parsing |

---

## Usage

```sh
chmod +x spire.sh

./spire.sh <input> [--threads N] [--timeout N] [--output DIR]
```

**Input formats**

| Format | Example |
|--------|---------|
| Single domain | `./spire.sh api.example.com` |
| Plain domain list | `./spire.sh targets.txt` |
| JSON with subdomains | `./spire.sh domains.json` |
| Pre-probed URL list | `./spire.sh live.txt` |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--threads` | `40` | Concurrent workers for fuzzing and validation |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--output` | `./spire-results` | Output directory |

---

## Phases

| # | Phase | Description |
|---|-------|-------------|
| 1 | Input detection | Parses JSON, plain list, URL list, or single target |
| 2 | Host probing | httpx on live hosts with status code, title, and tech detection |
| 3 | Wordlist | Builds 80+ path wordlist covering swagger, openapi, and Spring Actuator paths |
| 4 | Fuzzing | Runs `ffuf` across all live hosts × all paths |
| 5 | FP filtering | Validates hits via Content-Type header and JSON structure; separates swagger and actuator findings |
| 6 | Spec download | Pulls raw spec files including multi-spec initializer configs |
| 7 | Static analysis | Parses endpoints, checks authentication, transports, CORS |
| 7b | Actuator assessment | Probes each discovered actuator URL live, assigns severity by endpoint type |
| 8 | Live testing | Auth probing and HTTP verb tampering on confirmed swagger URLs |
| 9 | Sensitive data | Scans specs for hardcoded secrets, JWTs, internal IPs, ARNs |
| 10 | Versioning Graveyard | Detects old API versions still live on the server; flags auth regressions between versions |
| 11 | Hidden Endpoints | Generates path mutations from spec patterns and probes for undocumented endpoints |
| 12 | BOLA Surface | Maps all `{id}`-style path parameters as potential Broken Object Level Authorization points |
| 13 | JWT Confusion | Identifies JWT-secured endpoints and probes live with `alg:none` unsigned tokens |
| 14 | Mass Assignment | Inspects POST/PUT request schemas for dangerous fields (`role`, `isAdmin`, `permissions`, etc.) |
| 15 | Webhook Leakage | Parses `x-webhooks`, `callbacks`, and async channel definitions for internal URL and topic leakage |
| 16 | Header Mining | Fetches response headers to fingerprint frameworks, detect internal service leakage, and audit security headers |
| 17 | x-Extension Audit | Scans all `x-` custom fields for auth-disabled flags, role hints, beta markers, and dangerous annotations |
| 18 | Report | Generates `REPORT.md` and `findings.json` |

---

## Output

All results are written to the output directory (default: `./spire-results/`).

| File | Description |
|------|-------------|
| `REPORT.md` | Full scan report with findings, severity breakdown, remediation |
| `findings.json` | Machine-readable findings (risk score, stats, all issues) |
| `real-swaggers.txt` | Confirmed Swagger / OpenAPI URLs |
| `actuator-found.txt` | Confirmed Spring Actuator URLs |
| `all-endpoints.txt` | Every parsed endpoint with method, path, and API name |
| `auth-test.txt` | HTTP status codes from live authentication probes |
| `version-graveyard.txt` | Old API versions still alive; auth regression details |
| `hidden-endpoints.txt` | Undocumented endpoints discovered via path mutation |
| `bola-surface.txt` | Full map of `{id}`-style endpoints and their auth status |
| `jwt-surface.txt` | All JWT-secured endpoints with `alg:none` probe results |
| `mass-assignment.txt` | Request schemas containing privilege-escalation field names |
| `webhook-leakage.txt` | Webhook, callback, and async channel inventory with findings |
| `shadow-headers.txt` | Raw response headers and security header audit results |
| `xextension-issues.txt` | Full `x-` field inventory and inconsistency findings |
| `vuln-findings.txt` | Raw vulnerability data (JSON array) |
| `specs/` | Downloaded API specification files |

---

## False Positive Handling

Responses are rejected if the `Content-Type` header contains `text/html` (custom error pages). Remaining responses must either parse as valid JSON/YAML with both a version key (`openapi`/`swagger`) and a `paths` key, **or** match a recognised Spring Actuator JSON shape (`_links`, `activeProfiles`, `contexts`, `status+components`, `names`, `threads`, etc.). Catch-all 200 responses are additionally filtered by comparing against a baseline request to a non-existent path.

Swagger and actuator findings are written to separate output files so they do not contaminate each other's downstream pipelines.

---

## Findings Covered

### Core (v2.3)

| Category | Severity |
|----------|----------|
| Missing authentication on endpoints | HIGH |
| No security schemes defined in spec | HIGH |
| Insecure transport (HTTP base URL) | HIGH |
| Sensitive parameters in query string / cookie | MEDIUM |
| Dangerous HTTP methods on privileged paths | HIGH |
| CORS wildcard declared in spec | MEDIUM |
| Hardcoded secrets, API keys, JWT tokens | HIGH |
| AWS ARNs and internal IP addresses | MEDIUM |
| Deprecated endpoints | INFO |
| Unexpected HTTP verb acceptance (live) | MEDIUM |
| Spring Actuator root exposed | HIGH |
| Spring Actuator `/heapdump` exposed | CRITICAL |
| Spring Actuator `/env` or `/configprops` exposed | HIGH |
| Spring Actuator `/threaddump` or `/logfile` exposed | HIGH |
| Spring Actuator `/beans` or `/mappings` exposed | MEDIUM |
| Spring Actuator `/httptrace` or `/sessions` exposed | MEDIUM |
| Spring Actuator `/metrics`, `/prometheus` exposed | LOW |
| Spring Actuator `/info` or `/health` exposed | INFO |

### New in v2.4

| Category | Severity |
|----------|----------|
| Old API version still live (`/v1` while `/v3` is current) | HIGH |
| Auth regression — old version unauthenticated, current requires auth | CRITICAL |
| Undocumented endpoint responds with 200 (shadow endpoint) | HIGH |
| Undocumented endpoint responds with 401/403 (exists but protected) | MEDIUM |
| BOLA surface — `{id}` endpoint without authentication | HIGH |
| BOLA surface — `{id}` endpoint with authentication (manual review) | MEDIUM |
| JWT `alg:none` accepted live — critical auth bypass | CRITICAL |
| JWT endpoint returns unexpected code with unsigned token | HIGH |
| JWKS URI exposed in spec | MEDIUM |
| Mass assignment — dangerous field in request schema | HIGH |
| Webhook callback contains internal URL | HIGH |
| Sensitive async topic or channel name exposed | HIGH / MEDIUM |
| Outdated / EOL framework version in response header | HIGH |
| Internal service name leaked via response header | MEDIUM |
| CORS wildcard confirmed live (runtime, not just in spec) | HIGH |
| HSTS header missing on API endpoint | MEDIUM |
| Rate limiting headers absent | LOW |
| `x-auth-required: false` annotation in spec | HIGH |
| `x-internal: true` endpoint without auth scheme | HIGH |
| `x-beta` / `x-preview` endpoint (reduced security review risk) | MEDIUM |
| Dangerous `x-bypass` / `x-debug` annotation in public spec | HIGH |

---

## What SPIRE Finds That Snyk Cannot

Snyk analyzes source code and declared dependencies. It operates before deployment and has no visibility into runtime behavior, live configuration, or spec metadata. SPIRE fills that gap:

| Capability | Snyk | SPIRE |
|------------|------|-------|
| Source code vulnerability scanning | ✓ | — |
| Dependency CVE detection | ✓ | — |
| Exposed swagger / openapi URL discovery | — | ✓ |
| Old API version still live on server | — | ✓ |
| Auth regression between API versions | — | ✓ |
| Undocumented endpoint discovery | — | ✓ |
| BOLA surface mapping from spec | — | ✓ |
| JWT `alg:none` live probe | — | ✓ |
| Mass assignment field detection in spec schema | — | ✓ |
| Webhook / async channel internal URL leakage | — | ✓ |
| Response header security audit | — | ✓ |
| `x-` extension inconsistency analysis | — | ✓ |
| Spring Actuator live risk assessment | — | ✓ |

---

## Spring Actuator Detection

SPIRE adds dedicated Spring Actuator coverage across the full pipeline:

- **Wordlist** — 22 actuator paths included (`/actuator`, `/actuator/heapdump`, `/actuator/env`, `/manage/actuator`, `/api/actuator`, and more)
- **Phase 5** — Actuator JSON response shapes are recognised independently of OpenAPI structure; confirmed URLs are written to `actuator-found.txt` separately from swagger URLs
- **Phase 7b** — Every confirmed actuator URL is probed live; severity is assigned per endpoint type based on data exposure risk
- **Report** — A dedicated `Discovered Spring Actuator URLs` table and actuator-specific remediation entries are included in `REPORT.md` and `findings.json`

---

## License

MIT
