<div align="center">
  <img src="https://i.imgur.com/8PjFlfW.png" width="280" alt="SPIRE logo"/>

  # SPIRE

  **Spec Path Inspector & Recon Engine**

  ![Shell](https://img.shields.io/badge/shell-sh%2Fbash%2Fzsh-4c1d95?style=flat-square)
  ![Python](https://img.shields.io/badge/python-3.8%2B-10b981?style=flat-square)
  ![License](https://img.shields.io/badge/license-MIT-6d28d9?style=flat-square)

</div>

---

SPIRE automates the discovery and analysis of exposed Swagger, OpenAPI, and Spring Actuator endpoints across a target scope. It fuzzes for known spec and actuator paths, validates true positives through strict Content-Type and JSON structure checks, downloads the specs, parses every declared endpoint, and performs both static security analysis and live authentication probing — producing a full Markdown report.

Designed for API attack-surface enumeration during penetration tests and bug bounty assessments.

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
| 5 | FP filtering | Validates hits via Content-Type header and JSON structure; separates swagger and actuator findings into distinct output files |
| 6 | Spec download | Pulls raw spec files including multi-spec initializer configs |
| 7 | Static analysis | Parses endpoints, checks authentication, transports, CORS |
| 7b | Actuator assessment | Probes each discovered actuator URL live, assigns severity by endpoint type |
| 8 | Live testing | Auth probing and HTTP verb tampering on confirmed swagger URLs |
| 9 | Sensitive data | Scans specs for hardcoded secrets, JWTs, internal IPs, ARNs |
| 10 | Report | Generates `REPORT.md` and `findings.json` |

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
| `vuln-findings.txt` | Raw vulnerability data (JSON array) |
| `specs/` | Downloaded API specification files |

---

## False Positive Handling

Responses are rejected if the `Content-Type` header contains `text/html` (custom error pages). Remaining responses must either parse as valid JSON/YAML with both a version key (`openapi`/`swagger`) and a `paths` key, **or** match a recognised Spring Actuator JSON shape (`_links`, `activeProfiles`, `contexts`, `status+components`, `names`, `threads`, etc.). Catch-all 200 responses are additionally filtered by comparing against a baseline request to a non-existent path.

Swagger and actuator findings are written to separate output files so they do not contaminate each other's downstream pipelines.

---

## Findings Covered

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
| Spring Actuator root exposed (`/actuator`) | HIGH |
| Spring Actuator `/heapdump` exposed | CRITICAL |
| Spring Actuator `/env` or `/configprops` exposed | HIGH |
| Spring Actuator `/threaddump` or `/logfile` exposed | HIGH |
| Spring Actuator `/beans` or `/mappings` exposed | MEDIUM |
| Spring Actuator `/httptrace` or `/sessions` exposed | MEDIUM |
| Spring Actuator `/metrics`, `/prometheus` exposed | LOW |
| Spring Actuator `/info` or `/health` exposed | INFO |

---

## Spring Actuator Detection

SPIRE v2.3 adds dedicated Spring Actuator coverage across the full pipeline:

- **Wordlist** — 22 actuator paths included (`/actuator`, `/actuator/heapdump`, `/actuator/env`, `/manage/actuator`, `/api/actuator`, and more)
- **Phase 5** — Actuator JSON response shapes are recognised independently of OpenAPI structure; confirmed URLs are written to `actuator-found.txt` separately from swagger URLs
- **Phase 7b** — Every confirmed actuator URL is probed live; severity is assigned per endpoint type based on data exposure risk
- **Report** — A dedicated `Discovered Spring Actuator URLs` table and actuator-specific remediation entries are included in `REPORT.md` and `findings.json`

---

## License

MIT
