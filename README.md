<div align="center">
  <img src="https://i.imgur.com/8PjFlfW.png" width="280" alt="SPIRE logo"/>

  # SPIRE

  **Spec Path Inspector & Recon Engine**

  ![Shell](https://img.shields.io/badge/shell-sh%2Fbash%2Fzsh-4c1d95?style=flat-square)
  ![Python](https://img.shields.io/badge/python-3.8%2B-10b981?style=flat-square)
  ![License](https://img.shields.io/badge/license-MIT-6d28d9?style=flat-square)

</div>

---

SPIRE automates the discovery and analysis of exposed Swagger and OpenAPI specification endpoints across a target scope. It fuzzes for known spec paths, validates true positives through strict Content-Type and JSON structure checks, downloads the specs, parses every declared endpoint, and performs both static security analysis and live authentication probing — producing a full Markdown report.

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
| 2 | Host probing | Confirms live hosts via `httpx` |
| 3 | Wordlist | Builds 60-path swagger/openapi wordlist |
| 4 | Fuzzing | Runs `ffuf` across all live hosts × all paths |
| 5 | FP filtering | Validates hits via Content-Type header and JSON structure |
| 6 | Spec download | Pulls raw spec files including multi-spec initializer configs |
| 7 | Static analysis | Parses endpoints, checks authentication, transports, CORS |
| 8 | Live testing | Auth probing and HTTP verb tampering on confirmed URLs |
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
| `all-endpoints.txt` | Every parsed endpoint with method, path, and API name |
| `auth-test.txt` | HTTP status codes from live authentication probes |
| `vuln-findings.txt` | Raw vulnerability data (JSON array) |
| `specs/` | Downloaded API specification files |

---

## False Positive Handling

Responses are rejected if the `Content-Type` header contains `text/html` (custom error pages). Remaining responses must parse as valid JSON or YAML with both a version key (`openapi`/`swagger`) and a `paths` key present at the top level. Catch-all 200 responses are additionally filtered by comparing against a baseline request to a non-existent path.

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


