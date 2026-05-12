#!/usr/bin/env sh
# ============================================================
#  SPIRE - Spec Path Inspector & Recon Engine  v2.2
#
#  Input (any one of):
#    ./spire.sh domains.json          # JSON with domain/subdomains
#    ./spire.sh live.txt              # pre-probed URLs (http/https)
#    ./spire.sh targets.txt           # plain domain list
#    ./spire.sh api.example.com       # single domain
#
#  Options:
#    --threads N    (default: 40)
#    --timeout N    (default: 10)
#    --output DIR   (default: ./spire-results)
#
#  Shells: sh / bash / zsh / ksh / dash — callable from fish/nu/etc.
# ============================================================

# ─── Colors ──────────────────────────────────────────────────
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
D='\033[0;37m'
B='\033[1m'
N='\033[0m'

# ─── Defaults ────────────────────────────────────────────────
INPUT="$1"
OUTPUT_DIR="./spire-results"
THREADS=40
TIMEOUT=10
shift

while [ "$#" -gt 0 ]; do
  case "$1" in
    --threads) THREADS="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --output)  OUTPUT_DIR="$2"; shift ;;
    *) printf "${R}[!] Unknown option: %s${N}\n" "$1"; exit 1 ;;
  esac
  shift
done

# ─── Tool checks ─────────────────────────────────────────────
for tool in curl python3 ffuf httpx jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "${R}[!] Missing required tool: %s${N}\n" "$tool"
    exit 1
  fi
done

if [ -z "$INPUT" ]; then
  printf "${R}[!] Usage: %s <input> [--threads N] [--timeout N] [--output DIR]${N}\n" "$0"
  printf "    input: domains.json | live.txt | targets.txt | single.domain.com\n"
  exit 1
fi

# ─── Repeat a character N times ──────────────────────────────
repeat_char() {
  printf "%${1}s" "" | tr ' ' "$2"
}

# ─── Progress bar ─────────────────────────────────────────────
progress_bar() {
  _cur="$1"; _tot="$2"; _lbl="$3"
  _w=40
  _pct=0
  [ "$_tot" -gt 0 ] && _pct=$(( _cur * 100 / _tot ))
  _filled=$(( _cur * _w / ( _tot > 0 ? _tot : 1 ) ))
  _empty=$(( _w - _filled ))
  _bar=""; _i=0
  while [ "$_i" -lt "$_filled" ]; do _bar="${_bar}#"; _i=$(( _i + 1 )); done
  _i=0
  while [ "$_i" -lt "$_empty" ]; do _bar="${_bar}."; _i=$(( _i + 1 )); done
  printf "\r  [%s] %3d%%  %s" "$_bar" "$_pct" "$_lbl"
}

# ─── Spinner ─────────────────────────────────────────────────
SPINNER_PID=""
SPINNER_MSG=""

start_spinner() {
  SPINNER_MSG="$1"
  (
    while true; do
      for _c in '|' '/' '-' '\\'; do
        printf "\r  [%s] %s" "$_c" "$SPINNER_MSG"
        sleep 0.1
      done
    done
  ) &
  SPINNER_PID=$!
}

stop_spinner() {
  _done="${1:-$SPINNER_MSG}"
  if [ -n "$SPINNER_PID" ]; then
    kill "$SPINNER_PID" 2>/dev/null
    wait "$SPINNER_PID" 2>/dev/null
    SPINNER_PID=""
  fi
  _pad="$(repeat_char 80 ' ')"
  printf "\r%s\r" "$_pad"
  printf "  ${G}[+]${N} %s\n" "$_done"
}

# ─── Phase header ─────────────────────────────────────────────
phase_header() {
  _num="$1"; _lbl="$2"
  printf "\n${B}[ Phase %s / 10 ]  %s${N}\n" "$_num" "$_lbl"
  repeat_char 60 '-'; printf '\n'
}

# ─── Setup ────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR/specs" "$OUTPUT_DIR/logs"

TARGETS="$OUTPUT_DIR/targets.txt"
LIVE="$OUTPUT_DIR/live.txt"
LIVE_CLEAN="$OUTPUT_DIR/live-clean.txt"
FFUF_RAW="$OUTPUT_DIR/ffuf-raw.json"
REAL_SWAGGERS="$OUTPUT_DIR/real-swaggers.txt"
ENDPOINTS_FILE="$OUTPUT_DIR/all-endpoints.txt"
AUTH_RESULTS="$OUTPUT_DIR/auth-test.txt"
VULN_RESULTS="$OUTPUT_DIR/vuln-findings.txt"
SPECS_DIR="$OUTPUT_DIR/specs"
REPORT="$OUTPUT_DIR/REPORT.md"
JSON_REPORT="$OUTPUT_DIR/findings.json"
START_TIME=$(date +%s)

printf '' > "$REAL_SWAGGERS"
printf '' > "$ENDPOINTS_FILE"
printf '' > "$AUTH_RESULTS"
printf '[]' > "$VULN_RESULTS"

SEP="$(repeat_char 60 '=')"

printf "\n${B}SPIRE  --  Spec Path Inspector & Recon Engine  v2.2${N}\n"
printf "${D}%s${N}\n" "$SEP"
printf "  Input        : %s\n" "$INPUT"
printf "  Output dir   : %s\n" "$OUTPUT_DIR"
printf "  Threads      : %s\n" "$THREADS"
printf "  Timeout      : %ss\n" "$TIMEOUT"
printf "  Started      : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
printf "${D}%s${N}\n" "$SEP"

# ============================================================
# PHASE 1 – Parse input
# ============================================================
phase_header 1 "Detecting and loading input"

IS_LIVE=0

if [ -f "$INPUT" ]; then
  if grep -qE '^https?://' "$INPUT" 2>/dev/null; then
    IS_LIVE=1
    grep -E '^https?://' "$INPUT" | sort -u > "$LIVE_CLEAN"
    sed 's|https\?://||' "$LIVE_CLEAN" | cut -d'/' -f1 | sort -u > "$TARGETS"
    printf "  ${G}[+]${N} Pre-probed URL list detected\n"
  else
    _first=$(head -1 "$INPUT" | tr -d '[:space:]')
    case "$_first" in
      '['*|'{'*)
        jq -r '.[] | .domain, (.subdomains // [] | .[])?' "$INPUT" 2>/dev/null \
          | grep -Ev '^$|^#' | sort -u > "$TARGETS"
        printf "  ${G}[+]${N} JSON input detected\n"
        ;;
      *)
        grep -Ev '^$|^#' "$INPUT" | sort -u > "$TARGETS"
        printf "  ${G}[+]${N} Plain domain list detected\n"
        ;;
    esac
  fi
else
  printf '%s\n' "$INPUT" > "$TARGETS"
  printf "  ${G}[+]${N} Single target: %s\n" "$INPUT"
fi

TOTAL=$(wc -l < "$TARGETS" | tr -d ' ')
printf "  Unique targets loaded  : %s\n" "$TOTAL"

# ============================================================
# PHASE 2 – Probe live hosts (multi-step)
# ============================================================
#
#  Step 1  DNS pre-filter   — drop NX domains before any HTTP probe
#                             (dnsx → dig → python3 socket, first available)
#  Step 2  httpx pass 1     — ports 80, 443  (standard)
#  Step 3  httpx pass 2     — extended API ports
#  Step 4  curl fallback    — parallel Python probe for anything still missed
#  Step 5  merge            — deduplicate all results into live-clean.txt
#
# ============================================================
phase_header 2 "Probing live hosts"

if [ "$IS_LIVE" = "1" ]; then
  LIVE_COUNT=$(wc -l < "$LIVE_CLEAN" | tr -d ' ')
  printf "  ${G}[+]${N} Skipped -- input is already a probed URL list\n"
  printf "  Live hosts available   : %s\n" "$LIVE_COUNT"
else

  DNS_RESOLVED="$OUTPUT_DIR/dns-resolved.txt"
  LIVE_STD="$OUTPUT_DIR/live-std.txt"
  LIVE_EXT="$OUTPUT_DIR/live-ext.txt"
  LIVE_CURL="$OUTPUT_DIR/live-curl.txt"
  printf '' > "$DNS_RESOLVED"
  printf '' > "$LIVE_STD"
  printf '' > "$LIVE_EXT"
  printf '' > "$LIVE_CURL"

  # ── Step 1: DNS pre-filter ──────────────────────────────────
  printf "  [1/4] DNS resolution filter...\n"

  if command -v dnsx >/dev/null 2>&1; then
    dnsx -l "$TARGETS" -silent -o "$DNS_RESOLVED" 2>/dev/null
    printf "        dnsx: %s domains resolved\n" "$(wc -l < "$DNS_RESOLVED" | tr -d ' ')"
  else
    # dig or python3 socket fallback — parallel via Python
    SPIRE_TARGETS="$TARGETS" SPIRE_RESOLVED="$DNS_RESOLVED" \
    SPIRE_THREADS="$THREADS" python3 << 'DNSEOF'
import os, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

targets_f  = os.environ["SPIRE_TARGETS"]
resolved_f = os.environ["SPIRE_RESOLVED"]
workers    = max(1, int(os.environ.get("SPIRE_THREADS","40")))

domains = [l.strip() for l in open(targets_f) if l.strip() and not l.startswith("#")]
total   = len(domains)
ok      = []

def resolve(domain):
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, None)
        return domain
    except Exception:
        return None

done = 0
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(resolve, d): d for d in domains}
    for f in as_completed(futs):
        done += 1
        filled = done * 40 // max(total, 1)
        bar    = "#" * filled + "." * (40 - filled)
        pct    = done * 100 // max(total, 1)
        print(f"\r        [{bar}] {pct:3d}%  resolving...", end="", flush=True)
        r = f.result()
        if r:
            ok.append(r)

print()
with open(resolved_f, "w") as fh:
    for d in sorted(set(ok)):
        fh.write(d + "\n")

dropped = total - len(ok)
print(f"        socket: {len(ok)} resolved, {dropped} dropped (NXDOMAIN/timeout)")
DNSEOF
  fi

  RESOLVED_COUNT=$(wc -l < "$DNS_RESOLVED" | tr -d ' ')
  printf "  ${G}[+]${N} DNS resolved          : %s / %s\n" "$RESOLVED_COUNT" "$TOTAL"

  # ── Step 2: httpx — standard ports 80, 443 ─────────────────
  printf "  [2/4] httpx — standard ports (80, 443)...\n"
  httpx -l "$DNS_RESOLVED" \
    -ports 80,443 \
    -o "$LIVE_STD" \
    -timeout "$TIMEOUT" \
    -retries 3 \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -silent 2>/dev/null
  STD_COUNT=$(awk '{print $1}' "$LIVE_STD" | sort -u | wc -l | tr -d ' ')
  printf "  ${G}[+]${N} Standard ports hits   : %s\n" "$STD_COUNT"

  # ── Step 3: httpx — extended API ports ─────────────────────
  printf "  [3/4] httpx — extended API ports...\n"
  EXTENDED_PORTS="8080,8443,8000"
  httpx -l "$DNS_RESOLVED" \
    -ports "$EXTENDED_PORTS" \
    -o "$LIVE_EXT" \
    -timeout "$TIMEOUT" \
    -retries 2 \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -silent 2>/dev/null
  EXT_COUNT=$(awk '{print $1}' "$LIVE_EXT" | sort -u | wc -l | tr -d ' ')
  printf "  ${G}[+]${N} Extended ports hits   : %s\n" "$EXT_COUNT"

  # ── Step 4: curl fallback for missed domains ────────────────
  # Collect domains httpx confirmed, find which resolved domains
  # never appeared — probe those directly with curl.
  printf "  [4/4] curl fallback for unconfirmed domains...\n"

  SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'CURLEOF'
import os, subprocess, re
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ["SPIRE_OUT"]
workers  = max(1, int(os.environ.get("SPIRE_THREADS","40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT","10"))

# All resolved domains
try:
    resolved = set(l.strip() for l in open(f"{out_dir}/dns-resolved.txt") if l.strip())
except:
    resolved = set()

# Domains httpx already confirmed (extract host from URL)
confirmed = set()
for fname in ("live-std.txt", "live-ext.txt"):
    try:
        for line in open(f"{out_dir}/{fname}"):
            url = line.split()[0] if line.strip() else ""
            m = re.match(r'https?://([^/:]+)', url)
            if m:
                confirmed.add(m.group(1).lower())
    except:
        pass

# Domains httpx missed
missed = sorted(resolved - confirmed)

PROBE_PORTS   = [443, 80, 8443, 8080, 8000, 8888, 3000, 5000, 9000, 4443]
PROBE_SCHEMES = {443:"https", 80:"http", 8443:"https", 8080:"http",
                 8000:"http", 8888:"http", 3000:"http", 5000:"http",
                 9000:"http", 4443:"https"}

def probe(domain, port):
    scheme = PROBE_SCHEMES.get(port, "https")
    url    = f"{scheme}://{domain}" if port in (80,443) else f"{scheme}://{domain}:{port}"
    try:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", str(timeout), "--connect-timeout", "5",
             "-L", "--max-redirs", "3", url],
            capture_output=True, timeout=timeout + 5)
        code = r.stdout.decode().strip()
        # Any real HTTP response (including 4xx/5xx) means the host is live
        if code and code not in ("000", ""):
            return url, code
    except:
        pass
    return None, None

total   = len(missed)
done    = 0
found   = []
seen    = set()

tasks = [(d, p) for d in missed for p in PROBE_PORTS]

with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(probe, d, p): (d, p) for d, p in tasks}
    for f in as_completed(futs):
        domain, port = futs[f]
        if domain not in seen:
            done += 1
            filled = done * 40 // max(total, 1)
            bar    = "#" * filled + "." * (40 - filled)
            pct    = done * 100 // max(total, 1)
            print(f"\r        [{bar}] {pct:3d}%  {domain[:35]:<35}", end="", flush=True)
        url, code = f.result()
        if url and domain not in seen:
            seen.add(domain)
            found.append(url)

print()
with open(f"{out_dir}/live-curl.txt", "w") as fh:
    for u in sorted(set(found)):
        fh.write(u + "\n")

print(f"        curl fallback : {len(missed)} unchecked → {len(found)} additional live")
CURLEOF

  CURL_COUNT=$(wc -l < "$LIVE_CURL" | tr -d ' ')

  # ── Step 5: merge all sources into live-clean.txt ───────────
  {
    awk '{print $1}' "$LIVE_STD"
    awk '{print $1}' "$LIVE_EXT"
    cat "$LIVE_CURL"
  } | grep -E '^https?://' | sort -u > "$LIVE_CLEAN"

  # Also write a combined httpx-style LIVE file (used by later phases for tech/title)
  cat "$LIVE_STD" "$LIVE_EXT" > "$LIVE" 2>/dev/null

  LIVE_COUNT=$(wc -l < "$LIVE_CLEAN" | tr -d ' ')
  printf "\n"
  printf "  ${G}[+]${N} httpx std            : %s\n" "$STD_COUNT"
  printf "  ${G}[+]${N} httpx extended ports : %s\n" "$EXT_COUNT"
  printf "  ${G}[+]${N} curl fallback        : %s\n" "$CURL_COUNT"
  printf "  ${B}[+]${N} Total live hosts     : %s\n" "$LIVE_COUNT"

fi

# ============================================================
# PHASE 3 – Wordlist
# ============================================================
phase_header 3 "Building API path wordlist"

WORDLIST="$OUTPUT_DIR/swagger-paths.txt"
cat << 'PATHS' > "$WORDLIST"
swagger-ui.html
swagger-ui/index.html
swagger-ui/
swagger/index.html
swagger/
swagger.json
swagger.yaml
swagger.yml
api-docs
api-docs/
v1/api-docs
v2/api-docs
v3/api-docs
openapi.json
openapi.yaml
openapi.yml
openapi/
api/swagger-ui.html
api/swagger-ui/
api/swagger.json
api/swagger.yaml
api/openapi.json
api/openapi.yaml
api/openapi
api/docs
api/docs/
api/v1
api/v1/
api/v2
api/v2/
api/v3
api/v3/
docs
docs/
docs/api
documentation
documentation/
swagger/v1/swagger.json
swagger/v2/swagger.json
swagger/v3/swagger.json
swagger/v1/swagger.yaml
swagger/v2/swagger.yaml
swagger/v3/swagger.yaml
api-json
api-yaml
swagger-json
swagger-resources
swagger-resources/configuration/ui
swagger-resources/configuration/security
v3/api-docs/swagger-config
swagger/v3/api-docs/swagger-config.json
.well-known/openapi.json
.well-known/openapi.yaml
openapi/v1
openapi/v2
openapi/v3
api/swagger/ui/
rest/api-doc/
restapi/
rest/v1/api-docs
rest/v2/api-docs
rest/v3/api-docs
internal/docs
internal/api-docs
private/api-docs
admin/api-docs
admin/swagger
backend/api-docs
backend/swagger
service/api-docs
PATHS

PATH_COUNT=$(wc -l < "$WORDLIST" | tr -d ' ')
printf "  ${G}[+]${N} %s paths loaded\n" "$PATH_COUNT"

# ============================================================
# PHASE 4 – ffuf
# ============================================================
phase_header 4 "Fuzzing with ffuf"
start_spinner "Scanning $LIVE_COUNT hosts x $PATH_COUNT paths..."

ffuf -u "FUZZ1/FUZZ2" \
  -w "$LIVE_CLEAN:FUZZ1" \
  -w "$WORDLIST:FUZZ2" \
  -mc 200,201,204 \
  -t "$THREADS" \
  -timeout "$TIMEOUT" \
  -k \
  -o "$FFUF_RAW" \
  -of json \
  -s 2>/dev/null

RAW_HITS=$(python3 -c "
import json
try:    print(len(json.load(open('$FFUF_RAW')).get('results',[])))
except: print(0)
" 2>/dev/null)
stop_spinner "ffuf complete  ($RAW_HITS raw hits)"

# ============================================================
# PHASE 5 – False positive filter  [v2.2: threading + strict validation]
# ============================================================
phase_header 5 "Filtering false positives"

# ── What changed in v2.2 ──────────────────────────────────────
# OLD: sequential curl calls + loose keyword grep in HTML body
#      → custom 404 pages that contain words like "swagger" or "version"
#        were accepted as real findings (false positives)
#
# NEW: ThreadPoolExecutor (parallel) + two-gate validation:
#   Gate 1 – Content-Type header must contain json/yaml/openapi/octet-stream
#             A custom 404 page sends text/html → rejected immediately
#   Gate 2 – JSON/YAML parse with top-level key check:
#             body must be valid JSON with both ("openapi"|"swagger") AND "paths"
#             OR valid YAML with the same keys
#             A JSON error page or bare HTML never passes this gate
# ─────────────────────────────────────────────────────────────

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, subprocess, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT", "./spire-results")
workers  = max(1, int(os.environ.get("SPIRE_THREADS", "40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT", "10"))

try:
    data    = json.load(open(f"{out_dir}/ffuf-raw.json"))
    results = data.get("results", [])
except Exception as e:
    print(f"  [!] Cannot parse ffuf output: {e}")
    sys.exit(0)

# ── Gate helpers ─────────────────────────────────────────────
def content_type_ok(ct: str) -> bool:
    """True when Content-Type looks like a machine-readable spec, not HTML."""
    ct = ct.lower()
    return any(tok in ct for tok in (
        "json", "yaml", "openapi", "octet-stream", "x-yaml", "text/plain"
    )) and "html" not in ct

def body_is_spec(raw: bytes) -> bool:
    """
    True when the response body is a real OpenAPI/Swagger document.
    Tries JSON first, then falls back to a lightweight YAML key-scan
    (avoids a heavy PyYAML import that may not be available).
    """
    text = raw.decode("utf-8", errors="ignore")

    # ── JSON gate ────────────────────────────────────────────
    try:
        doc = json.loads(text)
        if not isinstance(doc, dict):
            return False
        has_version = "openapi" in doc or "swagger" in doc
        has_paths   = "paths" in doc
        return has_version and has_paths
    except json.JSONDecodeError:
        pass

    # ── Lightweight YAML key-scan (no import needed) ─────────
    # Real YAML specs always have top-level "openapi:" / "swagger:"
    # AND "paths:" — we look for them without a full parser.
    lines = text[:4000].splitlines()
    top_keys = set()
    for line in lines:
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            # top-level key = line with no leading spaces and a colon
            if line and line[0] not in (" ", "\t") and ":" in line:
                top_keys.add(line.split(":")[0].strip().lower())
    has_version = "openapi" in top_keys or "swagger" in top_keys
    has_paths   = "paths" in top_keys
    return has_version and has_paths

# ── Per-URL worker ────────────────────────────────────────────
def check_url(item):
    url  = item.get("url", "")
    size = item.get("length", 0)
    host = item.get("host") or url.split("/")[2] if "/" in url else url

    if size < 80:
        return None

    try:
        r = subprocess.run(
            ["curl", "-sk", url, "--max-time", str(timeout),
             "-D", "-",          # include response headers in stdout
             "--compressed"],
            capture_output=True, timeout=timeout + 5
        )
    except Exception:
        return None

    # Split headers from body
    raw = r.stdout
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        sep = b"\n\n"
        idx = raw.find(sep)

    if idx != -1:
        header_block = raw[:idx].decode("utf-8", errors="ignore")
        body         = raw[idx + len(sep):]
    else:
        header_block = ""
        body         = raw

    # Gate 1: Content-Type
    ct = ""
    for line in header_block.splitlines():
        if line.lower().startswith("content-type:"):
            ct = line.split(":", 1)[1].strip()
            break

    if ct and not content_type_ok(ct):
        return None   # text/html custom 404 → reject

    # Gate 2: body must parse as a real spec
    if not body_is_spec(body):
        return None

    return {"host": host, "url": url, "size": size}

# ── Baseline sizes (to catch catch-all 200s) ─────────────────
hosts_items = {}
for r in results:
    host = r.get("host") or r.get("url","").split("/")[2]
    hosts_items.setdefault(host, []).append(r)

baseline_sizes = {}
def get_baseline(host):
    try:
        r = subprocess.run(
            ["curl", "-sk", f"https://{host}/spire_nopath_1337_xyz",
             "--max-time", str(timeout)],
            capture_output=True, timeout=timeout + 5)
        return len(r.stdout)
    except Exception:
        return -1

# Fetch baselines in parallel
with ThreadPoolExecutor(max_workers=min(workers, len(hosts_items) or 1)) as ex:
    futs = {ex.submit(get_baseline, h): h for h in hosts_items}
    for f in as_completed(futs):
        baseline_sizes[futs[f]] = f.result()

# Filter out items whose size matches the catch-all baseline
flat_items = []
for host, items in hosts_items.items():
    bl = baseline_sizes.get(host, -1)
    for item in items:
        if item.get("length", 0) != bl:
            flat_items.append(item)

# ── Parallel validation ───────────────────────────────────────
total        = len(flat_items)
done_count   = 0
real_findings = []

with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(check_url, item): item for item in flat_items}
    for f in as_completed(futs):
        done_count += 1
        filled = done_count * 40 // max(total, 1)
        bar    = "#" * filled + "." * (40 - filled)
        pct    = done_count * 100 // max(total, 1)
        url_label = futs[f].get("url","")[:38]
        print(f"\r  [{bar}] {pct:3d}%  {url_label:<38}", end="", flush=True)
        result = f.result()
        if result:
            real_findings.append(result)

print()

with open(f"{out_dir}/real-swaggers.txt", "w") as f:
    for r in real_findings:
        f.write(r["url"] + "\n")

for r in real_findings:
    print(f"  [found]  {r['url']}  (size: {r['size']})")

print(f"\n  Confirmed endpoints    : {len(real_findings)}")
PYEOF

FOUND_COUNT=$(wc -l < "$REAL_SWAGGERS" | tr -d ' ')

# ============================================================
# PHASE 6 – Download specs  [v2.2: parallel downloads]
# ============================================================
phase_header 6 "Downloading API specs"

# ── What changed in v2.2 ──────────────────────────────────────
# OLD: sequential shell while-loop — one curl at a time
# NEW: ThreadPoolExecutor in Python — all URLs fetched in parallel
#      Same swagger-initializer.js resolution + sibling path probing,
#      but done concurrently across all confirmed swagger URLs.
# ─────────────────────────────────────────────────────────────

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, os, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir   = os.environ.get("SPIRE_OUT", "./spire-results")
workers   = max(1, int(os.environ.get("SPIRE_THREADS", "40")))
timeout   = int(os.environ.get("SPIRE_TIMEOUT", "10"))
specs_dir = f"{out_dir}/specs"

try:
    swagger_urls = [l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except:
    swagger_urls = []

def safe_name(url):
    import re
    return re.sub(r'[/:?=&]', '_', url)

def curl_get(url, max_time=None):
    try:
        r = subprocess.run(
            ["curl", "-sk", url, "--max-time", str(max_time or timeout)],
            capture_output=True, timeout=(max_time or timeout) + 5)
        return r.stdout
    except Exception:
        return b""

def is_spec(raw):
    try:
        d = json.loads(raw)
        return isinstance(d, dict) and ("openapi" in d or "swagger" in d)
    except:
        return False

def save_spec(raw, name):
    path = f"{specs_dir}/{name}.json"
    with open(path, "wb") as f:
        f.write(raw)

def process_url(url):
    saved = []
    host = url.split("/")[2] if "/" in url else url

    # 1. Check swagger-initializer.js for configUrl
    init_url    = url.rsplit("/", 1)[0] + "/swagger-initializer.js"
    init_body   = curl_get(init_url).decode("utf-8", errors="ignore")
    import re
    m = re.search(r'"configUrl"\s*:\s*"([^"]+)"', init_body)
    if m:
        config_url = m.group(1)
        if config_url.startswith("/"):
            config_url = f"https://{host}{config_url}"
        config_raw = curl_get(config_url)
        try:
            cfg = json.loads(config_raw)
            spec_urls = [u.get("url","") for u in cfg.get("urls",[])]
            if cfg.get("url"):
                spec_urls.append(cfg["url"])
            for su in spec_urls:
                if not su:
                    continue
                if su.startswith("/"):
                    su = f"https://{host}{su}"
                raw = curl_get(su, max_time=15)
                if is_spec(raw):
                    name = safe_name(su)
                    save_spec(raw, name)
                    saved.append(su)
        except Exception:
            pass

    # 2. Download the URL itself if it's a spec
    content = curl_get(url, max_time=15)
    if is_spec(content):
        save_spec(content, safe_name(url))
        saved.append(url)

    # 3. Probe common sibling spec paths
    for path in ("/v3/api-docs", "/v2/api-docs", "/openapi.json", "/swagger.json"):
        sib = curl_get(f"https://{host}{path}")
        if is_spec(sib):
            name = safe_name(f"https://{host}{path}")
            save_spec(sib, name)
            saved.append(f"https://{host}{path}")

    return url, saved

total      = len(swagger_urls)
done_count = 0

with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(process_url, url): url for url in swagger_urls}
    for f in as_completed(futs):
        done_count += 1
        filled = done_count * 40 // max(total, 1)
        bar    = "#" * filled + "." * (40 - filled)
        pct    = done_count * 100 // max(total, 1)
        url_label = futs[f][:38]
        print(f"\r  [{bar}] {pct:3d}%  {url_label:<38}", end="", flush=True)

print()

import glob
spec_count = len(glob.glob(f"{specs_dir}/*.json"))
print(f"  Spec files saved       : {spec_count}")
PYEOF

SPEC_COUNT=$(find "$SPECS_DIR" -name '*.json' -size +50c 2>/dev/null | wc -l | tr -d ' ')
printf "  ${G}[+]${N} %s spec files saved\n" "$SPEC_COUNT"

# ============================================================
# PHASE 7 – Static analysis
# ============================================================
phase_header 7 "Parsing endpoints and analyzing spec security"

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, os, glob, sys

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
specs_dir = f"{out_dir}/specs"
ep_file   = f"{out_dir}/all-endpoints.txt"
vuln_file = f"{out_dir}/vuln-findings.txt"

SENSITIVE_PARAMS = ["password","passwd","pwd","secret","token","api_key","apikey",
                    "access_key","private_key","auth","authorization","credit_card",
                    "card_number","cvv","ssn","pin","otp","session","cookie"]
SENSITIVE_PATHS  = ["/admin","/internal","/debug","/actuator","/health","/metrics",
                    "/env","/config","/management","/monitor","/private","/system",
                    "/user/list","/users/all","/dump","/export","/backup","/console"]
WRITE_METHODS    = ["DELETE","PUT","PATCH"]

spec_files    = sorted(glob.glob(f"{specs_dir}/*.json"))
total         = len(spec_files)
all_endpoints = []
vulns         = []

for idx, spec_file in enumerate(spec_files, 1):
    filled = idx * 40 // max(total, 1)
    bar    = "#" * filled + "." * (40 - filled)
    pct    = idx * 100 // max(total, 1)
    fname  = os.path.basename(spec_file)[:30]
    print(f"\r  [{bar}] {pct:3d}%  {fname:<30}", end="", flush=True)

    try:
        with open(spec_file) as f: data = json.load(f)
    except Exception:
        continue

    title    = data.get("info",{}).get("title","Unknown")
    base_paths = []
    if "servers" in data:
        for s in data["servers"]: base_paths.append(s.get("url",""))
    elif "host" in data:
        schemes = data.get("schemes",["https"])
        base_paths.append(f"{schemes[0]}://{data['host']}{data.get('basePath','')}")

    paths       = data.get("paths",{})
    global_sec  = data.get("security",[])
    sec_schemes = (data.get("components",{}).get("securitySchemes")
                   or data.get("securityDefinitions") or {})

    if not paths: continue

    if not sec_schemes:
        vulns.append({"severity":"HIGH","type":"No Security Schemes Defined",
                      "endpoint":"global","api":title,
                      "detail":"Spec defines no securitySchemes (no OAuth2/ApiKey/Bearer)"})

    for bp in base_paths:
        if bp.startswith("http://"):
            vulns.append({"severity":"HIGH","type":"Insecure Transport (HTTP)",
                          "endpoint":"server url","api":title,
                          "detail":f"Base URL uses plain HTTP: {bp}"})

    for path, methods_obj in paths.items():
        if not isinstance(methods_obj, dict): continue
        for method, op in methods_obj.items():
            mu = method.upper()
            if mu not in ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]: continue
            if not isinstance(op, dict): continue

            summary    = op.get("summary","")
            parameters = op.get("parameters",[])
            op_sec     = op.get("security",None)
            deprecated = op.get("deprecated",False)

            all_endpoints.append({"method":mu,"path":path,"summary":summary,
                                   "api":title,"deprecated":deprecated,
                                   "base":base_paths[0] if base_paths else ""})

            has_auth = bool(op_sec) if op_sec is not None else bool(global_sec)
            if not has_auth and mu in ["GET","POST","DELETE"]:
                vulns.append({"severity":"HIGH","type":"Missing Authentication",
                               "endpoint":f"{mu} {path}","api":title,
                               "detail":"No security scheme applied -- may be publicly accessible"})

            for param in parameters:
                if not isinstance(param, dict): continue
                pname = param.get("name","").lower()
                pin   = param.get("in","")
                for sp in SENSITIVE_PARAMS:
                    if sp in pname and pin in ["query","header","cookie"]:
                        vulns.append({"severity":"MEDIUM","type":"Sensitive Parameter in Request",
                                      "endpoint":f"{mu} {path}","api":title,
                                      "detail":f"'{param.get('name')}' via '{pin}' may be logged or cached"})

            if mu in WRITE_METHODS:
                for sp in SENSITIVE_PATHS:
                    if path.lower().startswith(sp):
                        vulns.append({"severity":"HIGH","type":"Dangerous Method on Sensitive Path",
                                      "endpoint":f"{mu} {path}","api":title,
                                      "detail":f"{mu} on privileged path -- risk of unauthorized mutation"})

            if deprecated:
                vulns.append({"severity":"INFO","type":"Deprecated Endpoint",
                               "endpoint":f"{mu} {path}","api":title,
                               "detail":"Marked deprecated -- may lack current security controls"})

            if mu == "OPTIONS":
                for code, resp in op.get("responses",{}).items():
                    if not isinstance(resp, dict): continue
                    for h, hval in resp.get("headers",{}).items():
                        if "access-control-allow-origin" in h.lower():
                            if isinstance(hval, dict):
                                val = hval.get("example","") or hval.get("default","")
                                if val == "*":
                                    vulns.append({"severity":"MEDIUM","type":"CORS Wildcard in Spec",
                                                  "endpoint":f"OPTIONS {path}","api":title,
                                                  "detail":"Spec declares Access-Control-Allow-Origin: *"})

print()

import re as _re
def _host(base):
    h = _re.sub(r'^https?://', '', base or "")
    return h.split("/")[0] or "unknown"

with open(ep_file,"w") as f:
    f.write(f"Total: {len(all_endpoints)} endpoints\n" + "-"*60 + "\n")
    for ep in all_endpoints:
        dep  = "  [DEPRECATED]" if ep["deprecated"] else ""
        host = _host(ep.get("base",""))
        f.write(f"  [{ep['method']:6}]  {host:<40}  {ep['path']}{dep}\n")

with open(vuln_file,"w") as f:
    json.dump(vulns, f, indent=2)

sev = {}
for v in vulns: sev[v["severity"]] = sev.get(v["severity"],0) + 1
print(f"  Endpoints parsed       : {len(all_endpoints)}")
print(f"  Issues found           :")
for s in ["HIGH","MEDIUM","LOW","INFO"]:
    if s in sev: print(f"    {s:<10} {sev[s]}")
PYEOF

# ============================================================
# PHASE 8 – Live auth + verb tampering  [v2.2: parallel]
# ============================================================
phase_header 8 "Live authentication and verb tampering"

# ── What changed in v2.2 ──────────────────────────────────────
# OLD: sequential curl calls inside a Python for-loop
# NEW: ThreadPoolExecutor — all auth probes and verb-tamper checks
#      run in parallel, dramatically reducing wall-clock time for
#      large swagger-URL lists.
# ─────────────────────────────────────────────────────────────

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, subprocess, os
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT", "./spire-results")
workers  = max(1, int(os.environ.get("SPIRE_THREADS", "40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT", "10"))
vuln_file = f"{out_dir}/vuln-findings.txt"
auth_file = f"{out_dir}/auth-test.txt"

try:    vulns = json.load(open(vuln_file))
except: vulns = []

try:    swagger_urls = [l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except: swagger_urls = []

def probe_code(method, url):
    try:
        r = subprocess.run(
            ["curl", "-sk", "-X", method, "-o", "/dev/null", "-w", "%{http_code}",
             url, "--max-time", str(timeout)],
            capture_output=True, timeout=timeout + 5)
        return r.stdout.decode().strip()
    except:
        return "ERR"

# ── Parallel auth probes ───────────────────────────────────────
total      = len(swagger_urls)
done_count = 0
live_results = []

with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(probe_code, "GET", url): url for url in swagger_urls}
    for f in as_completed(futs):
        done_count += 1
        filled = done_count * 40 // max(total, 1)
        bar    = "#" * filled + "." * (40 - filled)
        pct    = done_count * 100 // max(total, 1)
        url    = futs[f]
        code   = f.result()
        print(f"\r  [{bar}] {pct:3d}%  {url[:38]:<38}", end="", flush=True)
        status = ("OPEN"      if code == "200"                    else
                  "PROTECTED" if code in ("401","403")             else
                  "REDIRECT"  if code in ("301","302","307","308") else "OTHER")
        live_results.append({"url": url, "code": code, "status": status})

print()

# ── Parallel verb tampering (first 20 URLs) ───────────────────
print(f"\n  Verb tampering (first 20 endpoints, parallel)...")
VERB_METHODS = ["POST","PUT","DELETE","PATCH","OPTIONS"]
tamper_targets = [(m, url) for url in swagger_urls[:20] for m in VERB_METHODS]
tamper_vulns   = []

with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(probe_code, method, url): (method, url)
            for method, url in tamper_targets}
    for f in as_completed(futs):
        method, url = futs[f]
        code = f.result()
        if code not in ("405","404","400","501","000","","ERR"):
            print(f"  [verb]  {method} {url} -> {code}")
            tamper_vulns.append({
                "severity": "MEDIUM",
                "type":     "Unexpected HTTP Method Accepted",
                "endpoint": f"{method} {url}",
                "api":      "live-test",
                "detail":   f"Server returned {code} for {method} (expected 405)"
            })

vulns.extend(tamper_vulns)

with open(auth_file, "w") as f:
    f.write(f"{'URL':<70}  {'CODE':>4}  STATUS\n" + "-"*90 + "\n")
    for r in live_results:
        f.write(f"{r['url']:<70}  {r['code']:>4}  {r['status']}\n")

with open(vuln_file, "w") as f:
    json.dump(vulns, f, indent=2)

o = sum(1 for r in live_results if r["status"] == "OPEN")
p = sum(1 for r in live_results if r["status"] == "PROTECTED")
print(f"  Open (unauthenticated) : {o}")
print(f"  Protected (401/403)    : {p}")
PYEOF

# ============================================================
# PHASE 9 – Sensitive data in specs
# ============================================================
phase_header 9 "Scanning specs for sensitive data exposure"

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, os, glob, re

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
specs_dir = f"{out_dir}/specs"
vuln_file = f"{out_dir}/vuln-findings.txt"

try:    vulns = json.load(open(vuln_file))
except: vulns = []

PATTERNS = {
    "Hardcoded Secret or API Key":   r'(?i)(api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']',
    "Internal IP Address":           r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
    "AWS ARN":                       r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\']+',
    "JWT Token":                     r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    "Basic Auth Credentials in URL": r'https?://[^:@\s]+:[^:@\s]+@',
    "Email Address":                 r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "Verbose Example Field":         r'(?i)"example"\s*:\s*"[^"]{30,}"',
}

spec_files = sorted(glob.glob(f"{specs_dir}/*.json"))
total = len(spec_files)
found = 0

for idx, spec_file in enumerate(spec_files, 1):
    filled = idx * 40 // max(total, 1)
    bar    = "#" * filled + "." * (40 - filled)
    pct    = idx * 100 // max(total, 1)
    fname  = os.path.basename(spec_file)[:30]
    print(f"\r  [{bar}] {pct:3d}%  {fname:<30}", end="", flush=True)

    try:
        raw   = open(spec_file).read()
        title = json.loads(raw).get("info",{}).get("title","Unknown")
    except:
        continue

    for issue, pattern in PATTERNS.items():
        for m in re.findall(pattern, raw)[:5]:
            ms = m if isinstance(m, str) else m[0]
            if len(ms) < 6: continue
            sev = "HIGH" if any(k in issue for k in ["Secret","JWT","Basic Auth","AWS"]) else "MEDIUM"
            vulns.append({"severity":sev,
                          "type":f"Sensitive Data in Spec -- {issue}",
                          "endpoint":os.path.basename(spec_file),
                          "api":title,
                          "detail":f"Matched: {ms[:120]}"})
            found += 1

print()

with open(vuln_file,"w") as f:
    json.dump(vulns, f, indent=2)

print(f"  Sensitive data matches : {found}")
PYEOF

# ============================================================
# PHASE 10 – Report
# ============================================================
phase_header 10 "Generating report"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

SPIRE_OUT="$OUTPUT_DIR" SPIRE_INPUT="$INPUT" SPIRE_ELAPSED="$ELAPSED" python3 << 'PYEOF'
import json, os, glob, datetime

out_dir = os.environ.get("SPIRE_OUT","./spire-results")
inp     = os.environ.get("SPIRE_INPUT","")
elapsed = int(os.environ.get("SPIRE_ELAPSED","0"))

try:    vulns = json.load(open(f"{out_dir}/vuln-findings.txt"))
except: vulns = []

try:    swagger_urls = [l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except: swagger_urls = []

try:    auth_lines = open(f"{out_dir}/auth-test.txt").readlines()
except: auth_lines = []

try:
    ep_lines = [l for l in open(f"{out_dir}/all-endpoints.txt") if l.startswith("  [")]
    total_ep = len(ep_lines)
except:
    ep_lines = []; total_ep = 0

try:    total_t = open(f"{out_dir}/targets.txt").read().count("\n")
except: total_t = 0
try:    live_c  = open(f"{out_dir}/live-clean.txt").read().count("\n")
except: live_c  = 0

spec_count = len(glob.glob(f"{out_dir}/specs/*.json"))
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

sev = {}
for v in vulns: sev.setdefault(v.get("severity","INFO"),[]).append(v)

risk = (len(sev.get("CRITICAL",[])) * 10 + len(sev.get("HIGH",[])) * 7 +
        len(sev.get("MEDIUM",[])) * 4  + len(sev.get("LOW",[])) * 1)
rlbl = ("CRITICAL" if risk >= 50 else "HIGH" if risk >= 20
        else "MEDIUM" if risk >= 10 else "LOW" if risk >= 1 else "NONE")

L = []
L.append("# SPIRE -- Spec Path Inspector & Recon Engine")
L.append("## Scan Report\n")
L.append("| Field | Value |")
L.append("|-------|-------|")
L.append(f"| Generated | {now} |")
L.append(f"| Duration | {elapsed}s |")
L.append(f"| Input | `{inp}` |")
L.append(f"| Version | 2.2 |")
L.append(f"| Risk Score | {risk} ({rlbl}) |")

L.append("\n---\n")
L.append("## Executive Summary\n")
L.append("| Metric | Value |")
L.append("|--------|-------|")
L.append(f"| Targets Scanned | {total_t} |")
L.append(f"| Live Hosts | {live_c} |")
L.append(f"| Swagger / OpenAPI URLs Found | {len(swagger_urls)} |")
L.append(f"| Spec Files Downloaded | {spec_count} |")
L.append(f"| Endpoints Parsed | {total_ep} |")
L.append(f"| Total Issues | {len(vulns)} |")
for s in ["HIGH","MEDIUM","LOW","INFO"]:
    if s in sev: L.append(f"| {s} | {len(sev[s])} |")

L.append("\n---\n")
L.append("## Findings\n")

for severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
    items = sev.get(severity,[])
    if not items: continue
    L.append(f"### {severity}  ({len(items)})\n")
    by_type = {}
    for v in items: by_type.setdefault(v["type"],[]).append(v)
    for itype, findings in by_type.items():
        L.append(f"#### {itype}\n")
        L.append("| # | API | Endpoint | Detail |")
        L.append("|---|-----|----------|--------|")
        for i, v in enumerate(findings, 1):
            ep  = v.get("endpoint","").replace("|","/")
            det = v.get("detail","").replace("|","/")[:120]
            L.append(f"| {i} | {v.get('api','')} | `{ep}` | {det} |")
        L.append("")

L.append("\n---\n")
L.append("## Discovered Swagger / OpenAPI URLs\n")
L.append("| # | URL |")
L.append("|---|-----|")
for i, url in enumerate(swagger_urls, 1):
    L.append(f"| {i} | {url} |")

L.append("\n---\n")
L.append("## Live Authentication Test\n")
L.append("| URL | Code | Status |")
L.append("|-----|------|--------|")
for line in auth_lines[2:]:
    parts = [p.strip() for p in line.strip().split("  ") if p.strip()]
    if len(parts) >= 3:
        L.append(f"| {parts[0]} | {parts[1]} | {parts[2]} |")

L.append("\n---\n")
L.append("## All Parsed Endpoints\n")
L.append("| Method | Host | Path |")
L.append("|--------|------|------|")
import re as _re
for l in ep_lines[:500]:
    # line format: "  [METHOD]  host  /path  [DEPRECATED]"
    m = _re.match(r'\s+\[(\w+)\s*\]\s+(\S+)\s+(\/\S*)(.*)', l)
    if m:
        method, host, path, rest = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        dep = " `[DEPRECATED]`" if "DEPRECATED" in rest else ""
        L.append(f"| `{method}` | {host} | `{path}`{dep} |")
if total_ep > 500:
    L.append(f"\n_{total_ep - 500} more endpoints — see `all-endpoints.txt`_")

L.append("\n---\n")
L.append("## Remediation\n")
L.append("| Finding | Recommended Action |")
L.append("|---------|-------------------|")
for f, a in [
    ("Missing Authentication",             "Enforce OAuth2 / Bearer on all non-public endpoints"),
    ("No Security Schemes Defined",        "Define securitySchemes and apply globally via the security field"),
    ("Sensitive Parameter in Request",     "Move secrets to Authorization header; never query string or cookie"),
    ("Insecure Transport (HTTP)",          "Enforce HTTPS at the load balancer; reject all HTTP traffic"),
    ("CORS Wildcard",                      "Restrict Access-Control-Allow-Origin to an explicit allowlist"),
    ("Dangerous Method on Sensitive Path", "Require elevated roles for destructive methods on privileged paths"),
    ("Deprecated Endpoint",               "Decommission or apply identical hardening as current endpoints"),
    ("Hardcoded Secret or API Key",        "Rotate immediately; use a secrets manager, never embed in specs"),
    ("JWT Token",                          "Revoke the token; never include live credentials in spec examples"),
    ("Internal IP Address",               "Remove all internal network references from public-facing specs"),
    ("Unexpected HTTP Method Accepted",   "Return 405 for all disallowed HTTP verbs"),
]: L.append(f"| {f} | {a} |")

L.append("\n---\n")
L.append("## Output Files\n")
L.append("| File | Description |")
L.append("|------|-------------|")
for fn, desc in [
    ("real-swaggers.txt",  "Confirmed swagger/openapi URLs"),
    ("specs/",             "Downloaded API specification files"),
    ("all-endpoints.txt",  "All parsed endpoints with method and path"),
    ("auth-test.txt",      "Live HTTP response codes per swagger URL"),
    ("vuln-findings.txt",  "Raw vulnerability data (JSON)"),
    ("findings.json",      "Machine-readable summary"),
    ("REPORT.md",          "This report"),
]: L.append(f"| `{fn}` | {desc} |")

with open(f"{out_dir}/REPORT.md","w") as f:
    f.write("\n".join(L))

json.dump({"tool":"SPIRE","version":"2.2","scan_date":now,
           "duration_seconds":elapsed,"risk_score":risk,"risk_label":rlbl,
           "stats":{"targets":total_t,"live_hosts":live_c,
                    "swagger_urls":len(swagger_urls),"specs":spec_count,
                    "endpoints":total_ep,"issues":len(vulns)},
           "severity_breakdown":{k:len(v) for k,v in sev.items()},
           "swagger_urls":swagger_urls,"findings":vulns},
          open(f"{out_dir}/findings.json","w"), indent=2)

print("  REPORT.md written")
print("  findings.json written")
PYEOF

# ─── Final summary ────────────────────────────────────────────
ISSUE_COUNT=$(python3 -c "
import json
try:    print(len(json.load(open('$VULN_RESULTS'))))
except: print(0)
" 2>/dev/null)

printf '\n'
printf "${D}%s${N}\n" "$SEP"
printf "${B}  SPIRE scan complete${N}\n"
printf "${D}%s${N}\n" "$SEP"
printf "  ${G}[+]${N} Swagger URLs found   : %s\n" "$(wc -l < "$REAL_SWAGGERS" | tr -d ' ')"
printf "  ${G}[+]${N} Endpoints parsed     : %s\n" "$(grep -c '^\s*\[' "$ENDPOINTS_FILE" 2>/dev/null || printf 0)"
printf "  ${G}[+]${N} Issues flagged       : %s\n" "$ISSUE_COUNT"
printf "  ${G}[+]${N} Duration             : %ss\n" "$ELAPSED"
printf "  ${G}[+]${N} Output               : %s/\n" "$OUTPUT_DIR"
printf "${D}%s${N}\n" "$SEP"
printf '\n'
