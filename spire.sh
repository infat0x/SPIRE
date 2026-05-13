#!/usr/bin/env sh
# ============================================================
#  SPIRE - Spec Path Inspector & Recon Engine  v2.4
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
#  Shells: sh / bash / zsh / ksh / dash
#
#  v2.4 new phases:
#    10 - API Versioning Graveyard
#    11 - Hidden Endpoint Extraction
#    12 - BOLA Surface Mapping
#    13 - JWT Algorithm Confusion Surface
#    14 - Mass Assignment Surface
#    15 - Async / Webhook Leakage
#    16 - Shadow API via Response Header Mining
#    17 - OpenAPI x- Extension Inconsistency
#    18 - Report (was 10)
# ============================================================

R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
D='\033[0;37m'
B='\033[1m'
N='\033[0m'

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

for tool in curl python3 ffuf httpx jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "${R}[!] Missing required tool: %s${N}\n" "$tool"
    exit 1
  fi
done

if [ -z "$INPUT" ]; then
  printf "${R}[!] Usage: %s <input> [--threads N] [--timeout N] [--output DIR]${N}\n" "$0"
  exit 1
fi

repeat_char() { printf "%${1}s" "" | tr ' ' "$2"; }

phase_header() {
  printf "\n${B}[ Phase %s / 18 ]  %s${N}\n" "$1" "$2"
  repeat_char 60 '-'; printf '\n'
}

SPINNER_PID=""
SPINNER_MSG=""

start_spinner() {
  SPINNER_MSG="$1"
  ( while true; do
      for _c in '|' '/' '-' '\\'; do
        printf "\r  [%s] %s" "$_c" "$SPINNER_MSG"
        sleep 0.1
      done
    done ) &
  SPINNER_PID=$!
}

stop_spinner() {
  _done="${1:-$SPINNER_MSG}"
  [ -n "$SPINNER_PID" ] && kill "$SPINNER_PID" 2>/dev/null && wait "$SPINNER_PID" 2>/dev/null
  SPINNER_PID=""
  printf "\r%80s\r" ""
  printf "  ${G}[+]${N} %s\n" "$_done"
}

# ─── Setup ────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR/specs" "$OUTPUT_DIR/logs"

TARGETS="$OUTPUT_DIR/targets.txt"
LIVE="$OUTPUT_DIR/live.txt"
LIVE_CLEAN="$OUTPUT_DIR/live-clean.txt"
FFUF_RAW="$OUTPUT_DIR/ffuf-raw.json"
REAL_SWAGGERS="$OUTPUT_DIR/real-swaggers.txt"
ACTUATOR_FOUND="$OUTPUT_DIR/actuator-found.txt"
ENDPOINTS_FILE="$OUTPUT_DIR/all-endpoints.txt"
AUTH_RESULTS="$OUTPUT_DIR/auth-test.txt"
VULN_RESULTS="$OUTPUT_DIR/vuln-findings.txt"
SPECS_DIR="$OUTPUT_DIR/specs"
REPORT="$OUTPUT_DIR/REPORT.md"
JSON_REPORT="$OUTPUT_DIR/findings.json"
# v2.4 new output files
VERSION_GRAVEYARD="$OUTPUT_DIR/version-graveyard.txt"
HIDDEN_ENDPOINTS="$OUTPUT_DIR/hidden-endpoints.txt"
BOLA_MAP="$OUTPUT_DIR/bola-surface.txt"
SHADOW_HEADERS="$OUTPUT_DIR/shadow-headers.txt"
MASS_ASSIGN="$OUTPUT_DIR/mass-assignment.txt"
WEBHOOK_LEAK="$OUTPUT_DIR/webhook-leakage.txt"
XEXT_REPORT="$OUTPUT_DIR/xextension-issues.txt"
JWT_SURFACE="$OUTPUT_DIR/jwt-surface.txt"
START_TIME=$(date +%s)

for f in "$REAL_SWAGGERS" "$ACTUATOR_FOUND" "$ENDPOINTS_FILE" "$AUTH_RESULTS" \
         "$VERSION_GRAVEYARD" "$HIDDEN_ENDPOINTS" "$BOLA_MAP" "$SHADOW_HEADERS" \
         "$MASS_ASSIGN" "$WEBHOOK_LEAK" "$XEXT_REPORT" "$JWT_SURFACE"; do
  printf '' > "$f"
done
printf '[]' > "$VULN_RESULTS"

SEP="$(repeat_char 60 '=')"
printf "\n${B}SPIRE  --  Spec Path Inspector & Recon Engine  v2.4${N}\n"
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
# PHASE 2 – Probe live hosts
# ============================================================
phase_header 2 "Probing live hosts"

if [ "$IS_LIVE" = "1" ]; then
  LIVE_COUNT=$(wc -l < "$LIVE_CLEAN" | tr -d ' ')
  printf "  ${G}[+]${N} Skipped -- input is already a probed URL list\n"
  printf "  Live hosts available   : %s\n" "$LIVE_COUNT"
else
  start_spinner "Running httpx on $TOTAL hosts..."
  httpx -l "$TARGETS" -o "$LIVE" -timeout "$TIMEOUT" -retries 2 \
    -status-code -title -tech-detect -silent 2>/dev/null
  awk '{print $1}' "$LIVE" | sort -u > "$LIVE_CLEAN"
  LIVE_COUNT=$(wc -l < "$LIVE_CLEAN" | tr -d ' ')
  stop_spinner "httpx complete"
  printf "  Live hosts confirmed   : %s\n" "$LIVE_COUNT"
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
actuator
actuator/
actuator/health
actuator/env
actuator/beans
actuator/mappings
actuator/metrics
actuator/info
actuator/logfile
actuator/heapdump
actuator/threaddump
actuator/conditions
actuator/configprops
actuator/auditevents
actuator/httptrace
actuator/scheduledtasks
actuator/prometheus
actuator/flyway
actuator/liquibase
actuator/sessions
actuator/caches
actuator/integrationgraph
manage/actuator
manage/health
manage/env
spring/actuator
api/actuator
admin/actuator
app/actuator
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
# PHASE 5 – False positive filter
# ============================================================
phase_header 5 "Filtering false positives"

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

def content_type_ok(ct):
    ct = ct.lower()
    return any(tok in ct for tok in ("json","yaml","openapi","octet-stream","x-yaml","text/plain")) \
           and "html" not in ct

def body_is_spec(raw):
    text = raw.decode("utf-8", errors="ignore")
    try:
        doc = json.loads(text)
        if not isinstance(doc, dict): return None, None
        if ("openapi" in doc or "swagger" in doc) and "paths" in doc:
            return "swagger", doc
        if "_links" in doc and isinstance(doc["_links"], dict):
            if any(isinstance(v, dict) and "href" in v for v in doc["_links"].values()):
                return "actuator", doc
        if "activeProfiles" in doc or "propertySources" in doc: return "actuator", doc
        if "contexts" in doc and isinstance(doc["contexts"], dict): return "actuator", doc
        if "status" in doc and ("components" in doc or "details" in doc): return "actuator", doc
        if "names" in doc or "measurements" in doc: return "actuator", doc
        if "threads" in doc and isinstance(doc["threads"], list): return "actuator", doc
        if "cron" in doc or "fixedDelay" in doc or "fixedRate" in doc: return "actuator", doc
        if "cacheManagers" in doc: return "actuator", doc
        if "sessions" in doc: return "actuator", doc
        return None, None
    except json.JSONDecodeError:
        pass
    lines = text[:4000].splitlines()
    top_keys = set()
    for line in lines:
        s = line.lstrip()
        if s and not s.startswith("#") and line and line[0] not in (" ","\t") and ":" in line:
            top_keys.add(line.split(":")[0].strip().lower())
    if ("openapi" in top_keys or "swagger" in top_keys) and "paths" in top_keys:
        return "swagger", None
    return None, None

def check_url(item):
    url  = item.get("url","")
    size = item.get("length",0)
    host = item.get("host") or (url.split("/")[2] if "/" in url else url)
    if size < 80: return None
    try:
        r = subprocess.run(["curl","-sk",url,"--max-time",str(timeout),"-D","-","--compressed"],
                           capture_output=True, timeout=timeout+5)
    except: return None
    raw = r.stdout
    sep = b"\r\n\r\n"; idx = raw.find(sep)
    if idx == -1: sep = b"\n\n"; idx = raw.find(sep)
    if idx != -1:
        hdr  = raw[:idx].decode("utf-8",errors="ignore")
        body = raw[idx+len(sep):]
    else:
        hdr = ""; body = raw
    ct = ""
    for line in hdr.splitlines():
        if line.lower().startswith("content-type:"):
            ct = line.split(":",1)[1].strip(); break
    if ct and not content_type_ok(ct): return None
    kind, _ = body_is_spec(body)
    if kind is None: return None
    return {"host":host,"url":url,"size":size,"type":kind}

hosts_items = {}
for r in results:
    host = r.get("host") or r.get("url","").split("/")[2]
    hosts_items.setdefault(host,[]).append(r)

def get_baseline(host):
    try:
        r = subprocess.run(["curl","-sk",f"https://{host}/spire_nopath_1337_xyz","--max-time",str(timeout)],
                           capture_output=True,timeout=timeout+5)
        return len(r.stdout)
    except: return -1

baseline_sizes = {}
with ThreadPoolExecutor(max_workers=min(workers,len(hosts_items) or 1)) as ex:
    futs = {ex.submit(get_baseline,h):h for h in hosts_items}
    for f in as_completed(futs): baseline_sizes[futs[f]] = f.result()

flat_items = []
for host, items in hosts_items.items():
    bl = baseline_sizes.get(host,-1)
    for item in items:
        if item.get("length",0) != bl: flat_items.append(item)

total = len(flat_items); done_count = 0; real_findings = []
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(check_url,item):item for item in flat_items}
    for f in as_completed(futs):
        done_count += 1
        bar = "#"*(done_count*40//max(total,1)) + "."*(40-done_count*40//max(total,1))
        pct = done_count*100//max(total,1)
        print(f"\r  [{bar}] {pct:3d}%  {futs[f].get('url','')[:38]:<38}", end="", flush=True)
        result = f.result()
        if result: real_findings.append(result)
print()

swagger_findings  = [r for r in real_findings if r["type"]=="swagger"]
actuator_findings = [r for r in real_findings if r["type"]=="actuator"]

with open(f"{out_dir}/real-swaggers.txt","w") as f:
    [f.write(r["url"]+"\n") for r in swagger_findings]
with open(f"{out_dir}/actuator-found.txt","w") as f:
    [f.write(r["url"]+"\n") for r in actuator_findings]

for r in swagger_findings:  print(f"  [swagger ]  {r['url']}  (size: {r['size']})")
for r in actuator_findings: print(f"  [actuator]  {r['url']}  (size: {r['size']})")
print(f"\n  Confirmed swagger      : {len(swagger_findings)}")
print(f"  Confirmed actuator     : {len(actuator_findings)}")
PYEOF

FOUND_COUNT=$(wc -l < "$REAL_SWAGGERS" | tr -d ' ')
ACTUATOR_COUNT=$(wc -l < "$ACTUATOR_FOUND" | tr -d ' ')

# ============================================================
# PHASE 6 – Download specs
# ============================================================
phase_header 6 "Downloading API specs"

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, os, re, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
workers   = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout   = int(os.environ.get("SPIRE_TIMEOUT","10"))
specs_dir = f"{out_dir}/specs"

try:    swagger_urls = [l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except: swagger_urls = []

def safe_name(url): return re.sub(r'[/:?=&]','_',url)

def curl_get(url, max_time=None):
    try:
        r = subprocess.run(["curl","-sk",url,"--max-time",str(max_time or timeout)],
                           capture_output=True,timeout=(max_time or timeout)+5)
        return r.stdout
    except: return b""

def is_spec(raw):
    try:
        d = json.loads(raw)
        return isinstance(d,dict) and ("openapi" in d or "swagger" in d)
    except: return False

def save_spec(raw,name):
    with open(f"{specs_dir}/{name}.json","wb") as f: f.write(raw)

def process_url(url):
    saved=[]; host=url.split("/")[2] if "/" in url else url
    init_url  = url.rsplit("/",1)[0]+"/swagger-initializer.js"
    init_body = curl_get(init_url).decode("utf-8",errors="ignore")
    m = re.search(r'"configUrl"\s*:\s*"([^"]+)"',init_body)
    if m:
        config_url = m.group(1)
        if config_url.startswith("/"): config_url = f"https://{host}{config_url}"
        config_raw = curl_get(config_url)
        try:
            cfg       = json.loads(config_raw)
            spec_urls = [u.get("url","") for u in cfg.get("urls",[])]
            if cfg.get("url"): spec_urls.append(cfg["url"])
            for su in spec_urls:
                if not su: continue
                if su.startswith("/"): su = f"https://{host}{su}"
                raw = curl_get(su,max_time=15)
                if is_spec(raw): save_spec(raw,safe_name(su)); saved.append(su)
        except: pass
    content = curl_get(url,max_time=15)
    if is_spec(content): save_spec(content,safe_name(url)); saved.append(url)
    for path in ("/v3/api-docs","/v2/api-docs","/openapi.json","/swagger.json"):
        sib = curl_get(f"https://{host}{path}")
        if is_spec(sib):
            save_spec(sib,safe_name(f"https://{host}{path}")); saved.append(f"https://{host}{path}")
    return url, saved

total=len(swagger_urls); done_count=0
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs = {ex.submit(process_url,url):url for url in swagger_urls}
    for f in as_completed(futs):
        done_count+=1
        bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
        pct=done_count*100//max(total,1)
        print(f"\r  [{bar}] {pct:3d}%  {futs[f][:38]:<38}",end="",flush=True)
print()

import glob
spec_count=len(glob.glob(f"{specs_dir}/*.json"))
print(f"  Spec files saved       : {spec_count}")
PYEOF

SPEC_COUNT=$(find "$SPECS_DIR" -name '*.json' -size +50c 2>/dev/null | wc -l | tr -d ' ')
printf "  ${G}[+]${N} %s spec files saved\n" "$SPEC_COUNT"

# ============================================================
# PHASE 7 – Static analysis
# ============================================================
phase_header 7 "Parsing endpoints and analyzing spec security"

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, os, glob

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
WRITE_METHODS = ["DELETE","PUT","PATCH"]

spec_files=sorted(glob.glob(f"{specs_dir}/*.json"))
total=len(spec_files); all_endpoints=[]; vulns=[]

for idx, spec_file in enumerate(spec_files,1):
    bar="#"*(idx*40//max(total,1))+"."*(40-idx*40//max(total,1))
    pct=idx*100//max(total,1)
    print(f"\r  [{bar}] {pct:3d}%  {os.path.basename(spec_file)[:30]:<30}",end="",flush=True)
    try:
        with open(spec_file) as f: data=json.load(f)
    except: continue
    title   = data.get("info",{}).get("title","Unknown")
    base_paths=[]
    if "servers" in data:
        for s in data["servers"]: base_paths.append(s.get("url",""))
    elif "host" in data:
        schemes=data.get("schemes",["https"])
        base_paths.append(f"{schemes[0]}://{data['host']}{data.get('basePath','')}")
    paths      = data.get("paths",{})
    global_sec = data.get("security",[])
    sec_schemes= (data.get("components",{}).get("securitySchemes") or
                  data.get("securityDefinitions") or {})
    if not paths: continue
    if not sec_schemes:
        vulns.append({"severity":"HIGH","type":"No Security Schemes Defined",
                      "endpoint":"global","api":title,
                      "detail":"Spec defines no securitySchemes"})
    for bp in base_paths:
        if bp.startswith("http://"):
            vulns.append({"severity":"HIGH","type":"Insecure Transport (HTTP)",
                          "endpoint":"server url","api":title,"detail":f"Base URL uses HTTP: {bp}"})
    for path, methods_obj in paths.items():
        if not isinstance(methods_obj,dict): continue
        for method, op in methods_obj.items():
            mu=method.upper()
            if mu not in ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]: continue
            if not isinstance(op,dict): continue
            parameters = op.get("parameters",[])
            op_sec     = op.get("security",None)
            deprecated = op.get("deprecated",False)
            all_endpoints.append({"method":mu,"path":path,"summary":op.get("summary",""),
                                   "api":title,"deprecated":deprecated,
                                   "base":base_paths[0] if base_paths else ""})
            has_auth = bool(op_sec) if op_sec is not None else bool(global_sec)
            if not has_auth and mu in ["GET","POST","DELETE"]:
                vulns.append({"severity":"HIGH","type":"Missing Authentication",
                               "endpoint":f"{mu} {path}","api":title,
                               "detail":"No security scheme applied"})
            for param in parameters:
                if not isinstance(param,dict): continue
                pname=param.get("name","").lower(); pin=param.get("in","")
                for sp in SENSITIVE_PARAMS:
                    if sp in pname and pin in ["query","header","cookie"]:
                        vulns.append({"severity":"MEDIUM","type":"Sensitive Parameter in Request",
                                      "endpoint":f"{mu} {path}","api":title,
                                      "detail":f"'{param.get('name')}' via '{pin}'"})
            if mu in WRITE_METHODS:
                for sp in SENSITIVE_PATHS:
                    if path.lower().startswith(sp):
                        vulns.append({"severity":"HIGH","type":"Dangerous Method on Sensitive Path",
                                      "endpoint":f"{mu} {path}","api":title,
                                      "detail":f"{mu} on privileged path"})
            if deprecated:
                vulns.append({"severity":"INFO","type":"Deprecated Endpoint",
                               "endpoint":f"{mu} {path}","api":title,"detail":"Marked deprecated"})
print()

import re as _re
def _host(base):
    h=_re.sub(r'^https?://','',base or "")
    return h.split("/")[0] or "unknown"

with open(ep_file,"w") as f:
    f.write(f"Total: {len(all_endpoints)} endpoints\n"+"-"*60+"\n")
    for ep in all_endpoints:
        dep="  [DEPRECATED]" if ep["deprecated"] else ""
        f.write(f"  [{ep['method']:6}]  {_host(ep.get('base','')):<40}  {ep['path']}{dep}\n")

with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
sev={}
for v in vulns: sev[v["severity"]]=sev.get(v["severity"],0)+1
print(f"  Endpoints parsed       : {len(all_endpoints)}")
print(f"  Issues found           :")
for s in ["HIGH","MEDIUM","LOW","INFO"]:
    if s in sev: print(f"    {s:<10} {sev[s]}")
PYEOF

# ============================================================
# PHASE 7b – Spring Actuator Risk Assessment
# ============================================================
phase_header "7b" "Spring Actuator endpoint risk assessment"

SPIRE_OUT="$OUTPUT_DIR" SPIRE_TIMEOUT="$TIMEOUT" SPIRE_THREADS="$THREADS" python3 << 'PYEOF'
import json, subprocess, os, re
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
timeout   = int(os.environ.get("SPIRE_TIMEOUT","10"))
workers   = max(1,int(os.environ.get("SPIRE_THREADS","40")))
vuln_file = f"{out_dir}/vuln-findings.txt"
try:    vulns=json.load(open(vuln_file))
except: vulns=[]
try:    actuator_urls=[l.strip() for l in open(f"{out_dir}/actuator-found.txt") if l.strip()]
except: actuator_urls=[]

if not actuator_urls:
    print("  No actuator endpoints to assess.")
    with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
    exit(0)

ACTUATOR_RISK = {
    "heapdump":        ("CRITICAL","JVM heap dump -- full memory export, credentials may be visible"),
    "threaddump":      ("HIGH",    "Thread dump -- internal class/method names exposed"),
    "env":             ("HIGH",    "Environment variables -- may contain API keys, DB passwords"),
    "configprops":     ("HIGH",    "Configuration properties -- secret leakage risk"),
    "logfile":         ("HIGH",    "Log file readable -- credentials/PII leakage risk"),
    "flyway":          ("HIGH",    "Flyway migration history -- DB schema details exposed"),
    "liquibase":       ("HIGH",    "Liquibase migration history -- DB schema details exposed"),
    "beans":           ("MEDIUM",  "All Spring beans visible -- architecture recon"),
    "mappings":        ("MEDIUM",  "All HTTP mappings visible -- hidden endpoint discovery"),
    "httptrace":       ("MEDIUM",  "HTTP trace history -- token/session leakage risk"),
    "auditevents":     ("MEDIUM",  "Audit events -- usernames and actions visible"),
    "sessions":        ("MEDIUM",  "Active sessions visible -- session hijacking risk"),
    "integrationgraph":("MEDIUM",  "Spring Integration graph exposed"),
    "conditions":      ("LOW",     "Auto-configuration conditions report exposed"),
    "scheduledtasks":  ("LOW",     "Scheduled task details exposed"),
    "caches":          ("LOW",     "Cache manager details exposed"),
    "prometheus":      ("LOW",     "Prometheus metrics exposed"),
    "metrics":         ("LOW",     "Metrics endpoint open"),
    "info":            ("INFO",    "Build/version information exposed"),
    "health":          ("INFO",    "Health status endpoint open"),
}

def probe_actuator(url):
    url_lower=url.lower()
    matched=next((k for k in ACTUATOR_RISK if f"/{k}" in url_lower or url_lower.endswith(k)),None)
    try:
        r=subprocess.run(["curl","-sk","-o","/dev/null","-w","%{http_code}",url,"--max-time",str(timeout)],
                         capture_output=True,timeout=timeout+5)
        code=r.stdout.decode().strip()
    except: code="ERR"
    if code!="200": return None
    if matched:
        sev,detail=ACTUATOR_RISK[matched]
        return {"severity":sev,"type":f"Spring Actuator Exposed -- /{matched}",
                "endpoint":url,"api":"spring-actuator","detail":f"HTTP 200  |  {detail}"}
    if "actuator" in url_lower:
        try:
            r2=subprocess.run(["curl","-sk",url,"--max-time",str(timeout)],
                              capture_output=True,timeout=timeout+5)
            body=r2.stdout.decode("utf-8",errors="ignore")
        except: body=""
        if "_links" in body:
            exposed=re.findall(r'"([a-z\-]+)":\s*\{[^}]*"href"',body)
            return {"severity":"HIGH","type":"Spring Actuator Root Exposed",
                    "endpoint":url,"api":"spring-actuator",
                    "detail":f"HTTP 200  |  Exposed: {', '.join(exposed[:15])}"}
    return None

total=len(actuator_urls); done_count=0; new_vulns=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(probe_actuator,url):url for url in actuator_urls}
    for f in as_completed(futs):
        done_count+=1
        bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
        pct=done_count*100//max(total,1)
        print(f"\r  [{bar}] {pct:3d}%  {futs[f][:38]:<38}",end="",flush=True)
        result=f.result()
        if result: new_vulns.append(result)
print()

sev_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
for v in sorted(new_vulns,key=lambda x:sev_order.get(x["severity"],9)):
    print(f"  [{v['severity']:<8}]  {v['endpoint']}")
vulns.extend(new_vulns)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"\n  Actuator URLs assessed : {total}")
print(f"  Risk findings added    : {len(new_vulns)}")
PYEOF

# ============================================================
# PHASE 8 – Live auth + verb tampering
# ============================================================
phase_header 8 "Live authentication and verb tampering"

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, subprocess, os
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
workers   = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout   = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file = f"{out_dir}/vuln-findings.txt"
auth_file = f"{out_dir}/auth-test.txt"
try:    vulns=json.load(open(vuln_file))
except: vulns=[]
try:    swagger_urls=[l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except: swagger_urls=[]

def probe_code(method,url):
    try:
        r=subprocess.run(["curl","-sk","-X",method,"-o","/dev/null","-w","%{http_code}",
                          url,"--max-time",str(timeout)],capture_output=True,timeout=timeout+5)
        return r.stdout.decode().strip()
    except: return "ERR"

total=len(swagger_urls); done_count=0; live_results=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(probe_code,"GET",url):url for url in swagger_urls}
    for f in as_completed(futs):
        done_count+=1
        bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
        pct=done_count*100//max(total,1)
        url=futs[f]; code=f.result()
        print(f"\r  [{bar}] {pct:3d}%  {url[:38]:<38}",end="",flush=True)
        status=("OPEN" if code=="200" else
                "PROTECTED" if code in ("401","403") else
                "REDIRECT"  if code in ("301","302","307","308") else "OTHER")
        live_results.append({"url":url,"code":code,"status":status})
print()

print(f"\n  Verb tampering (first 20 endpoints, parallel)...")
VERB_METHODS=["POST","PUT","DELETE","PATCH","OPTIONS"]
tamper_targets=[(m,url) for url in swagger_urls[:20] for m in VERB_METHODS]
tamper_vulns=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(probe_code,method,url):(method,url) for method,url in tamper_targets}
    for f in as_completed(futs):
        method,url=futs[f]; code=f.result()
        if code not in ("405","404","400","501","000","","ERR"):
            print(f"  [verb]  {method} {url} -> {code}")
            tamper_vulns.append({"severity":"MEDIUM","type":"Unexpected HTTP Method Accepted",
                                  "endpoint":f"{method} {url}","api":"live-test",
                                  "detail":f"Server returned {code} for {method} (expected 405)"})
vulns.extend(tamper_vulns)

with open(auth_file,"w") as f:
    f.write(f"{'URL':<70}  {'CODE':>4}  STATUS\n"+"-"*90+"\n")
    for r in live_results:
        f.write(f"{r['url']:<70}  {r['code']:>4}  {r['status']}\n")
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)

o=sum(1 for r in live_results if r["status"]=="OPEN")
p=sum(1 for r in live_results if r["status"]=="PROTECTED")
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
try:    vulns=json.load(open(vuln_file))
except: vulns=[]

PATTERNS = {
    "Hardcoded Secret or API Key":   r'(?i)(api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']',
    "Internal IP Address":           r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
    "AWS ARN":                       r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"\']+',
    "JWT Token":                     r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    "Basic Auth Credentials in URL": r'https?://[^:@\s]+:[^:@\s]+@',
    "Email Address":                 r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "Verbose Example Field":         r'(?i)"example"\s*:\s*"[^"]{30,}"',
}

spec_files=sorted(glob.glob(f"{specs_dir}/*.json"))
total=len(spec_files); found=0
for idx, spec_file in enumerate(spec_files,1):
    bar="#"*(idx*40//max(total,1))+"."*(40-idx*40//max(total,1))
    pct=idx*100//max(total,1)
    print(f"\r  [{bar}] {pct:3d}%  {os.path.basename(spec_file)[:30]:<30}",end="",flush=True)
    try:
        raw=open(spec_file).read()
        title=json.loads(raw).get("info",{}).get("title","Unknown")
    except: continue
    for issue, pattern in PATTERNS.items():
        for m in re.findall(pattern,raw)[:5]:
            ms=m if isinstance(m,str) else m[0]
            if len(ms)<6: continue
            sev="HIGH" if any(k in issue for k in ["Secret","JWT","Basic Auth","AWS"]) else "MEDIUM"
            vulns.append({"severity":sev,"type":f"Sensitive Data in Spec -- {issue}",
                          "endpoint":os.path.basename(spec_file),"api":title,
                          "detail":f"Matched: {ms[:120]}"})
            found+=1
print()
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  Sensitive data matches : {found}")
PYEOF

# ============================================================
# PHASE 10 – API Versioning Graveyard
# ============================================================
phase_header 10 "API Versioning Graveyard -- old version auth bypass"

# Finds deprecated API versions still live on the server.
# Old versions often lack new auth middleware, rate limiting, input validation.
# Strategy:
#   1. Parse all-endpoints.txt for versioned paths (/v1/, /v2/, /v3/, etc.)
#   2. Identify max version per host (that's the "current" one)
#   3. Probe older versions live — if they return 200, flag HIGH
#   4. Compare HTTP status between versions to detect auth downgrade

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, re, subprocess, os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir   = os.environ.get("SPIRE_OUT","./spire-results")
workers   = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout   = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file = f"{out_dir}/vuln-findings.txt"
out_file  = f"{out_dir}/version-graveyard.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

import glob
spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))

# Collect versioned paths per base host
# Structure: { host: { version_int: [path, ...] } }
host_versions = defaultdict(lambda: defaultdict(list))

for spec_file in spec_files:
    try:
        data=json.load(open(spec_file))
    except: continue
    # Determine base host
    base=""
    if "servers" in data:
        base=data["servers"][0].get("url","") if data["servers"] else ""
    elif "host" in data:
        schemes=data.get("schemes",["https"])
        base=f"{schemes[0]}://{data['host']}{data.get('basePath','')}"
    host_match=re.sub(r'^https?://','',base).split('/')[0]
    if not host_match: continue

    for path in data.get("paths",{}).keys():
        m=re.search(r'/v(\d+)/',path)
        if m:
            v=int(m.group(1))
            host_versions[host_match][v].append(path)

if not host_versions:
    print("  No versioned endpoints found in specs.")
    with open(out_file,"w") as f: f.write("No versioned endpoints found.\n")
    with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
    exit(0)

# Build probe list: for each host, find current (max) version and probe older ones
probes=[]  # (host, old_version, current_version, sample_paths)
for host, versions in host_versions.items():
    if len(versions)<2: continue
    max_ver=max(versions.keys())
    for ver, paths in versions.items():
        if ver<max_ver:
            probes.append((host,ver,max_ver,paths[:3]))

print(f"  Version pairs to probe : {len(probes)}")

def probe_version(host,old_ver,cur_ver,paths):
    findings=[]
    for path in paths:
        old_path=re.sub(r'/v\d+/',f'/v{old_ver}/',path)
        cur_path=re.sub(r'/v\d+/',f'/v{cur_ver}/',path)
        old_url=f"https://{host}{old_path}"
        cur_url=f"https://{host}{cur_path}"
        def get_code(url):
            try:
                r=subprocess.run(["curl","-sk","-o","/dev/null","-w","%{http_code}",
                                  url,"--max-time",str(timeout)],
                                 capture_output=True,timeout=timeout+5)
                return r.stdout.decode().strip()
            except: return "ERR"
        old_code=get_code(old_url)
        cur_code=get_code(cur_url)
        if old_code in ("200","201","204"):
            # Old version still alive
            if cur_code in ("401","403") and old_code=="200":
                # Auth regression! Current requires auth, old does not
                findings.append({
                    "severity":"CRITICAL",
                    "type":"API Versioning Graveyard -- Auth Regression",
                    "endpoint":old_url,
                    "api":host,
                    "detail":f"v{old_ver} returns {old_code} (no auth) but v{cur_ver} returns {cur_code} -- auth bypass possible"
                })
            else:
                findings.append({
                    "severity":"HIGH",
                    "type":"API Versioning Graveyard -- Old Version Live",
                    "endpoint":old_url,
                    "api":host,
                    "detail":f"v{old_ver} still responds {old_code}; current v{cur_ver} returns {cur_code}. May lack new security controls."
                })
    return findings

total=len(probes); done_count=0; all_new_vulns=[]
graveyard_lines=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(probe_version,*p):p for p in probes}
    for f in as_completed(futs):
        done_count+=1
        bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
        pct=done_count*100//max(total,1)
        p=futs[f]
        print(f"\r  [{bar}] {pct:3d}%  {p[0][:38]:<38}",end="",flush=True)
        results=f.result()
        for r in results:
            all_new_vulns.append(r)
            graveyard_lines.append(f"[{r['severity']:<8}]  {r['endpoint']}\n    {r['detail']}\n")
print()

with open(out_file,"w") as f:
    f.write(f"API Versioning Graveyard -- {len(all_new_vulns)} findings\n"+"="*60+"\n")
    for line in graveyard_lines: f.write(line+"\n")

for v in all_new_vulns:
    print(f"  [{v['severity']:<8}]  {v['endpoint']}")

vulns.extend(all_new_vulns)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"\n  Graveyard findings     : {len(all_new_vulns)}")
PYEOF

# ============================================================
# PHASE 11 – Hidden Endpoint Extraction
# ============================================================
phase_header 11 "Hidden endpoint extraction from spec path patterns"

# Takes real spec paths and generates likely-but-undocumented mutations.
# /api/v1/users  →  probes /api/v1/users/export, /bulk, /admin, /search, /count etc.
# Undocumented endpoints often bypass auth and lack rate limiting.

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, re, subprocess, os, glob
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
workers  = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/hidden-endpoints.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

# Suffixes to append to each collection path
SHADOW_SUFFIXES=[
    "export","export.csv","export.json","export.xlsx",
    "bulk","bulk-delete","bulk-update","bulk-create",
    "admin","internal","debug","test",
    "search","query","filter","find",
    "count","stats","statistics","summary","report",
    "all","list","dump","backup",
    "import","upload","download",
    "token","refresh","verify","validate",
    "reset","disable","enable","activate","deactivate",
]

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))

# Extract collection paths (paths not ending in {param})
candidate_bases=set()
for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    base_url=""
    if "servers" in data and data["servers"]:
        base_url=data["servers"][0].get("url","").rstrip("/")
    elif "host" in data:
        schemes=data.get("schemes",["https"])
        base_url=f"{schemes[0]}://{data['host']}{data.get('basePath','')}".rstrip("/")
    if not base_url: continue
    for path in data.get("paths",{}).keys():
        # Skip paths ending in a parameter
        if path.rstrip("/").endswith("}"):  continue
        # Skip very short or very deep paths
        parts=[p for p in path.split("/") if p]
        if len(parts)<1 or len(parts)>5: continue
        candidate_bases.add(base_url+path.rstrip("/"))

probes=[(base,suffix) for base in candidate_bases for suffix in SHADOW_SUFFIXES]
print(f"  Candidate bases        : {len(candidate_bases)}")
print(f"  Total probes           : {len(probes)}")

def probe_hidden(base,suffix):
    url=f"{base}/{suffix}"
    try:
        r=subprocess.run(["curl","-sk","-o","/dev/null","-w","%{http_code}",
                          url,"--max-time",str(timeout)],
                         capture_output=True,timeout=timeout+5)
        code=r.stdout.decode().strip()
    except: return None
    # Accept 200,201,204 but NOT 401/403 (those are "protected but exist" -- still note them)
    if code in ("200","201","204"):
        return {"severity":"HIGH","type":"Hidden / Shadow Endpoint Found",
                "endpoint":url,"api":base.split("/")[2],
                "detail":f"Undocumented path returned HTTP {code} -- not in spec"}
    if code in ("401","403"):
        return {"severity":"MEDIUM","type":"Hidden Endpoint -- Auth Required",
                "endpoint":url,"api":base.split("/")[2],
                "detail":f"Undocumented path returns {code} -- exists but protected, verify it's intentional"}
    return None

total=len(probes); done_count=0; new_vulns=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(probe_hidden,base,suf):(base,suf) for base,suf in probes}
    for f in as_completed(futs):
        done_count+=1
        if done_count%50==0 or done_count==total:
            bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
            pct=done_count*100//max(total,1)
            b,s=futs[f]
            print(f"\r  [{bar}] {pct:3d}%  {(b+'/'+s)[:38]:<38}",end="",flush=True)
        result=f.result()
        if result: new_vulns.append(result)
print()

with open(out_file,"w") as f:
    f.write(f"Hidden Endpoint Extraction -- {len(new_vulns)} findings\n"+"="*60+"\n")
    for v in new_vulns:
        f.write(f"[{v['severity']:<8}]  {v['endpoint']}\n    {v['detail']}\n\n")

for v in new_vulns[:20]:
    print(f"  [{v['severity']:<8}]  {v['endpoint']}")
if len(new_vulns)>20:
    print(f"  ... ({len(new_vulns)-20} more in hidden-endpoints.txt)")

vulns.extend(new_vulns)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"\n  Hidden endpoints found : {len(new_vulns)}")
PYEOF

# ============================================================
# PHASE 12 – BOLA Surface Mapping
# ============================================================
phase_header 12 "BOLA surface mapping -- object-level authorization risk"

# Extracts all spec paths containing {id}, {userId}, {orderId}, etc.
# Each one is a potential Broken Object Level Authorization point.
# Snyk can't see this because it's a runtime concern — which ID belongs to whom.
# SPIRE maps the surface so pentesters/auditors know where to focus.

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, re, os, glob

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/bola-surface.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

# Parameter names that indicate object-level ID
ID_PATTERNS=re.compile(
    r'\{('
    r'id|[a-z_]*[Ii][dD]|[a-z_]*_id|uuid|guid|'
    r'user[_\-]?id|account[_\-]?id|order[_\-]?id|product[_\-]?id|'
    r'customer[_\-]?id|org[_\-]?id|tenant[_\-]?id|doc[_\-]?id|'
    r'record[_\-]?id|item[_\-]?id|resource[_\-]?id|entity[_\-]?id'
    r')\}'
)

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))
bola_endpoints=[]

for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    title=data.get("info",{}).get("title","Unknown")
    base_url=""
    if "servers" in data and data["servers"]:
        base_url=data["servers"][0].get("url","").rstrip("/")
    elif "host" in data:
        schemes=data.get("schemes",["https"])
        base_url=f"{schemes[0]}://{data['host']}{data.get('basePath','')}".rstrip("/")

    for path, methods_obj in data.get("paths",{}).items():
        if not isinstance(methods_obj,dict): continue
        m=ID_PATTERNS.search(path)
        if not m: continue
        param_name=m.group(1)
        for method, op in methods_obj.items():
            mu=method.upper()
            if mu not in ["GET","PUT","PATCH","DELETE"]: continue
            if not isinstance(op,dict): continue
            has_auth=bool(op.get("security")) or bool(data.get("security",[]))
            bola_endpoints.append({
                "method":mu,"path":path,"param":param_name,
                "api":title,"base":base_url,"has_auth":has_auth,
                "summary":op.get("summary","")
            })
            severity="HIGH" if not has_auth else "MEDIUM"
            vulns.append({
                "severity":severity,
                "type":"BOLA Surface -- Object-Level Authorization Risk",
                "endpoint":f"{mu} {path}",
                "api":title,
                "detail":f"Path param '{{{param_name}}}' -- verify per-object ownership check exists"
                         + (" [NO AUTH ON ENDPOINT]" if not has_auth else "")
            })

with open(out_file,"w") as f:
    f.write(f"BOLA Surface Map -- {len(bola_endpoints)} endpoints\n"+"="*60+"\n")
    f.write(f"{'METHOD':<8}  {'PARAM':<20}  {'AUTH':<5}  PATH\n"+"-"*80+"\n")
    for ep in bola_endpoints:
        auth_str="YES" if ep["has_auth"] else "NO "
        f.write(f"{ep['method']:<8}  {'{'+ep['param']+'}':<20}  {auth_str:<5}  {ep['path']}\n")

with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  BOLA surface endpoints : {len(bola_endpoints)}")
print(f"  (see bola-surface.txt for full map)")
PYEOF

# ============================================================
# PHASE 13 – JWT Algorithm Confusion Surface
# ============================================================
phase_header 13 "JWT algorithm confusion surface"

# Finds all JWT-secured endpoints from securitySchemes.
# Then probes live with:
#   1. alg:none token (unsigned) → if 200, critical auth bypass
#   2. Checks if spec exposes public key material (jwks_uri)
# Snyk sees the code; SPIRE tests the runtime behavior.

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, re, os, glob, base64, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
workers  = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/jwt-surface.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

# Build a minimal alg:none JWT (unsigned)
def make_alg_none_token():
    header =base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    payload=base64.urlsafe_b64encode(b'{"sub":"spire-test","iat":1700000000,"exp":9999999999}').rstrip(b'=').decode()
    return f"{header}.{payload}."

ALG_NONE_TOKEN=make_alg_none_token()

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))
jwt_endpoints=[]
new_vulns=[]

for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    title=data.get("info",{}).get("title","Unknown")
    sec_schemes=(data.get("components",{}).get("securitySchemes") or
                 data.get("securityDefinitions") or {})
    base_url=""
    if "servers" in data and data["servers"]:
        base_url=data["servers"][0].get("url","").rstrip("/")
    elif "host" in data:
        schemes_list=data.get("schemes",["https"])
        base_url=f"{schemes_list[0]}://{data['host']}{data.get('basePath','')}".rstrip("/")

    # Check for JWT schemes
    jwt_scheme_names=set()
    for name, scheme in sec_schemes.items():
        if not isinstance(scheme,dict): continue
        bf=(scheme.get("bearerFormat","") or "").upper()
        stype=(scheme.get("type","") or "").lower()
        sname=name.lower()
        if bf=="JWT" or "jwt" in sname or ("bearer" in stype and "jwt" in str(scheme).lower()):
            jwt_scheme_names.add(name)
        # Check for exposed JWKS URI
        flows=scheme.get("flows",{}) or {}
        for flow_name, flow in flows.items():
            if isinstance(flow,dict):
                authz_url=flow.get("authorizationUrl","")
                if authz_url:
                    new_vulns.append({"severity":"INFO","type":"JWT OAuth2 Flow Detected",
                                      "endpoint":f"scheme:{name}","api":title,
                                      "detail":f"Authorization URL: {authz_url}"})
        # x-jwks-uri or openIdConnectUrl
        jwks=scheme.get("openIdConnectUrl","") or scheme.get("x-jwks-uri","")
        if jwks:
            new_vulns.append({"severity":"MEDIUM","type":"JWKS URI Exposed in Spec",
                               "endpoint":f"scheme:{name}","api":title,
                               "detail":f"JWKS URI: {jwks} -- verify it doesn't expose private key material"})

    if not jwt_scheme_names: continue

    # Collect endpoints that use JWT schemes
    for path, methods_obj in data.get("paths",{}).items():
        if not isinstance(methods_obj,dict): continue
        for method, op in methods_obj.items():
            mu=method.upper()
            if mu not in ["GET","POST","PUT","DELETE","PATCH"]: continue
            if not isinstance(op,dict): continue
            op_sec=op.get("security",[]) or data.get("security",[])
            for sec_req in op_sec:
                if any(k in jwt_scheme_names for k in sec_req.keys()):
                    url=f"{base_url}{path}" if base_url else None
                    jwt_endpoints.append({"method":mu,"path":path,"url":url,"api":title})
                    break

print(f"  JWT-secured endpoints  : {len(jwt_endpoints)}")

# Probe first 30 endpoints with alg:none token
probe_targets=[ep for ep in jwt_endpoints if ep.get("url") and "{" not in ep["url"]][:30]

def probe_jwt(ep):
    url=ep["url"]
    try:
        r=subprocess.run(
            ["curl","-sk","-X",ep["method"],"-o","/dev/null","-w","%{http_code}",
             "-H",f"Authorization: Bearer {ALG_NONE_TOKEN}",
             url,"--max-time",str(timeout)],
            capture_output=True,timeout=timeout+5)
        code=r.stdout.decode().strip()
    except: return None
    if code in ("200","201","204"):
        return {"severity":"CRITICAL","type":"JWT Algorithm Confusion -- alg:none Accepted",
                "endpoint":f"{ep['method']} {url}","api":ep["api"],
                "detail":f"Server returned {code} with unsigned alg:none JWT -- critical auth bypass"}
    if code not in ("401","403","400","ERR",""):
        return {"severity":"HIGH","type":"JWT Algorithm Confusion -- Unexpected Response",
                "endpoint":f"{ep['method']} {url}","api":ep["api"],
                "detail":f"Returned {code} with alg:none token -- manual verification needed"}
    return None

total=len(probe_targets); done_count=0
if total>0:
    print(f"  Probing {total} endpoints with alg:none token...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs={ex.submit(probe_jwt,ep):ep for ep in probe_targets}
        for f in as_completed(futs):
            done_count+=1
            bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
            pct=done_count*100//max(total,1)
            ep=futs[f]
            print(f"\r  [{bar}] {pct:3d}%  {ep.get('path','')[:38]:<38}",end="",flush=True)
            result=f.result()
            if result: new_vulns.append(result)
    print()
else:
    print("  No concrete JWT endpoints to probe (all have path params).")

with open(out_file,"w") as f:
    f.write(f"JWT Surface -- {len(jwt_endpoints)} endpoints\n"+"="*60+"\n")
    for ep in jwt_endpoints:
        f.write(f"[{ep['method']:6}]  {ep.get('path','')}\n")

vulns.extend(new_vulns)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  JWT findings           : {len(new_vulns)}")
PYEOF

# ============================================================
# PHASE 14 – Mass Assignment Surface
# ============================================================
phase_header 14 "Mass assignment surface detection"

# Inspects POST/PUT request body schemas for dangerous fields.
# If role, isAdmin, permissions, verified etc. appear in requestBody schema,
# the developer may have forgotten to strip them server-side.
# Snyk sees ORM code; SPIRE sees what the API spec says the server accepts.

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, os, glob

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/mass-assignment.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

DANGEROUS_FIELDS=[
    "role","roles","isadmin","is_admin","admin","superuser","is_superuser",
    "permissions","permission","privilege","privileges","scope","scopes",
    "verified","is_verified","active","is_active","enabled","is_enabled",
    "approved","is_approved","group","groups","acl","access_level","access_control",
    "plan","tier","subscription","credits","balance","verified_at",
    "email_verified","phone_verified","kyc_status","trust_level",
]

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))
findings=[]

for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    title=data.get("info",{}).get("title","Unknown")
    # Flatten all schema $refs
    components=data.get("components",{}).get("schemas",{})
    defs=data.get("definitions",{})
    all_schemas={**components,**defs}

    def resolve_schema(schema,depth=0):
        if depth>5 or not isinstance(schema,dict): return schema
        if "$ref" in schema:
            ref=schema["$ref"].split("/")[-1]
            return resolve_schema(all_schemas.get(ref,{}),depth+1)
        return schema

    def extract_props(schema):
        s=resolve_schema(schema)
        if not isinstance(s,dict): return {}
        props=s.get("properties",{})
        # allOf / oneOf / anyOf
        for key in ("allOf","oneOf","anyOf"):
            for sub in s.get(key,[]):
                props.update(extract_props(sub))
        return props

    for path, methods_obj in data.get("paths",{}).items():
        if not isinstance(methods_obj,dict): continue
        for method, op in methods_obj.items():
            mu=method.upper()
            if mu not in ["POST","PUT","PATCH"]: continue
            if not isinstance(op,dict): continue
            # OpenAPI 3.x requestBody
            rb=op.get("requestBody",{})
            if rb:
                for media_type,media_obj in rb.get("content",{}).items():
                    schema=media_obj.get("schema",{})
                    props=extract_props(schema)
                    for field in props:
                        if field.lower() in DANGEROUS_FIELDS:
                            findings.append({
                                "severity":"HIGH",
                                "type":"Mass Assignment Risk -- Dangerous Field in Request Schema",
                                "endpoint":f"{mu} {path}",
                                "api":title,
                                "detail":f"Field '{field}' in {media_type} requestBody -- may allow privilege escalation if not server-side filtered"
                            })
            # Swagger 2.x body parameter
            for param in op.get("parameters",[]):
                if not isinstance(param,dict): continue
                if param.get("in")!="body": continue
                props=extract_props(param.get("schema",{}))
                for field in props:
                    if field.lower() in DANGEROUS_FIELDS:
                        findings.append({
                            "severity":"HIGH",
                            "type":"Mass Assignment Risk -- Dangerous Field in Request Schema",
                            "endpoint":f"{mu} {path}",
                            "api":title,
                            "detail":f"Field '{field}' in body param -- may allow privilege escalation if not server-side filtered"
                        })

with open(out_file,"w") as f:
    f.write(f"Mass Assignment Surface -- {len(findings)} findings\n"+"="*60+"\n")
    for v in findings:
        f.write(f"[{v['severity']:<8}]  {v['endpoint']}\n    {v['detail']}\n\n")

vulns.extend(findings)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  Mass assignment risks  : {len(findings)}")
PYEOF

# ============================================================
# PHASE 15 – Async / Webhook Endpoint Leakage
# ============================================================
phase_header 15 "Async API and webhook endpoint leakage"

# Parses x-webhooks (OpenAPI 3.1), callbacks (OpenAPI 3.x), and
# AsyncAPI-style channel definitions for leaked internal URLs,
# Kafka topics, queue names, and internal service references.
# No SAST tool touches this — it's spec metadata, not code.

SPIRE_OUT="$OUTPUT_DIR" python3 << 'PYEOF'
import json, os, glob, re

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/webhook-leakage.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

# Patterns that indicate internal/sensitive callback URLs
INTERNAL_URL_PATTERNS=[
    re.compile(r'https?://(?:localhost|127\.|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)'),
    re.compile(r'https?://[^/]*\.(?:internal|local|corp|intranet|private)\b'),
    re.compile(r'https?://[^/]*-(?:svc|service|int|internal)\b'),
]
SENSITIVE_TOPIC_PATTERNS=re.compile(
    r'(?i)(payment|billing|auth|password|secret|private|internal|admin|'
    r'user-data|pii|sensitive|credential|token|ssn|health|finance)'
)

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))
findings=[]
webhook_lines=[]

for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    title=data.get("info",{}).get("title","Unknown")

    # ── OpenAPI 3.1 x-webhooks ───────────────────────────────
    webhooks=data.get("x-webhooks",{}) or data.get("webhooks",{})
    for wh_name, wh_obj in webhooks.items():
        if not isinstance(wh_obj,dict): continue
        webhook_lines.append(f"[webhook]  {title}  /{wh_name}")
        for method, op in wh_obj.items():
            if not isinstance(op,dict): continue
            # Check for internal URLs in servers
            for server in op.get("servers",[]):
                url=server.get("url","")
                if any(p.search(url) for p in INTERNAL_URL_PATTERNS):
                    findings.append({"severity":"HIGH",
                                     "type":"Webhook Internal URL Exposed",
                                     "endpoint":f"{method.upper()} {wh_name}","api":title,
                                     "detail":f"Callback URL suggests internal network: {url}"})
        # Sensitive webhook name
        if SENSITIVE_TOPIC_PATTERNS.search(wh_name):
            findings.append({"severity":"MEDIUM",
                             "type":"Sensitive Webhook Name Exposed",
                             "endpoint":wh_name,"api":title,
                             "detail":f"Webhook '{wh_name}' suggests sensitive data flow"})

    # ── OpenAPI 3.x callbacks ────────────────────────────────
    for path, methods_obj in data.get("paths",{}).items():
        if not isinstance(methods_obj,dict): continue
        for method, op in methods_obj.items():
            if not isinstance(op,dict): continue
            for cb_name, cb_obj in op.get("callbacks",{}).items():
                if not isinstance(cb_obj,dict): continue
                webhook_lines.append(f"[callback] {title}  {method.upper()} {path}  -> {cb_name}")
                for expr, cb_path_obj in cb_obj.items():
                    if not isinstance(cb_path_obj,dict): continue
                    # Check expr for internal URL patterns
                    if any(p.search(expr) for p in INTERNAL_URL_PATTERNS):
                        findings.append({"severity":"HIGH",
                                         "type":"Callback Internal URL in Spec",
                                         "endpoint":f"{method.upper()} {path} -> {cb_name}",
                                         "api":title,
                                         "detail":f"Callback expression contains internal address: {expr[:100]}"})
                    if SENSITIVE_TOPIC_PATTERNS.search(cb_name) or SENSITIVE_TOPIC_PATTERNS.search(expr):
                        findings.append({"severity":"MEDIUM",
                                         "type":"Sensitive Callback Reference",
                                         "endpoint":f"{method.upper()} {path} -> {cb_name}",
                                         "api":title,
                                         "detail":f"Callback name/expr suggests sensitive topic: {cb_name}"})

    # ── x-kafka / x-amqp / AsyncAPI channel hints ───────────
    for ext_key in ("x-kafka-topic","x-amqp-exchange","x-sqs-queue",
                    "x-pubsub-topic","channels","x-channels"):
        ext_val=data.get(ext_key,{})
        if not ext_val: continue
        if isinstance(ext_val,str):
            webhook_lines.append(f"[async]    {title}  {ext_key}: {ext_val}")
            if SENSITIVE_TOPIC_PATTERNS.search(ext_val):
                findings.append({"severity":"HIGH",
                                 "type":f"Sensitive Async Topic Exposed -- {ext_key}",
                                 "endpoint":ext_key,"api":title,
                                 "detail":f"Topic/queue name reveals sensitive context: {ext_val}"})
        elif isinstance(ext_val,dict):
            for ch_name in ext_val.keys():
                webhook_lines.append(f"[async]    {title}  {ext_key}/{ch_name}")
                if SENSITIVE_TOPIC_PATTERNS.search(ch_name):
                    findings.append({"severity":"HIGH",
                                     "type":f"Sensitive Async Channel Exposed -- {ext_key}",
                                     "endpoint":ch_name,"api":title,
                                     "detail":f"Channel name reveals sensitive context: {ch_name}"})

with open(out_file,"w") as f:
    f.write(f"Webhook / Async Leakage -- {len(findings)} findings\n"+"="*60+"\n")
    f.write("\nAll Webhook / Callback / Async References:\n"+"-"*40+"\n")
    for line in webhook_lines: f.write(line+"\n")
    f.write("\nFindings:\n"+"-"*40+"\n")
    for v in findings:
        f.write(f"[{v['severity']:<8}]  {v['endpoint']}\n    {v['detail']}\n\n")

vulns.extend(findings)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  Webhook references     : {len(webhook_lines)}")
print(f"  Leakage findings       : {len(findings)}")
PYEOF

# ============================================================
# PHASE 16 – Shadow API via Response Header Mining
# ============================================================
phase_header 16 "Shadow API discovery via response header mining"

# Re-fetches confirmed swagger URLs (and live hosts) with full header capture.
# Extracts intelligence from:
#   X-Powered-By, Server → framework/version fingerprint
#   X-Internal-Service, X-Upstream, X-Backend → internal service names
#   X-Request-Id format → microservice architecture inference
#   X-RateLimit-* absence → no rate limiting
#   Access-Control-Allow-Origin: * → CORS wildcard confirmed live
#   Strict-Transport-Security absence → HSTS missing
#   X-Content-Type-Options absence → MIME sniffing possible

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, re, subprocess, os
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
workers  = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/shadow-headers.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]
try:    swagger_urls=[l.strip() for l in open(f"{out_dir}/real-swaggers.txt") if l.strip()]
except: swagger_urls=[]

EOL_FRAMEWORKS=re.compile(
    r'(?i)(express/[01]\.|koa/[01]\.|flask/0\.|django/[12]\.|'
    r'spring/[34]\.|rails/[1-5]\.|laravel/[1-8]\.|apache/2\.[0-3]\.|'
    r'nginx/1\.[0-9]\.|php/[1-7]\.|node/[1-9]\.|tomcat/[0-7]\.)',
    re.I
)
INTERNAL_HEADER_NAMES=re.compile(
    r'^x-(?:internal|upstream|backend|forwarded-for|real-ip|service|'
    r'microservice|cluster|pod|node|instance|region|dc|datacenter)',
    re.I
)

def fetch_headers(url):
    try:
        r=subprocess.run(
            ["curl","-sk","-I",url,"--max-time",str(timeout),"--compressed"],
            capture_output=True,timeout=timeout+5)
        return r.stdout.decode("utf-8",errors="ignore")
    except: return ""

def analyze_headers(url,raw_headers):
    findings=[]
    headers={}
    for line in raw_headers.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            k,_,v=line.partition(":")
            headers[k.strip().lower()]=v.strip()

    host=url.split("/")[2] if "/" in url else url

    # EOL / outdated framework
    server=headers.get("server","")
    powered=headers.get("x-powered-by","")
    for val in (server,powered):
        if EOL_FRAMEWORKS.search(val):
            findings.append({"severity":"HIGH","type":"Outdated / EOL Framework Detected",
                             "endpoint":url,"api":host,
                             "detail":f"Header reveals potentially EOL version: {val}"})

    # Internal service name leakage
    for hname,hval in headers.items():
        if INTERNAL_HEADER_NAMES.match(hname) and hval:
            findings.append({"severity":"MEDIUM","type":"Internal Service Reference in Response Header",
                             "endpoint":url,"api":host,
                             "detail":f"Header '{hname}: {hval}' may leak internal architecture"})

    # CORS wildcard confirmed live
    acao=headers.get("access-control-allow-origin","")
    if acao=="*":
        findings.append({"severity":"HIGH","type":"CORS Wildcard Confirmed Live",
                         "endpoint":url,"api":host,
                         "detail":"Response header Access-Control-Allow-Origin: * confirmed at runtime"})

    # HSTS missing
    if "strict-transport-security" not in headers:
        findings.append({"severity":"MEDIUM","type":"HSTS Header Missing",
                         "endpoint":url,"api":host,
                         "detail":"Strict-Transport-Security not present on API endpoint"})

    # X-Content-Type-Options missing
    if "x-content-type-options" not in headers:
        findings.append({"severity":"LOW","type":"X-Content-Type-Options Missing",
                         "endpoint":url,"api":host,
                         "detail":"MIME sniffing protection header absent"})

    # Rate limit headers absent
    rl_present=any(h.startswith("x-ratelimit") or h.startswith("ratelimit") or h=="retry-after"
                   for h in headers)
    if not rl_present:
        findings.append({"severity":"LOW","type":"Rate Limiting Headers Absent",
                         "endpoint":url,"api":host,
                         "detail":"No X-RateLimit-* headers observed -- rate limiting may not be enforced"})

    # X-Frame-Options missing
    if "x-frame-options" not in headers:
        findings.append({"severity":"LOW","type":"X-Frame-Options Missing",
                         "endpoint":url,"api":host,
                         "detail":"Clickjacking protection header absent"})

    return findings, headers

total=len(swagger_urls); done_count=0; new_vulns=[]; all_header_data=[]
with ThreadPoolExecutor(max_workers=workers) as ex:
    futs={ex.submit(fetch_headers,url):url for url in swagger_urls}
    for f in as_completed(futs):
        done_count+=1
        bar="#"*(done_count*40//max(total,1))+"."*(40-done_count*40//max(total,1))
        pct=done_count*100//max(total,1)
        url=futs[f]
        print(f"\r  [{bar}] {pct:3d}%  {url[:38]:<38}",end="",flush=True)
        raw=f.result()
        findings,headers=analyze_headers(url,raw)
        new_vulns.extend(findings)
        all_header_data.append({"url":url,"headers":headers})
print()

with open(out_file,"w") as f:
    f.write(f"Shadow Header Analysis -- {len(new_vulns)} findings\n"+"="*60+"\n\n")
    for item in all_header_data:
        f.write(f"URL: {item['url']}\n")
        for k,v in item["headers"].items():
            f.write(f"  {k}: {v}\n")
        f.write("\n")

vulns.extend(new_vulns)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"  Header findings        : {len(new_vulns)}")
PYEOF

# ============================================================
# PHASE 17 – OpenAPI x- Extension Inconsistency
# ============================================================
phase_header 17 "OpenAPI x- extension inconsistency analysis"

# Scans all specs for custom x- fields and flags:
#   x-auth-required: false  → endpoint claims no auth needed
#   x-internal: true         → claims internal only (verify it's not public)
#   x-role / x-permission    → role hints that may not be enforced
#   x-deprecated-by          → deprecated but may still be live
#   x-beta / x-preview       → beta endpoints often skip security review
#   Cross-check: if x-internal:true but no auth on endpoint → HIGH
#   Cross-check: if x-auth-required:false but live probe returns 401 → LOW (false positive in spec)

SPIRE_OUT="$OUTPUT_DIR" SPIRE_THREADS="$THREADS" SPIRE_TIMEOUT="$TIMEOUT" python3 << 'PYEOF'
import json, re, os, glob, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

out_dir  = os.environ.get("SPIRE_OUT","./spire-results")
workers  = max(1,int(os.environ.get("SPIRE_THREADS","40")))
timeout  = int(os.environ.get("SPIRE_TIMEOUT","10"))
vuln_file= f"{out_dir}/vuln-findings.txt"
out_file = f"{out_dir}/xextension-issues.txt"

try:    vulns=json.load(open(vuln_file))
except: vulns=[]

spec_files=sorted(glob.glob(f"{out_dir}/specs/*.json"))
findings=[]
ext_inventory=[]  # all x- fields found for reference

SENSITIVE_X_KEYS=re.compile(
    r'^x-(?:auth|role|permission|acl|internal|private|admin|secret|'
    r'deprecated|beta|preview|test|debug|scope|trust|verified|bypass)',
    re.I
)

def get_live_code(url,method="GET"):
    try:
        r=subprocess.run(["curl","-sk","-X",method,"-o","/dev/null","-w","%{http_code}",
                          url,"--max-time",str(timeout)],
                         capture_output=True,timeout=timeout+5)
        return r.stdout.decode().strip()
    except: return "ERR"

def check_val_truthy(val):
    if isinstance(val,bool): return val
    if isinstance(val,str): return val.lower() in ("true","yes","1")
    return False

def check_val_falsy(val):
    if isinstance(val,bool): return not val
    if isinstance(val,str): return val.lower() in ("false","no","0")
    return False

for spec_file in spec_files:
    try: data=json.load(open(spec_file))
    except: continue
    title=data.get("info",{}).get("title","Unknown")
    base_url=""
    if "servers" in data and data["servers"]:
        base_url=data["servers"][0].get("url","").rstrip("/")
    elif "host" in data:
        schemes=data.get("schemes",["https"])
        base_url=f"{schemes[0]}://{data['host']}{data.get('basePath','')}".rstrip("/")

    # Global x- extensions
    global_x={k:v for k,v in data.items() if k.startswith("x-")}
    for k,v in global_x.items():
        ext_inventory.append(f"[global]  {title}  {k}: {json.dumps(v)[:80]}")

    for path, methods_obj in data.get("paths",{}).items():
        if not isinstance(methods_obj,dict): continue

        # Path-level x- fields
        path_x={k:v for k,v in methods_obj.items() if k.startswith("x-")}
        for k,v in path_x.items():
            ext_inventory.append(f"[path]    {title}  {path}  {k}: {json.dumps(v)[:80]}")

        for method, op in methods_obj.items():
            if method.startswith("x-"): continue
            mu=method.upper()
            if mu not in ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]: continue
            if not isinstance(op,dict): continue

            # Collect x- fields at operation level
            op_x={k:v for k,v in op.items() if k.startswith("x-")}
            has_auth=bool(op.get("security")) or bool(data.get("security",[]))
            url=f"{base_url}{path}" if base_url and "{" not in path else None

            for k,v in op_x.items():
                ext_inventory.append(f"[op]      {title}  {mu} {path}  {k}: {json.dumps(v)[:80]}")
                k_lower=k.lower()

                # x-auth-required: false
                if "auth" in k_lower and "required" in k_lower and check_val_falsy(v):
                    findings.append({
                        "severity":"HIGH",
                        "type":"x-Extension: Auth Explicitly Disabled",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"'{k}: {v}' -- endpoint explicitly declares no auth required"
                    })

                # x-internal: true but no auth
                elif "internal" in k_lower and check_val_truthy(v) and not has_auth:
                    findings.append({
                        "severity":"HIGH",
                        "type":"x-Extension: Internal Endpoint Without Auth",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"'{k}: {v}' claims internal-only but no security scheme applied"
                    })

                # x-role / x-permission / x-required-role
                elif any(t in k_lower for t in ("role","permission","scope","acl")):
                    findings.append({
                        "severity":"MEDIUM",
                        "type":"x-Extension: Role/Permission Hint in Spec",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"'{k}: {json.dumps(v)[:80]}' -- verify this is enforced server-side, not just documented"
                    })

                # x-deprecated-by
                elif "deprecated" in k_lower:
                    dep_by=str(v) if v else "unspecified"
                    findings.append({
                        "severity":"INFO",
                        "type":"x-Extension: Deprecated-by Annotation",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"Deprecated by '{dep_by}' -- verify old endpoint is not still accessible"
                    })

                # x-beta / x-preview / x-test / x-experimental
                elif any(t in k_lower for t in ("beta","preview","experimental","test")):
                    findings.append({
                        "severity":"MEDIUM",
                        "type":"x-Extension: Beta/Preview Endpoint",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"'{k}: {v}' -- beta/preview endpoints often bypass security review"
                    })

                # x-bypass / x-debug / x-admin
                elif any(t in k_lower for t in ("bypass","debug","admin","secret")):
                    findings.append({
                        "severity":"HIGH",
                        "type":"x-Extension: Dangerous Extension Field",
                        "endpoint":f"{mu} {path}","api":title,
                        "detail":f"'{k}: {v}' -- potentially sensitive extension field in public spec"
                    })

print(f"  x- fields inventoried  : {len(ext_inventory)}")

with open(out_file,"w") as f:
    f.write(f"x-Extension Inconsistency -- {len(findings)} findings\n"+"="*60+"\n\n")
    f.write("FINDINGS:\n"+"-"*40+"\n")
    for v in findings:
        f.write(f"[{v['severity']:<8}]  {v['endpoint']}\n    {v['detail']}\n\n")
    f.write("\nFULL x- INVENTORY:\n"+"-"*40+"\n")
    for line in ext_inventory: f.write(line+"\n")

for v in findings[:15]:
    print(f"  [{v['severity']:<8}]  {v['endpoint']}  |  {v['detail'][:60]}")
if len(findings)>15:
    print(f"  ... ({len(findings)-15} more in xextension-issues.txt)")

vulns.extend(findings)
with open(vuln_file,"w") as f: json.dump(vulns,f,indent=2)
print(f"\n  x-Extension findings   : {len(findings)}")
PYEOF

# ============================================================
# PHASE 18 – Report
# ============================================================
phase_header 18 "Generating report"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

SPIRE_OUT="$OUTPUT_DIR" SPIRE_INPUT="$INPUT" SPIRE_ELAPSED="$ELAPSED" python3 << 'PYEOF'
import json, os, glob, datetime

out_dir = os.environ.get("SPIRE_OUT","./spire-results")
inp     = os.environ.get("SPIRE_INPUT","")
elapsed = int(os.environ.get("SPIRE_ELAPSED","0"))

try:    vulns=json.load(open(f"{out_dir}/vuln-findings.txt"))
except: vulns=[]

def safe_read_lines(path):
    try:    return open(path).readlines()
    except: return []

swagger_urls  =[l.strip() for l in safe_read_lines(f"{out_dir}/real-swaggers.txt") if l.strip()]
actuator_urls =[l.strip() for l in safe_read_lines(f"{out_dir}/actuator-found.txt") if l.strip()]
auth_lines    =safe_read_lines(f"{out_dir}/auth-test.txt")
ep_lines      =[l for l in safe_read_lines(f"{out_dir}/all-endpoints.txt") if l.startswith("  [")]

try:    total_t=open(f"{out_dir}/targets.txt").read().count("\n")
except: total_t=0
try:    live_c=open(f"{out_dir}/live-clean.txt").read().count("\n")
except: live_c=0

spec_count=len(glob.glob(f"{out_dir}/specs/*.json"))
total_ep=len(ep_lines)
now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

sev={}
for v in vulns: sev.setdefault(v.get("severity","INFO"),[]).append(v)

risk=(len(sev.get("CRITICAL",[]))*10+len(sev.get("HIGH",[]))*7+
      len(sev.get("MEDIUM",[]))*4+len(sev.get("LOW",[]))*1)
rlbl=("CRITICAL" if risk>=50 else "HIGH" if risk>=20
      else "MEDIUM" if risk>=10 else "LOW" if risk>=1 else "NONE")

# Count v2.4 specific findings
def count_by_type(pattern):
    return sum(1 for v in vulns if pattern.lower() in v.get("type","").lower())

L=[]
L.append("# SPIRE -- Spec Path Inspector & Recon Engine")
L.append("## Scan Report\n")
L.append("| Field | Value |")
L.append("|-------|-------|")
L.append(f"| Generated | {now} |")
L.append(f"| Duration | {elapsed}s |")
L.append(f"| Input | `{inp}` |")
L.append(f"| Version | 2.4 |")
L.append(f"| Risk Score | {risk} ({rlbl}) |")
L.append("\n---\n")
L.append("## Executive Summary\n")
L.append("| Metric | Value |")
L.append("|--------|-------|")
L.append(f"| Targets Scanned | {total_t} |")
L.append(f"| Live Hosts | {live_c} |")
L.append(f"| Swagger / OpenAPI URLs Found | {len(swagger_urls)} |")
L.append(f"| Spring Actuator URLs Found | {len(actuator_urls)} |")
L.append(f"| Spec Files Downloaded | {spec_count} |")
L.append(f"| Endpoints Parsed | {total_ep} |")
L.append(f"| Total Issues | {len(vulns)} |")
for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
    if s in sev: L.append(f"| {s} | {len(sev[s])} |")
L.append("\n**v2.4 Feature Findings:**\n")
L.append("| Feature | Findings |")
L.append("|---------|----------|")
for label, pattern in [
    ("API Versioning Graveyard",          "versioning graveyard"),
    ("Hidden Endpoints",                  "hidden / shadow endpoint"),
    ("BOLA Surface",                      "bola surface"),
    ("JWT Algorithm Confusion",           "jwt algorithm"),
    ("Mass Assignment",                   "mass assignment"),
    ("Webhook / Async Leakage",           "webhook"),
    ("Shadow Header Analysis",            "cors wildcard confirmed|outdated|internal service reference|hsts"),
    ("x-Extension Inconsistency",         "x-extension"),
]:
    import re
    n=sum(1 for v in vulns if re.search(pattern,v.get("type",""),re.I))
    if n: L.append(f"| {label} | {n} |")

L.append("\n---\n")
L.append("## Findings\n")
for severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
    items=sev.get(severity,[])
    if not items: continue
    L.append(f"### {severity}  ({len(items)})\n")
    by_type={}
    for v in items: by_type.setdefault(v["type"],[]).append(v)
    for itype, findings in by_type.items():
        L.append(f"#### {itype}\n")
        L.append("| # | API | Endpoint | Detail |")
        L.append("|---|-----|----------|--------|")
        for i,v in enumerate(findings,1):
            ep =v.get("endpoint","").replace("|","/")
            det=v.get("detail","").replace("|","/")[:120]
            L.append(f"| {i} | {v.get('api','')} | `{ep}` | {det} |")
        L.append("")

L.append("\n---\n")
L.append("## Discovered Swagger / OpenAPI URLs\n")
L.append("| # | URL |")
L.append("|---|-----|")
for i,url in enumerate(swagger_urls,1): L.append(f"| {i} | {url} |")

L.append("\n---\n")
L.append("## Discovered Spring Actuator URLs\n")
L.append("| # | URL |")
L.append("|---|-----|")
for i,url in enumerate(actuator_urls,1): L.append(f"| {i} | {url} |")

L.append("\n---\n")
L.append("## Live Authentication Test\n")
L.append("| URL | Code | Status |")
L.append("|-----|------|--------|")
for line in auth_lines[2:]:
    parts=[p.strip() for p in line.strip().split("  ") if p.strip()]
    if len(parts)>=3: L.append(f"| {parts[0]} | {parts[1]} | {parts[2]} |")

L.append("\n---\n")
L.append("## All Parsed Endpoints\n```")
for l in ep_lines[:500]: L.append(l.rstrip())
if total_ep>500: L.append(f"... ({total_ep-500} more -- see all-endpoints.txt)")
L.append("```")

L.append("\n---\n")
L.append("## Remediation\n")
L.append("| Finding | Recommended Action |")
L.append("|---------|-------------------|")
for f,a in [
    ("Missing Authentication",                   "Enforce OAuth2 / Bearer on all non-public endpoints"),
    ("No Security Schemes Defined",              "Define securitySchemes and apply globally"),
    ("Sensitive Parameter in Request",           "Move secrets to Authorization header; never query string"),
    ("Insecure Transport (HTTP)",                "Enforce HTTPS at the load balancer"),
    ("CORS Wildcard",                            "Restrict ACAO to an explicit allowlist"),
    ("Dangerous Method on Sensitive Path",       "Require elevated roles for destructive methods"),
    ("Deprecated Endpoint",                      "Decommission or apply identical hardening"),
    ("Hardcoded Secret or API Key",              "Rotate immediately; use a secrets manager"),
    ("JWT Token",                                "Revoke the token; never embed live credentials in specs"),
    ("Internal IP Address",                      "Remove all internal network references from public specs"),
    ("Unexpected HTTP Method Accepted",          "Return 405 for all disallowed HTTP verbs"),
    ("Spring Actuator Root Exposed",             "Restrict /actuator with Spring Security"),
    ("Spring Actuator Exposed -- /heapdump",     "DISABLE immediately: management.endpoint.heapdump.enabled=false"),
    ("Spring Actuator Exposed -- /env",          "Disable: management.endpoint.env.enabled=false"),
    ("API Versioning Graveyard -- Auth Regression","Decommission old API versions or apply identical auth middleware"),
    ("API Versioning Graveyard -- Old Version Live","Sunset old versions; route traffic to current version only"),
    ("Hidden / Shadow Endpoint Found",           "Audit undocumented endpoints; add to spec or remove"),
    ("BOLA Surface",                             "Implement per-object ownership check on every {id} endpoint"),
    ("JWT Algorithm Confusion -- alg:none Accepted","Explicitly validate alg field server-side; reject alg:none"),
    ("JWT Algorithm Confusion -- Unexpected",    "Review JWT library configuration; pin accepted algorithms"),
    ("Mass Assignment Risk",                     "Implement server-side allowlist for writable fields; use DTOs"),
    ("Webhook Internal URL Exposed",             "Remove internal callback URLs from public specs"),
    ("Sensitive Async Topic Exposed",            "Rename topics to non-revealing names in public specs"),
    ("x-Extension: Auth Explicitly Disabled",   "Remove x-auth-required:false or enforce auth regardless"),
    ("x-Extension: Internal Endpoint Without Auth","Add auth or block external access at network layer"),
    ("x-Extension: Beta/Preview Endpoint",      "Apply same security controls as production endpoints"),
    ("x-Extension: Dangerous Extension Field",  "Remove sensitive extension fields from public-facing specs"),
    ("Outdated / EOL Framework Detected",        "Upgrade framework; apply latest security patches"),
    ("CORS Wildcard Confirmed Live",             "Set ACAO to explicit origin allowlist in server config"),
    ("HSTS Header Missing",                      "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("Internal Service Reference in Response Header","Remove or mask internal service headers at API gateway"),
    ("JWKS URI Exposed in Spec",                 "Verify JWKS endpoint only exposes public keys, never private"),
]: L.append(f"| {f} | {a} |")

L.append("\n---\n")
L.append("## Output Files\n")
L.append("| File | Description |")
L.append("|------|-------------|")
for fn,desc in [
    ("real-swaggers.txt",     "Confirmed swagger/openapi URLs"),
    ("actuator-found.txt",    "Confirmed Spring Actuator URLs"),
    ("specs/",                "Downloaded API specification files"),
    ("all-endpoints.txt",     "All parsed endpoints"),
    ("auth-test.txt",         "Live HTTP response codes per swagger URL"),
    ("version-graveyard.txt", "Old API versions still live (v2.4)"),
    ("hidden-endpoints.txt",  "Undocumented endpoints discovered (v2.4)"),
    ("bola-surface.txt",      "BOLA surface map -- {id} endpoints (v2.4)"),
    ("jwt-surface.txt",       "JWT-secured endpoints inventory (v2.4)"),
    ("mass-assignment.txt",   "Mass assignment risk fields (v2.4)"),
    ("webhook-leakage.txt",   "Webhook/async channel leakage (v2.4)"),
    ("shadow-headers.txt",    "Response header intelligence (v2.4)"),
    ("xextension-issues.txt", "x-extension inconsistencies (v2.4)"),
    ("vuln-findings.txt",     "Raw vulnerability data (JSON)"),
    ("findings.json",         "Machine-readable summary"),
    ("REPORT.md",             "This report"),
]: L.append(f"| `{fn}` | {desc} |")

with open(f"{out_dir}/REPORT.md","w") as f: f.write("\n".join(L))

json.dump({
    "tool":"SPIRE","version":"2.4","scan_date":now,
    "duration_seconds":elapsed,"risk_score":risk,"risk_label":rlbl,
    "stats":{"targets":total_t,"live_hosts":live_c,
             "swagger_urls":len(swagger_urls),"actuator_urls":len(actuator_urls),
             "specs":spec_count,"endpoints":total_ep,"issues":len(vulns)},
    "severity_breakdown":{k:len(v) for k,v in sev.items()},
    "swagger_urls":swagger_urls,"actuator_urls":actuator_urls,
    "findings":vulns
}, open(f"{out_dir}/findings.json","w"), indent=2)

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
printf "${B}  SPIRE v2.4 scan complete${N}\n"
printf "${D}%s${N}\n" "$SEP"
printf "  ${G}[+]${N} Swagger URLs found   : %s\n" "$(wc -l < "$REAL_SWAGGERS" | tr -d ' ')"
printf "  ${G}[+]${N} Actuator URLs found  : %s\n" "$(wc -l < "$ACTUATOR_FOUND" | tr -d ' ')"
printf "  ${G}[+]${N} Endpoints parsed     : %s\n" "$(grep -c '^\s*\[' "$ENDPOINTS_FILE" 2>/dev/null || printf 0)"
printf "  ${G}[+]${N} Issues flagged       : %s\n" "$ISSUE_COUNT"
printf "  ${G}[+]${N} Duration             : %ss\n" "$ELAPSED"
printf "  ${G}[+]${N} Output               : %s/\n" "$OUTPUT_DIR"
printf "${D}%s${N}\n" "$SEP"
printf '\n'
