#!/usr/bin/env bash
# Live demo: builds Sentinel, starts the demo app behind it with evidence
# capture on, sends real benign traffic and a set of real attacks (classic and
# parser-differential), then verifies the evidence chain and writes the
# analyst's incident report.
#
#   bash scripts/demo.sh            # dashboard stays up until Ctrl-C
#   DEMO_KEEP=0 bash scripts/demo.sh  # stop after the report is written
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=demo-out
PROXY=127.0.0.1:8080
ADMIN=127.0.0.1:9090
APP=127.0.0.1:8000
mkdir -p "$OUT" bin
rm -f "$OUT/evidence.jsonl"

echo "==> building"
go build -o bin/ ./cmd/waf ./cmd/target ./cmd/sentinel-report

cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT
PIDS=()
./bin/target -listen "$APP" >"$OUT/target.log" 2>&1 & PIDS+=($!)
./bin/waf -listen "$PROXY" -upstream "http://$APP" -admin "$ADMIN" \
  -evidence "$OUT/evidence.jsonl" -log "$OUT/waf.log" >"$OUT/waf.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do curl -fsS "http://$ADMIN/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
echo "==> dashboard: http://$ADMIN/   (proxy on http://$PROXY)"

P="http://$PROXY"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "==> benign traffic (real names, sentences and paths from the regression corpus)"
ok=0; fp=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  c=$(code -G "$P/search" --data-urlencode "q=$line"); [ "$c" = 403 ] && fp=$((fp+1)) || ok=$((ok+1))
  c=$(code -X POST "$P/login" --data-urlencode "username=$line" -d password=correct-horse); [ "$c" = 403 ] && fp=$((fp+1)) || ok=$((ok+1))
  sleep 0.2
done < <(head -n 40 eval/corpus/benign/general.txt)
echo "    benign requests passed: $ok, wrongly blocked: $fp"

echo "==> attacks"
attack() { local name=$1; shift; printf '    %-46s HTTP %s\n' "$name" "$(code "$@")"; }
Q="'"
attack "SQL injection (UNION)"            -G "$P/search" --data-urlencode "q=1${Q} UNION SELECT username,password FROM users--"
attack "Path traversal"                   -G "$P/file"   --data-urlencode "name=../../../../etc/passwd"
attack "OS command injection"             -G "$P/ping"   --data-urlencode "host=127.0.0.1; cat /etc/passwd"
attack "Stored XSS"                       -X POST "$P/login" --data-urlencode "username=<img src=x onerror=alert(document.cookie)>" -d password=x
attack "JSON body sent as text/plain"     -X POST "$P/api" -H 'Content-Type: text/plain' -d "{\"q\":\"1${Q} UNION SELECT password FROM users--\"}"
attack "Case-variant JSON key (Go struct)" -X POST "$P/api" -H 'Content-Type: application/json' -d "{\"role\":\"user\",\"ROLE\":\"admin${Q} OR ${Q}1${Q}=${Q}1\"}"
attack "Duplicate JSON key"               -X POST "$P/api" -H 'Content-Type: application/json' -d '{"cmd":"hello","cmd":"; rm -rf / #"}'
attack "Multipart part after close"       -X POST "$P/upload" -H 'Content-Type: multipart/form-data; boundary=XB' \
  --data-binary $'--XB\r\nContent-Disposition: form-data; name="a"\r\n\r\nhi\r\n--XB--\r\n--XB\r\nContent-Disposition: form-data; name="q"\r\n\r\n1\x27 UNION SELECT 1--\r\n--XB--\r\n'
attack "Multipart with two boundaries"    -X POST "$P/upload" -H 'Content-Type: multipart/form-data; boundary=AAA; boundary=BBB' \
  --data-binary $'--BBB\r\nContent-Disposition: form-data; name="q"\r\n\r\nhello\r\n--BBB--\r\n'
attack "HTTP parameter pollution"         -G "$P/search" -d "q=1${Q}/*&q=*/UNION/*&q=*/SELECT+1--"
attack "EBCDIC (ibm037) body charset"     -X POST "$P/api" -H 'Content-Type: application/x-www-form-urlencoded; charset=ibm037' -d 'q=%88%85'

echo "==> evidence"
./bin/sentinel-report verify -evidence "$OUT/evidence.jsonl"
./bin/sentinel-report report -evidence "$OUT/evidence.jsonl" -out "$OUT/incident-report.html" -title "Sentinel WAF live demo: incident report"
./bin/sentinel-report report -evidence "$OUT/evidence.jsonl" -out "$OUT/incident-report.md" -title "Sentinel WAF live demo: incident report"
echo "    report: $OUT/incident-report.html  (also live at http://$ADMIN/report)"

if [ "${DEMO_KEEP:-1}" = 1 ]; then
  echo "==> running. Open http://$ADMIN/ - Ctrl-C to stop."
  wait
fi
