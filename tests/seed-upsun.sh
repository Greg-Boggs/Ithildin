#!/usr/bin/env bash
# seed-upsun.sh - plant harmless canaries on an Upsun TEST environment so strider.sh has
# something to find, then remove them again. Never point this at production.
#
# Usage:
#   tests/seed-upsun.sh -p PROJECT -e ENV           # plant canaries and send canary traffic
#   ../strider.sh -p PROJECT -e ENV                 # expect REVIEW (see list below)
#   tests/seed-upsun.sh -p PROJECT -e ENV --clean   # remove the canaries
#   ../strider.sh -p PROJECT -e ENV                 # file/session/process flags clear; the traffic
#                                                   # flags stay until Upsun trims the access log
#
# Planted (all named "strider-canary", nothing executable by the web server):
#   files mount:  strider-canary.php    -> files, php-in-files, shells (signature is inside a comment)
#   sessions:     sess_stridercanary    -> session-files (upload_progress_ key, PHP tag, short ID)
#   /tmp:         .strider-canary       -> a copy of sleep running 15 minutes: tmp-exe, procs
# Traffic from your machine to the environment's URL:
#   6x POST /, PUT and PATCH on /node/1, ?PHP_SESSION_UPLOAD_PROGRESS=strider-canary
#                                       -> POST-BURSTS, PUT/PATCH, UPLOAD-PROGRESS-FIELD
# KNOWN-IPS can't be tested this way: the requests come from your own address.

P=""; E=""; CLEAN=0
while [ $# -gt 0 ]; do
  case $1 in
    -p) P=$2; shift 2 ;;
    -e) E=$2; shift 2 ;;
    --clean) CLEAN=1; shift ;;
    *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
  esac
done
[ -n "$P" ] && [ -n "$E" ] || { echo "need -p PROJECT and -e ENV"; exit 1; }
case $E in main|master|production|prod|live)
  printf 'Environment "%s" looks like production. Type the project ID to continue: ' "$E"
  read -r confirm; [ "$confirm" = "$P" ] || exit 1 ;;
esac

# Runs inside the container: finds the files mount and session dir the same way strider.sh does.
REMOTE=$(cat <<'REMOTE'
CLEAN=$1
APPDIR="${PLATFORM_APP_DIR:-/app}"
FILESDIR=$(awk -v d="$APPDIR" 'index($2, d "/") == 1 && $2 ~ /files/ {print $2; exit}' /proc/mounts)
SESSDIR=$(php -r '$p = ini_get("session.save_path"); $p = $p === "" ? sys_get_temp_dir() : $p; echo substr($p, strrpos($p, ";") === false ? 0 : strrpos($p, ";") + 1);')
if [ "$CLEAN" = 1 ]; then
  pkill -f /tmp/.strider-canary
  rm -f "$FILESDIR/strider-canary.php" "$SESSDIR/sess_stridercanary" /tmp/.strider-canary
  echo "removed canaries from ${FILESDIR:-?}, ${SESSDIR:-?}, /tmp"
  exit 0
fi
[ -n "$FILESDIR" ] || { echo "no files mount under $APPDIR"; exit 1; }
echo "<?php // strider-canary test file, safe to delete. Signature for the scanner: eval(base64_decode('c3RpbmctY2FuYXJ5'))" > "$FILESDIR/strider-canary.php"
echo 'upload_progress_strider-canary|s:5:"<?php";' > "$SESSDIR/sess_stridercanary"
cp "$(command -v sleep)" /tmp/.strider-canary
setsid nohup /tmp/.strider-canary 900 >/dev/null 2>&1 < /dev/null &
echo "planted $FILESDIR/strider-canary.php, $SESSDIR/sess_stridercanary, /tmp/.strider-canary (pid $!)"
REMOTE
)

upsun ssh -p "$P" -e "$E" -- "bash -s -- $CLEAN" <<<"$REMOTE" || { echo "ssh failed"; exit 1; }
[ "$CLEAN" = 1 ] && exit 0

URL=$(upsun environment:url -p "$P" -e "$E" --primary --pipe 2>/dev/null </dev/null)
[ -n "$URL" ] || { echo "could not read the environment URL; canary traffic not sent"; exit 1; }
URL=${URL%/}
echo "sending canary traffic to $URL"
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "POST / %{http_code}\n" -A strider-canary -F "strider-canary=$i" "$URL/"
done
curl -s -o /dev/null -w "PUT /node/1 %{http_code}\n" -A strider-canary -X PUT -F strider-canary=1 "$URL/node/1"
curl -s -o /dev/null -w "PATCH /node/1 %{http_code}\n" -A strider-canary -X PATCH -F strider-canary=1 "$URL/node/1"
curl -s -o /dev/null -w "POST /?PHP_SESSION_UPLOAD_PROGRESS %{http_code}\n" -A strider-canary -F strider-canary=1 "$URL/?PHP_SESSION_UPLOAD_PROGRESS=strider-canary"
echo "done. Run: ./strider.sh -p $P -e $E"
