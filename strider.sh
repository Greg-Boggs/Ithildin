#!/usr/bin/env bash
# strider.sh - PHP security triage for hosted Drupal/PHP apps (CVE-2026-109618 / CVE-2026-109619).
#
# Follows the Drupal Association's post-release audit guidance
# (https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites).
# For every project/app it:
#   - checks the PHP version against the fixed releases (8.5.12, 8.4.27, 8.3.36, 8.2.35)
#   - saves the container logs (before the host trims them) and filters them to a window
#   - looks for Amazon's published source IPs, PUT/PATCH, POST bursts to one page, crashes and memory errors
#   - looks for the PHP_SESSION_UPLOAD_PROGRESS field name in any logged request (AWS step 3)
#   - inspects PHP's native session directory for upload-progress / PHP-tag payloads
#   - scans writable mounts, /tmp and /dev/shm for dropped scripts and webshells
#   - lists suspicious processes, outbound connections, crontab and authorized_keys
#   - on Drupal sites: new/changed users, administrators, modules enabled outside exported config
# Output: a timestamped report folder with report.html (open it in a browser) and SUMMARY.txt,
# marking each app OK, REVIEW or INCOMPLETE.
#
# Usage:
#   ./strider.sh                       # all projects, each on its default branch, Oct 17 -> now
#   ./strider.sh -p abc123 -p def456   # specific projects
#   ./strider.sh -e production -f 2026-10-17T00:00:00 -t 2026-10-21T16:00:00
#   ./strider.sh -c myhost.conf        # another host; upsun.conf next to this script is the default
#
# Times are UTC. Read-only: nothing on the server is changed.

set -o pipefail

FROM="2026-10-17T00:00:00"
TO="$(date -u +%Y-%m-%dT%H:%M:%S)"
ENV=""   # empty: use each project's default branch
PROJECTS=""

# Fixed PHP releases per branch, and source IPs published by Amazon.
FIXED_VERSIONS="${STRIDER_FIXED_VERSIONS:-8.5.12 8.4.27 8.3.36 8.2.35}"   # override for tests only
KNOWN_IPS="103.216.220.92 31.223.184.166 37.19.200.5 134.209.159.64 103.114.163.188 95.217.98.37"

# Noise thresholds: a healthy site has a few of these, so only flag runs.
POST_BURST=5            # POSTs from one client to the same page...
POST_BURST_MINUTES=10   # ...within this many minutes
MEMORY_ERRORS=20        # memory/timeout errors in the logs (worker crashes are always flagged)
FATAL_BURST=10          # fatal/parse/uncaught errors in the error logs...
FATAL_BURST_MINUTES=10  # ...within this many minutes, inside the review window
LINE0_BURST=10          # "in Unknown on line 0" diagnostics (raised before any script runs)...
LINE0_BURST_MINUTES=10  # ...within this many minutes, inside the review window

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

CONFIG="$(cd "$(dirname "$0")" && pwd)/upsun.conf"
while getopts "p:e:f:t:c:h" o; do
  case $o in
    c) CONFIG=$OPTARG ;;
    p) PROJECTS="$PROJECTS $OPTARG" ;;
    e) ENV=$OPTARG ;;
    f) FROM=$OPTARG ;;
    t) TO=$OPTARG ;;
    *) usage ;;
  esac
done

# Everything host-specific (CLI calls, log paths, app dir, wording) comes from the config file.
[ -f "$CONFIG" ] || { echo "config file not found: $CONFIG"; exit 1; }
# shellcheck source=upsun.conf
. "$CONFIG"
for fn in platform_projects platform_default_env platform_title platform_apps platform_ssh; do
  declare -F "$fn" >/dev/null || { echo "$CONFIG does not define $fn()"; exit 1; }
done
command -v "$PLATFORM_CLI" >/dev/null 2>&1 || { echo "$PLATFORM_CLI not found in PATH"; exit 1; }

if [ -z "$PROJECTS" ]; then
  PROJECTS=$(platform_projects 2>/dev/null </dev/null)
  [ -z "$PROJECTS" ] && { echo "No projects found (are you logged in? run: $LOGIN_HINT)"; exit 1; }
fi

OUT="ithildin-report-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.txt"
{
  echo "PHP security audit report (CVE-2026-109618 / CVE-2026-109619)"
  echo "Window (UTC): $FROM -> $TO"
  echo "Environment:  ${ENV:-default branch of each project}"
  echo "Fixed PHP:    $FIXED_VERSIONS"
  echo "Generated:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
} > "$SUMMARY"

# ---------------------------------------------------------------------------
# Runs inside the app container (read-only checks).
# ---------------------------------------------------------------------------
REMOTE_SCRIPT=$(cat <<'REMOTE'
FROM="$1"
SINCE="${FROM}Z"
APPDIR=$(printenv "$2" 2>/dev/null)
APPDIR=${APPDIR:-$3}
LOGDIR=$4
cd "$APPDIR" 2>/dev/null || true
count() { [ -z "$1" ] && echo 0 || printf '%s\n' "$1" | wc -l | tr -d ' '; }

echo "### PHP version"
php -r 'echo PHP_VERSION, "\n";' 2>&1

echo
echo "### PHP ini values (CLI)"
php -r 'foreach (["session.upload_progress.enabled","session.upload_progress.name","session.upload_progress.prefix","session.use_strict_mode","session.save_handler","session.save_path","upload_tmp_dir","post_max_size","upload_max_filesize","memory_limit","fatal_error_backtraces"] as $k) printf("%-35s %s\n", $k, var_export(ini_get($k), true));' 2>&1
UPREFIX=$(php -r 'echo ini_get("session.upload_progress.prefix");' 2>/dev/null)
UPREFIX=${UPREFIX:-upload_progress_}

# --- Required PHP settings: the value the web server's PHP actually uses --------------------
# The CLI and PHP-FPM can load different ini files and FPM pools can override both, so for each
# setting take the first of: pool override, FPM's ini files, CLI. The advisories say these must be
# set in php.ini or the pool config; ini_set() and .user.ini don't count.
PHPMM=$(php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;' 2>/dev/null)
FPM=$(command -v "php-fpm$PHPMM" php-fpm 2>/dev/null | head -1)
if [ -z "$FPM" ]; then
  for c in "/usr/sbin/php-fpm$PHPMM" /usr/sbin/php-fpm /usr/local/sbin/php-fpm; do [ -x "$c" ] && { FPM=$c; break; }; done
fi
FPMINFO=$([ -n "$FPM" ] && "$FPM" -i 2>/dev/null)
POOLS=$(ls /etc/php/"$PHPMM"/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf 2>/dev/null | sort -u)
onoff() { case $(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '"'"'"' ') in 1|on|true|yes) echo 1 ;; ''|0|off|false|no|none) echo 0 ;; *) echo "$1" ;; esac; }
effective() {   # $1 = setting; prints "value|source", value empty when this PHP has no such setting
  pv=$(grep -hE "^[[:space:]]*php_(admin_)?(value|flag)\[$1\]" $POOLS 2>/dev/null | tail -1 | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//')
  if [ -n "$pv" ]; then echo "$(onoff "$pv")|fpm-pool"; return; fi
  fv=$(printf '%s\n' "$FPMINFO" | awk -F' => ' -v k="$1" '$1 == k {print $2; exit}')
  if [ -n "$fv" ]; then echo "$(onoff "$fv")|fpm"; return; fi
  cv=$(php -r "\$v = ini_get('$1'); echo \$v === false ? '@none' : \$v;" 2>/dev/null)
  if [ "$cv" = "@none" ]; then echo "|cli"; else echo "$(onoff "$cv")|cli"; fi
}
IFS='|' read -r UPROG UPROGSRC <<<"$(effective session.upload_progress.enabled)"
IFS='|' read -r STRICT STRICTSRC <<<"$(effective session.use_strict_mode)"
IFS='|' read -r FEB FEBSRC <<<"$(effective fatal_error_backtraces)"
echo
echo "### Required PHP settings (the value the web server's PHP uses; source: fpm-pool > fpm > cli)"
echo "PHP-FPM: ${FPM:-not found, so these are the CLI values}${POOLS:+   pools: $(printf '%s\n' "$POOLS" | paste -sd' ' -)}"
for k in session.upload_progress.enabled:0:$UPROG:$UPROGSRC session.use_strict_mode:1:$STRICT:$STRICTSRC fatal_error_backtraces:0:$FEB:$FEBSRC; do
  IFS=: read -r name want have src <<<"$k"
  cli=$(onoff "$(php -r "echo ini_get('$name');" 2>/dev/null)")
  printf '%-34s required %s   effective %-4s (%s)   cli %s\n' "$name" "$want" "${have:-n/a}" "$src" "$([ -n "$have" ] && echo "$cli" || echo n/a)"
done
FEBON=$([ "$FEB" = 1 ] && echo 1 || echo 0)
echo "--- .user.ini files setting these (the advisories say not to rely on them)"
USERINI=$(grep -rnE --include=.user.ini '^[[:space:]]*(session\.upload_progress\.enabled|session\.use_strict_mode|fatal_error_backtraces)' "$APPDIR" 2>/dev/null | head -20)
echo "${USERINI:-(none)}"
echo "--- code that switches session.serialize_handler at runtime (CVE-2026-115560 needs this with upload progress on)"
SERSWITCH=$(grep -rnE "ini_set\([[:space:]]*['\"]session\.serialize_handler" "$APPDIR" --include='*.php' --include='*.module' --include='*.inc' --include='*.install' --include='*.theme' --exclude-dir=node_modules --exclude-dir=.git 2>/dev/null | head -20)
echo "${SERSWITCH:-(none)}"

echo
echo "### $LOGDIR"
ls -la "$LOGDIR" 2>&1

# --- PHP native session store -------------------------------------------------
SESSDIR=$(php -r '$p = ini_get("session.save_path"); $p = $p === "" ? sys_get_temp_dir() : $p; echo substr($p, strrpos($p, ";") === false ? 0 : strrpos($p, ";") + 1);' 2>/dev/null)
echo
echo "### PHP session directory: ${SESSDIR:-unknown}"
SESSBAD=""
if [ -n "$SESSDIR" ] && [ -d "$SESSDIR" ]; then
  echo "Files: $(find "$SESSDIR" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l | tr -d ' ')"
  echo "--- newest 40"
  ls -lat --time-style=full-iso "$SESSDIR" 2>/dev/null | head -40
  echo "--- session files containing a PHP open tag"
  TAGS=$(grep -l '<?' "$SESSDIR"/sess_* 2>/dev/null)
  echo "${TAGS:-(none)}"
  echo "--- session files containing $UPREFIX"
  UPF=$(grep -lF "$UPREFIX" "$SESSDIR"/sess_* 2>/dev/null)
  echo "${UPF:-(none)}"
  echo "--- session IDs that are not 26-32 alphanumeric characters"
  ODD=$(find "$SESSDIR" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | sed 's#.*/sess_##' | grep -vE '^[A-Za-z0-9,-]{26,32}$' | head -50)
  echo "${ODD:-(none)}"
  SESSBAD=$(printf '%s\n%s\n%s\n' "$TAGS" "$UPF" "$ODD" | sed '/^$/d')
fi

# --- Filesystem -------------------------------------------------------------
MOUNTS=$(awk -v d="$APPDIR" 'index($2, d "/") == 1 {print $2}' /proc/mounts | sort -u)
UPTMP=$(php -r 'echo ini_get("upload_tmp_dir");' 2>/dev/null)
SCAN=$(printf '%s\n' $MOUNTS /tmp /dev/shm $UPTMP $SESSDIR | sed '/^$/d' | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done)
echo
echo "### Writable locations scanned"
echo "$SCAN"

echo
# Drupal writes these files itself; they are listed separately, not counted:
#  - PHP storage (Twig templates, Trash and proxy classes): <dir>/<43-char hash>.php. The webshell
#    scan below still reads them.
#  - .htaccess files made only of the lines Drupal and Package Manager generate.
# Empty files can't carry a payload (the ssh login itself creates empty /tmp/.*_history files), and
# a PHP exploit can only write as the web user, so other owners (the host's root-owned files) are skipped.
HASHPHP='.*/[A-Za-z0-9_-]{43}\.php'
benign_htaccess() {
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$1" | sed '/^$/d' | grep -vixF \
    -e 'Require all denied' -e 'Deny from all' -e 'Order allow,deny' \
    -e 'Options -Indexes -ExecCGI -Includes -MultiViews' -e 'Options None' -e 'Options +FollowSymLinks' \
    -e 'SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006' -e 'SetHandler Drupal_Security_Do_Not_Remove_See_SA_2013_003' \
    -e '<Files *>' -e '</Files>' -e '<IfModule mod_authz_core.c>' -e '<IfModule !mod_authz_core.c>' \
    -e '<IfModule mod_php.c>' -e '<IfModule mod_php5.c>' -e '<IfModule mod_php7.c>' -e 'php_flag engine off' -e '</IfModule>' | grep -q . && return 1
  return 0
}
echo "### Script-like, .htaccess or hidden files in writable locations modified since $FROM (web user, non-empty)"
CANDIDATES=$(find $SCAN -xdev -regextype posix-extended -type f -newermt "$SINCE" -user "$(id -u)" -not -empty \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '.htaccess' -o -iname '.user.ini' -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -name '.*' \) -not -name 'sess_*' -printf '%TY-%Tm-%Td %TH:%TM  %u  %10s  %p\n' 2>/dev/null | sort)
FILES=""; GENERATED=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  f="/${line#*  /}"
  case ${f##*/} in .*_history) continue ;; esac   # read below, in "Shell history"
  if printf '%s\n' "$f" | grep -qE "^$HASHPHP\$" || { [ "${f##*/}" = .htaccess ] && benign_htaccess "$f"; }; then
    GENERATED="$GENERATED$line"$'\n'
  else
    FILES="$FILES$line"$'\n'
  fi
done <<<"$CANDIDATES"
FILES=${FILES%$'\n'}; GENERATED=${GENERATED%$'\n'}
echo "${FILES:-(none)}" | head -300
echo "--- Drupal-generated, not counted"
echo "${GENERATED:-(none)}" | head -100

echo
echo "### Shell history (hosts like Upsun touch these at every login, so their dates mean nothing; the commands do)"
HISTFILES=$(ls -d /tmp/.*_history "$HOME"/.*_history 2>/dev/null | sort -u)
HISTN=0; HISTBAD=""
if [ -n "$HISTFILES" ]; then
  HISTN=$(cat $HISTFILES 2>/dev/null | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
  HISTBAD=$(grep -naE '(^|[;&|[:space:]])(curl|wget|nc|ncat|netcat|socat|telnet)([[:space:]]|$)|/dev/tcp/|base64[[:space:]]+(-d|--decode)|chmod[[:space:]]+[+0-7]*x|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|crontab[[:space:]]+(-[er]|[^-[:space:]])|>>?[[:space:]]*[^[:space:]]*authorized_keys|useradd|adduser' $HISTFILES 2>/dev/null)
  echo "$HISTN commands in: $(printf '%s\n' "$HISTFILES" | paste -sd' ' -)"
  echo "--- commands matching downloader, reverse-shell or persistence patterns"
  echo "${HISTBAD:-(none)}" | head -100
  echo "--- last 40 commands"
  cat $HISTFILES 2>/dev/null | sed '/^[[:space:]]*$/d' | tail -40
else
  echo "(no history files)"
fi

echo
echo "### Any PHP-type file inside a files/ directory (any age, Drupal-generated PHP storage excluded)"
PHPINFILES=$(find $SCAN -xdev -regextype posix-extended -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -path '*files*' -not -regex "$HASHPHP" 2>/dev/null)
echo "${PHPINFILES:-(none)}" | head -200

echo
echo "### Webshell signatures in writable locations (files under 2 MB, Drupal-generated PHP included)"
SHELLRE='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\('
SHELLS=$(find $SCAN -xdev -type f -size -2M -print0 2>/dev/null | xargs -0 -r grep -lIE "$SHELLRE" 2>/dev/null)
echo "${SHELLS:-(none)}" | head -200
if [ -n "$SHELLS" ]; then
  echo "--- matching code"
  printf '%s\n' "$SHELLS" | head -50 | while IFS= read -r f; do grep -nIE "$SHELLRE" "$f" | head -3 | cut -c1-200 | sed "s#^#$f:#"; done
fi

echo
echo "### Code files changed since $FROM (excluding vendor/node_modules/.git; on hosts with read-only code, any hit here is odd)"
find "$APPDIR" -xdev -newermt "$SINCE" -type f -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/.git/*' $(for m in $MOUNTS; do printf -- "-not -path %s/* " "$m"; done) -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort | tail -100

# --- Processes, connections, persistence --------------------------------------
echo
echo "### Suspicious processes"
PROCS=$(ps -eo pid,user,lstart,args 2>/dev/null | grep -E '(^|[ /])(nc|ncat|netcat|socat|perl|ruby|telnet|curl|wget|python[0-9.]*)( |$)|bash -i|sh -i|/dev/tcp/|(^| )/tmp/|(^| )/dev/shm/' | grep -v -E 'grep -E|bash -s --')
echo "${PROCS:-(none)}"

echo
echo "### Executables running from /tmp or /dev/shm"
EXETMP=$(for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null); case $e in /tmp/*|/dev/shm/*|*"(deleted)"*) echo "${p#/proc/} $e";; esac; done)
echo "${EXETMP:-(none)}"

echo
echo "### Established TCP connections (check remote ends are your DB, cache, mail relay or known APIs)"
if command -v ss >/dev/null 2>&1; then ss -tnp state established 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then netstat -tnp 2>/dev/null | grep ESTABLISHED
else
  awk 'NR>1 && $4=="01" {split($3,a,":"); ip=""; for(i=7;i>=1;i-=2) ip=ip strtonum("0x" substr(a[1],i,2)) (i>1?".":""); print ip ":" strtonum("0x" a[2])}' /proc/net/tcp 2>/dev/null | sort | uniq -c | sort -rn
fi

echo
echo "### Crontab for this user"
crontab -l 2>&1

echo
echo "### authorized_keys"
for k in "$HOME/.ssh/authorized_keys" "$APPDIR/.ssh/authorized_keys"; do [ -f "$k" ] && ls -la --time-style=full-iso "$k"; done 2>/dev/null
KEYS=$(find "$HOME/.ssh" -newermt "$SINCE" -type f 2>/dev/null)
[ -n "$KEYS" ] && echo "Changed since $FROM:" && echo "$KEYS"

echo
echo "### All processes"
ps auxf 2>/dev/null || ps aux

# --- Drupal -------------------------------------------------------------------
NEWUSERS=0; NEWADMINS=0; NEWMODULES=0; NOEXPORT=0
DRUSH=$(command -v drush 2>/dev/null || { [ -x vendor/bin/drush ] && echo vendor/bin/drush; })
if [ -n "$DRUSH" ] && $DRUSH status --field=bootstrap 2>/dev/null | grep -qi success; then
  TS=$(date -u -d "$SINCE" +%s 2>/dev/null || echo 0)
  DV=$($DRUSH status --field=drupal-version 2>/dev/null)
  echo
  echo "### Drupal $DV"
  case $DV in
    7.*) UT=users; RJ="users_roles r JOIN role ro ON ro.rid = r.rid JOIN users u ON u.uid = r.uid"; RW="ro.name = 'administrator'" ;;
    *)   UT=users_field_data; RJ="user__roles r JOIN users_field_data u ON u.uid = r.entity_id"; RW="r.roles_target_id = 'administrator'" ;;
  esac

  # Accounts made by a site install (or an environment rebuild) inside the window aren't news:
  # skip anything from the first hour after uid 1 was created.
  BASE=$TS
  INSTALLED=$($DRUSH sql:query "SELECT created FROM $UT WHERE uid = 1" 2>/dev/null | head -1 | tr -d '[:space:]')
  if [ -n "$INSTALLED" ] && [ "$INSTALLED" -ge "$TS" ] 2>/dev/null; then
    BASE=$((INSTALLED + 3600))
    echo "Site installed $(date -u -d "@$INSTALLED" +%Y-%m-%dT%H:%M:%SZ), inside the window; accounts from its first hour are not counted."
  fi

  echo
  echo "### Drupal: users created or changed since $(date -u -d "@$BASE" +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$UT" = users ]; then
    # Drupal 7 has no "changed" column; access/login show recent use.
    U=$($DRUSH sql:query "SELECT uid, name, mail, status, FROM_UNIXTIME(created), FROM_UNIXTIME(access), FROM_UNIXTIME(login) FROM users WHERE uid > 0 AND created >= $BASE ORDER BY created DESC" 2>&1)
  else
    U=$($DRUSH sql:query "SELECT uid, name, mail, status, FROM_UNIXTIME(created), FROM_UNIXTIME(changed), FROM_UNIXTIME(login) FROM users_field_data WHERE created >= $BASE OR changed >= $BASE ORDER BY changed DESC" 2>&1)
  fi
  echo "${U:-(none)}"
  NEWUSERS=$(printf '%s\n' "$U" | grep -cE '^[0-9]+[[:space:]]')
  UTOTAL=$($DRUSH sql:query "SELECT COUNT(*) FROM $UT WHERE uid > 0" 2>/dev/null | head -1 | tr -d '[:space:]')

  echo
  echo "### Drupal: administrators (cols: uid name mail created changed-or-access)"
  if [ "$UT" = users ]; then
    ADMINS=$($DRUSH sql:query "SELECT u.uid, u.name, u.mail, u.created, u.access FROM $RJ WHERE $RW ORDER BY u.created DESC" 2>&1)
  else
    ADMINS=$($DRUSH sql:query "SELECT u.uid, u.name, u.mail, u.created, u.changed FROM $RJ WHERE $RW ORDER BY u.changed DESC" 2>&1)
  fi
  echo "${ADMINS:-(none)}"
  ATOTAL=$(printf '%s\n' "$ADMINS" | grep -cE '^[0-9]+[[:space:]]')
  # Admin accounts created (D7) or changed (D8+) since BASE.
  NEWADMINS=$(printf '%s\n' "$ADMINS" | awk -v ts="$BASE" -v d7="$([ "$UT" = users ] && echo 1)" '$1 ~ /^[0-9]+$/ && ((d7 && $(NF-1) >= ts) || (!d7 && $NF >= ts))' | wc -l | tr -d ' ')

  if [ "$UT" != users ]; then
    # The advisory's concern is newly enabled modules, so compare those exactly; other config
    # differences are normal while a site is being built and are shown for context only.
    echo
    echo "### Drupal: modules enabled in the database but not in exported config"
    ROOT=$($DRUSH status --field=root 2>/dev/null)
    SYNC=$($DRUSH php:eval 'echo \Drupal\Core\Site\Settings::get("config_sync_directory");' 2>/dev/null)
    case $SYNC in /*) ;; ?*) SYNC="$ROOT/$SYNC" ;; esac
    ENABLED=$($DRUSH pm:list --type=module --status=enabled --field=name 2>/dev/null | sort -u)
    MODN=$(printf '%s\n' "$ENABLED" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ -n "$SYNC" ] && [ -f "$SYNC/core.extension.yml" ]; then
      EXPORTED=$(awk '/^module:/ {m = 1; next} /^[^ ]/ {m = 0} m && /^  [A-Za-z0-9_]+:/ {sub(/^  /, ""); sub(/:.*/, ""); print}' "$SYNC/core.extension.yml" | sort -u)
      EXPN=$(printf '%s\n' "$EXPORTED" | sed '/^$/d' | wc -l | tr -d ' ')
      EXTRA=$(comm -13 <(printf '%s\n' "$EXPORTED") <(printf '%s\n' "$ENABLED") | sed '/^$/d')
      echo "${EXTRA:-(none)}"
      NEWMODULES=$([ -z "$EXTRA" ] && echo 0 || printf '%s\n' "$EXTRA" | wc -l | tr -d ' ')
    else
      echo "(no exported core.extension.yml at ${SYNC:-?}; nothing to compare against)"
      NOEXPORT=1
    fi
    echo
    echo "### Drupal: config status (context only)"
    $DRUSH config:status 2>&1 | head -200
  fi

else
  echo
  echo "### Drupal: drush not found or site not bootstrapped, skipped"
fi

SESSN=0
[ -n "$SESSDIR" ] && [ -d "$SESSDIR" ] && SESSN=$(find "$SESSDIR" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l | tr -d ' ')
SHELLN=$(find $SCAN -xdev -type f -size -2M 2>/dev/null | wc -l | tr -d ' ')
PROCN=$(ps -e --no-headers 2>/dev/null | wc -l | tr -d ' ')
CONNN=$(awk 'NR > 1 && $4 == "01"' /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l | tr -d ' ')
CRONN=$(crontab -l 2>/dev/null | grep -cvE '^[[:space:]]*(#|$)')
echo
echo "@@STATS uprog=${UPROG:-?}:$UPROGSRC strict=${STRICT:-?}:$STRICTSRC feb=${FEB:-na}:$FEBSRC fpm=$([ -n "$FPM" ] && echo yes || echo no) php=$(php -r 'echo PHP_VERSION;' 2>/dev/null) sessdir=${SESSDIR:-none} sessions=$SESSN scandirs=$(printf '%s\n' "$SCAN" | paste -sd, -) changed=$(( $(count "$FILES") + $(count "$GENERATED") )) generated=$(count "$GENERATED") shellscan=$SHELLN history=$HISTN procs=$PROCN conns=$CONNN cron=$CRONN drupal=${DV:-none} users=${UTOTAL:-} admins=${ATOTAL:-} modules=${MODN:-} exported=${EXPN:-}"
echo "@@SUMMARY files=$(count "$FILES") php-in-files=$(count "$PHPINFILES") shells=$(count "$SHELLS") procs=$(count "$PROCS") tmp-exe=$(count "$EXETMP") session-files=$(count "$SESSBAD") ssh-keys-changed=$(count "$KEYS") shell-history=$(count "$HISTBAD") drupal-users-changed=$NEWUSERS drupal-admins-changed=$NEWADMINS modules-not-in-config=$NEWMODULES no-config-export=$NOEXPORT upload-progress-on=$([ "$UPROG" = 0 ] && echo 0 || echo 1) strict-mode-off=$([ "$STRICT" = 1 ] && echo 0 || echo 1) fatal-backtraces-on=$FEBON runtime-serializer-switch=$(count "$SERSWITCH")"
REMOTE
)

# ---------------------------------------------------------------------------
# Local log analysis helpers.
# ---------------------------------------------------------------------------
NGINX_TS='BEGIN { n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= n; i++) M[m[i]] = sprintf("%02d", i) }
function ts(line,   a) {
  if (!match(line, /\[[0-9]+\/[A-Za-z]+\/[0-9]+:[0-9]+:[0-9]+:[0-9]+/)) return ""
  split(substr(line, RSTART + 1, RLENGTH - 1), a, /[\/:]/)
  return a[3] "-" M[a[2]] "-" sprintf("%02d", a[1]) "T" a[4] ":" a[5] ":" a[6]
}'

filter_nginx() {
  awk -v f="$FROM" -v t="$TO" "$NGINX_TS"' { x = ts($0); if (x != "" && x >= f && x <= t) print }' "$1"
}

first_nginx_ts() {
  head -1 "$1" | awk "$NGINX_TS"' { print ts($0) }'
}

filter_iso() {
  awk -v f="$FROM" -v t="$TO" '{ ts = substr($1, 1, 19) } ts >= f && ts <= t' "$1"
}

# 0 if version $1 is at or above the fixed release for its branch
php_is_patched() {
  v=$1; branch=${v%.*}
  [ -z "$v" ] && return 3
  for fx in $FIXED_VERSIONS; do
    if [ "${fx%.*}" = "$branch" ]; then
      [ "$(printf '%s\n%s\n' "$fx" "$v" | sort -V | head -1)" = "$fx" ] && return 0 || return 1
    fi
  done
  return 2   # branch has no fix (unsupported)
}

# Counts error-log lines matching $1 (minus those matching $2) inside the review window, and the
# most within any $4 minutes. Prints "in-window busiest start", start "-" when under $3.
# Understands PHP's "[21-Oct-2026 04:01:00" and nginx/ISO "2026/10/21 04:01:00" timestamps.
burst_scan() {
  # shellcheck disable=SC2086
  cat $LOGS 2>/dev/null | grep -aE "$1" | { if [ -n "$2" ]; then grep -avE "$2"; else cat; fi; } |
  awk -v f="$FROM" -v t="$TO" 'BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= 12; i++) M[m[i]] = sprintf("%02d", i)
      split("0 31 59 90 120 151 181 212 243 273 304 334", c, " ") }
    { iso = ""
      if (match($0, /[0-9][0-9]-[A-Z][a-z][a-z]-[0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        x = substr($0, RSTART, RLENGTH); iso = substr(x, 8, 4) "-" M[substr(x, 4, 3)] "-" substr(x, 1, 2) "T" substr(x, 13, 8)
      } else if (match($0, /[0-9][0-9][0-9][0-9][-\/][0-9][0-9][-\/][0-9][0-9][ T][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        x = substr($0, RSTART, RLENGTH); iso = substr(x, 1, 4) "-" substr(x, 6, 2) "-" substr(x, 9, 2) "T" substr(x, 12, 8)
      }
      if (iso == "" || iso < f || iso > t) next
      y = substr(iso, 1, 4) + 0
      print ((y * 365 + int(y / 4) + c[substr(iso, 6, 2) + 0] + substr(iso, 9, 2)) * 24 + substr(iso, 12, 2)) * 60 + substr(iso, 15, 2), iso }' |
  sort -n | awk -v n="$3" -v win="$4" '{ tm[e] = $1; ts[e] = $2; e++; while (tm[e - 1] - tm[h] >= win) h++; if (e - h > best) { best = e - h; start = ts[h] } }
    END { printf "%d %d %s\n", e, best, (best >= n ? start : "-") }'
}

analyze() {
  dir=$1
  r="$dir/analysis.txt"
  flags=""; first=""; total=""; posts=""; putpatch=""; clients=""; postclients=""; logtotal=""
  {
    echo "Window (UTC): $FROM -> $TO"
    echo

    if [ -s "$dir/access.log" ]; then
      first=$(first_nginx_ts "$dir/access.log")
      logtotal=$(wc -l < "$dir/access.log" | tr -d ' ')
      echo "access.log starts at: ${first:-unknown}"
      if [ -n "$first" ] && [ "$first" \> "$FROM" ]; then
        echo "!! access.log does not reach back to $FROM - earlier traffic was already trimmed by $PLATFORM_NAME"
      fi
      W="$dir/access.window.log"
      filter_nginx "$dir/access.log" > "$W"
      total=$(wc -l < "$W" | tr -d ' ')
      posts=$(grep -a -c '"POST ' "$W")
      putpatch=$(grep -a -cE '"(PUT|PATCH) ' "$W")
      postclients=$(grep -a '"POST ' "$W" | awk '{print $1}' | sort -u | wc -l | tr -d ' ')
      clients=$(awk '{print $1}' "$W" | sort -u | wc -l | tr -d ' ')
      echo "Requests in window: $total   Clients: $clients   POSTs: $posts   PUT/PATCH: $putpatch"

      echo; echo "=== Requests from Amazon's published source IPs"
      ipre=$(echo "$KNOWN_IPS" | sed 's/\./\\./g; s/ /|/g')
      ipHits=$(grep -a -E "^($ipre) " "$W")
      echo "${ipHits:-(none)}" | head -200
      ipCount=$([ -z "$ipHits" ] && echo 0 || printf '%s\n' "$ipHits" | wc -l | tr -d ' ')

      echo; echo "=== Requests per client and method (first pass)"
      awk '{print $1, $6}' "$W" | tr -d '"' | sort | uniq -c | sort -rn | head -25
      echo; echo "=== PUT / PATCH requests (browsers never send multipart on these)"
      grep -a -E '"(PUT|PATCH) ' "$W" | tail -100
      echo; echo "=== Top POST URLs"
      grep -a '"POST ' "$W" | awk '{print $7}' | sort | uniq -c | sort -rn | head -30
      echo; echo "=== Top POST client IPs"
      grep -a '"POST ' "$W" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
      echo; echo "=== POST bursts: one client, same page (query string ignored), $POST_BURST+ POSTs within $POST_BURST_MINUTES minutes"
      echo "(cols: POSTs in the busiest window, client, page, window start)"
      # Minutes on a monotonic scale (mawk has no mktime), then a sliding window per client and page.
      bursts=$(grep -a '"POST ' "$W" | awk 'BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= 12; i++) M[m[i]] = i
          split("0 31 59 90 120 151 181 212 243 273 304 334", c, " ") }
        { split(substr($4, 2), t, /[\/:]/); path = $7; sub(/\?.*/, "", path)
          print $1, path, ((t[3] * 365 + int(t[3] / 4) + c[M[t[2]]] + t[1]) * 24 + t[4]) * 60 + t[5], substr($4, 2) }' |
        sort -k1,1 -k2,2 -k3,3n |
        awk -v n="$POST_BURST" -v win="$POST_BURST_MINUTES" '
          { k = $1 " " $2; if (k != prev) { emit(); prev = k; h = 0; e = 0; best = 0 }
            tm[e] = $3; ts[e] = $4; e++
            while (tm[e - 1] - tm[h] >= win) h++
            if (e - h > best) { best = e - h; start = ts[h] } }
          END { emit() }
          function emit() { if (prev != "" && best >= n) print best, prev, start }' | sort -rn)
      echo "${bursts:-(none)}" | head -40
      burstN=$([ -z "$bursts" ] && echo 0 || printf '%s\n' "$bursts" | wc -l | tr -d ' ')
      echo; echo "=== Largest POST requests by response bytes"
      grep -a '"POST ' "$W" | sort -t' ' -k10 -n -r | head -20
      echo; echo "=== Requests carrying the upload-progress field name (AWS step 3; bodies are not logged, so only query strings show up)"
      upHits=$(grep -a -iE 'PHP_SESSION_UPLOAD_PROGRESS|upload_progress' "$W")
      echo "${upHits:-(none)}" | head -100
      upCount=$([ -z "$upHits" ] && echo 0 || printf '%s\n' "$upHits" | wc -l | tr -d ' ')
      echo; echo "=== Requests touching PHP files in uploads/files or inclusion patterns"
      grep -a -Ei 'uploads/[^ ]*\.ph(p|tml|ar)|/files/[^ ]*\.ph(p|tml|ar)|\.\./|sess_|php://|/tmp/' "$W" | head -100

      [ "$ipCount" -gt 0 ] && flags="$flags KNOWN-IPS=$ipCount"
      [ "$putpatch" -gt 0 ] && flags="$flags PUT/PATCH=$putpatch"
      [ "$burstN" -gt 0 ] && flags="$flags POST-BURSTS=$burstN"
      [ "$upCount" -gt 0 ] && flags="$flags UPLOAD-PROGRESS-FIELD=$upCount"
    else
      echo "access.log: missing or empty"
      flags="$flags NO-ACCESS-LOG"
    fi

    if [ -s "$dir/php.access.log" ]; then
      echo; echo "php.access.log starts at: $(head -1 "$dir/php.access.log" | awk '{print $1}')"
      filter_iso "$dir/php.access.log" > "$dir/php.access.window.log"
      echo; echo "=== Heaviest PHP POSTs by memory (cols: time method status ms 'ms' kB 'kB' cpu uri)"
      grep -a ' POST ' "$dir/php.access.window.log" | sort -k6 -n -r | head -30
      echo; echo "=== PHP POST status counts"
      grep -a ' POST ' "$dir/php.access.window.log" | awk '{print $3}' | sort | uniq -c | sort -rn
    fi

    LOGS=$(for f in $ERROR_LOGS; do printf '%s ' "$dir/$(basename "$f")"; done)
    echo; echo "=== PHP_SESSION_UPLOAD_PROGRESS in app/error/php logs"
    # shellcheck disable=SC2086
    upLog=$(cat $LOGS 2>/dev/null | grep -a -i 'PHP_SESSION_UPLOAD_PROGRESS')
    echo "${upLog:-(none)}" | tail -50
    [ -n "$upLog" ] && flags="$flags UPLOAD-PROGRESS-FIELD-IN-LOGS=$(printf '%s\n' "$upLog" | wc -l | tr -d ' ')"

    echo; echo "=== Worker crashes in app/error/php logs (all dates, grouped)"
    # shellcheck disable=SC2086
    crashes=$(cat $LOGS 2>/dev/null | grep -a -iE 'exited on signal|Segmentation fault|SIGSEGV|SIGABRT|SIGBUS|core dumped')
    if [ -n "$crashes" ]; then
      printf '%s\n' "$crashes" | cut -c1-120 | sort | uniq -c | sort -rn | head -20
      echo; echo "--- last 50 raw lines"
      printf '%s\n' "$crashes" | tail -50
      flags="$flags CRASHES=$(printf '%s\n' "$crashes" | wc -l | tr -d ' ')"
    else
      echo "(none)"
    fi

    echo; echo "=== Memory and timeout errors in app/error/php logs (all dates, grouped)"
    # shellcheck disable=SC2086
    mem=$(cat $LOGS 2>/dev/null | grep -a -iE 'memory size of|out of memory|Maximum execution time')
    if [ -n "$mem" ]; then
      printf '%s\n' "$mem" | cut -c1-120 | sort | uniq -c | sort -rn | head -20
      echo; echo "--- last 50 raw lines"
      printf '%s\n' "$mem" | tail -50
      n=$(printf '%s\n' "$mem" | wc -l | tr -d ' ')
      if [ "$n" -ge "$MEMORY_ERRORS" ]; then flags="$flags MEMORY-ERRORS=$n"; else flags="$flags note:memory-errors=$n"; fi
    else
      echo "(none)"
    fi

    # GHSA-6wmf-4rv5-p3rp: the attack's first request ends in a fatal error (timeouts and memory are
    # counted above); its second shows up as diagnostics raised before any script runs.
    FATALRE='Fatal error|Parse error|Compile Error|Core Error|Uncaught [A-Za-z_\\]*(Error|Exception)|Failed opening required'
    MEMRE='memory size of|out of memory|Maximum execution time'
    echo; echo "=== Fatal, parse and uncaught errors in the window ($FATAL_BURST+ within $FATAL_BURST_MINUTES minutes is a burst)"
    read -r fatalN fatalMax fatalStart <<<"$(burst_scan "$FATALRE" "$MEMRE" "$FATAL_BURST" "$FATAL_BURST_MINUTES")"
    echo "In the window: $fatalN   busiest $FATAL_BURST_MINUTES minutes: $fatalMax$([ "$fatalStart" != - ] && echo ", starting $fatalStart")"
    echo "--- last 30 matching lines (all dates)"
    # shellcheck disable=SC2086
    cat $LOGS 2>/dev/null | grep -aE "$FATALRE" | grep -avE "$MEMRE" | cut -c1-200 | tail -30
    if [ "$fatalStart" != - ]; then flags="$flags FATAL-BURSTS=$fatalMax"; elif [ "$fatalN" -gt 0 ]; then flags="$flags note:fatal-errors=$fatalN"; fi

    echo; echo "=== Diagnostics 'in Unknown on line 0' in the window ($LINE0_BURST+ within $LINE0_BURST_MINUTES minutes is a burst)"
    read -r line0N line0Max line0Start <<<"$(burst_scan 'in Unknown on line 0' '' "$LINE0_BURST" "$LINE0_BURST_MINUTES")"
    echo "In the window: $line0N   busiest $LINE0_BURST_MINUTES minutes: $line0Max$([ "$line0Start" != - ] && echo ", starting $line0Start")"
    echo "--- last 30 matching lines (all dates)"
    # shellcheck disable=SC2086
    cat $LOGS 2>/dev/null | grep -a 'in Unknown on line 0' | cut -c1-200 | tail -30
    if [ "$line0Start" != - ]; then flags="$flags LINE0-BURSTS=$line0Max"; elif [ "$line0N" -gt 0 ]; then flags="$flags note:line0=$line0N"; fi

    # shellcheck disable=SC2086
    echo; echo "@@STATS logstart=${first:-} logtotal=${logtotal:-} requests=${total:-} clients=${clients:-} posts=${posts:-} postclients=${postclients:-} putpatch=${putpatch:-} loglines=$(cat $LOGS 2>/dev/null | wc -l | tr -d ' ') ips=$(echo $KNOWN_IPS | wc -w | tr -d ' ') fatal=$fatalN fatalmax=$fatalMax line0=$line0N line0max=$line0Max"
  } > "$r"
  echo "$flags"
}

# ---------------------------------------------------------------------------
# HTML report: report.html in the report folder, self-contained, readable offline.
# ---------------------------------------------------------------------------
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

# Sets TITLE, WHY, EFILE (container|analysis) and EHEAD (section heading prefix) for a flag key.
describe() {
  EFILE=container; EHEAD=""
  case $1 in
    PHP-UNPATCHED) TITLE="PHP is not patched"; WHY="This PHP is older than the fixed release for its branch. Redeploy so the container picks up the patched image."; EHEAD="### PHP version" ;;
    PHP-UNSUPPORTED) TITLE="PHP branch has no fix"; WHY="No fixed release exists for this PHP branch. Move the app to a supported PHP version."; EHEAD="### PHP version" ;;
    PHP-UNKNOWN) TITLE="PHP version could not be read"; WHY="The version check didn't return a version, so patch status is unknown."; EHEAD="### PHP version" ;;
    KNOWN-IPS) TITLE="Requests from Amazon's published attack IPs"; WHY="These addresses were seen exploiting this bug. They are shared anonymizers, so read what they requested."; EFILE=analysis; EHEAD="=== Requests from Amazon" ;;
    PUT/PATCH) TITLE="PUT or PATCH requests"; WHY="Browsers never send uploads this way. Check who sent them and whether an API client you know explains it."; EFILE=analysis; EHEAD="=== PUT / PATCH" ;;
    POST-BURSTS) TITLE="Bursts of POSTs to one page"; WHY="A client sent $POST_BURST or more POSTs to the same page within $POST_BURST_MINUTES minutes, which is how exploit attempts look in the logs. Check who sent them."; EFILE=analysis; EHEAD="=== POST bursts" ;;
    UPLOAD-PROGRESS-FIELD) TITLE="Requests naming PHP_SESSION_UPLOAD_PROGRESS"; WHY="The exploit uses this upload-progress field. Normal Drupal traffic never sends it."; EFILE=analysis; EHEAD="=== Requests carrying" ;;
    UPLOAD-PROGRESS-FIELD-IN-LOGS) TITLE="PHP_SESSION_UPLOAD_PROGRESS in error logs"; WHY="The exploit uses this upload-progress field. Normal Drupal traffic never mentions it."; EFILE=analysis; EHEAD="=== PHP_SESSION_UPLOAD_PROGRESS in" ;;
    CRASHES) TITLE="PHP worker crashes"; WHY="PHP-FPM workers died on a signal. That is rare on a healthy site and is a side effect of this exploit."; EFILE=analysis; EHEAD="=== Worker crashes" ;;
    MEMORY-ERRORS) TITLE="Many memory or timeout errors"; WHY="A burst of memory exhaustion or timeouts can be the exploit grinding on PHP."; EFILE=analysis; EHEAD="=== Memory and timeout" ;;
    memory-errors) TITLE="Memory or timeout errors"; WHY="A handful happen on any Drupal site."; EFILE=analysis; EHEAD="=== Memory and timeout" ;;
    session-files) TITLE="Tampered PHP session files"; WHY="Session files with PHP code, upload-progress keys or malformed names are the exploit's footprint."; EHEAD="### PHP session directory" ;;
    files) TITLE="New script or hidden files in writable folders"; WHY="Someone or something wrote these since the window began, and Drupal didn't generate them."; EHEAD="### Script-like" ;;
    php-in-files) TITLE="PHP file inside a files folder"; WHY="Uploaded-files folders should never hold PHP."; EHEAD="### Any PHP-type file" ;;
    shells) TITLE="Webshell-like code"; WHY="These files contain code that runs commands sent in a web request."; EHEAD="### Webshell" ;;
    procs) TITLE="Suspicious processes"; WHY="Shells, downloaders or programs from /tmp running in the container."; EHEAD="### Suspicious processes" ;;
    tmp-exe) TITLE="Program running from /tmp or /dev/shm"; WHY="Legitimate code doesn't run from these folders; dropped malware does."; EHEAD="### Executables running" ;;
    shell-history) TITLE="Attacker-style commands in shell history"; WHY="Commands that download files, open reverse shells or add persistence. Confirm each was someone on your team."; EHEAD="### Shell history" ;;
    ssh-keys-changed) TITLE="SSH keys changed"; WHY="Files under ~/.ssh changed in the window."; EHEAD="### authorized_keys" ;;
    drupal-admins-changed) TITLE="Administrator accounts created or changed"; WHY="Confirm each one was a person on your team."; EHEAD="### Drupal: administrators" ;;
    drupal-users-changed) TITLE="User accounts created or changed"; WHY="Normal on a site with registrations or staff edits."; EHEAD="### Drupal: users created" ;;
    modules-not-in-config) TITLE="Modules enabled outside exported config"; WHY="These modules are on in the database but not in the config in git. Attackers enable modules like PHP filter or devel."; EHEAD="### Drupal: modules enabled" ;;
    could-not-connect) TITLE="Could not connect"; WHY="$PLATFORM_CLI could not open a shell in the app. Check the environment name (-e) and that it is active."; EHEAD="" ;;
    no-config-export) TITLE="Enabled modules not compared"; WHY="The site has no exported core.extension.yml, so there is no list of expected modules to check against."; EHEAD="### Drupal: modules enabled" ;;
    LOGS-ONLY) TITLE="Logs only"; WHY="This run read copied log files only, so the PHP version, sessions, files, processes and Drupal were not checked. Run it inside the app's container for those."; EHEAD="" ;;
    NO-ACCESS-LOG) TITLE="No access log"; WHY="The web traffic checks could not run."; EFILE=analysis; EHEAD="access.log" ;;
    CONTAINER-CHECKS-INCOMPLETE) TITLE="Container checks didn't finish"; WHY="The checks inside the container stopped part way; see container.txt and ssh-errors.txt." ;;
    LOGS-TRIMMED) TITLE="Access log doesn't reach back to the window start"; WHY="$PLATFORM_NAME already discarded the oldest traffic, so the earliest days weren't checked."; EFILE=analysis; EHEAD="access.log starts at" ;;
    upload-progress-on) TITLE="session.upload_progress.enabled must be 0"; WHY="Required by both PHP advisories (GHSA-6wmf-4rv5-p3rp, CVE-2026-115560). Drupal doesn't use it. Set it in php.ini or the FPM pool ($CONFIG_HINT); ini_set() and .user.ini don't count."; EHEAD="### Required PHP settings" ;;
    strict-mode-off) TITLE="session.use_strict_mode must be 1"; WHY="Required by the Drupal Association's guidance, so PHP rejects made-up session IDs. Set it in php.ini or the FPM pool ($CONFIG_HINT)."; EHEAD="### Required PHP settings" ;;
    fatal-backtraces-on) TITLE="fatal_error_backtraces must be 0 (PHP 8.5)"; WHY="This is the confirmed remote-code-execution path in GHSA-6wmf-4rv5-p3rp. Set it in php.ini or the FPM pool ($CONFIG_HINT) until PHP is patched."; EHEAD="### Required PHP settings" ;;
    runtime-serializer-switch) TITLE="Code switches session.serialize_handler at runtime"; WHY="With upload progress on, this is the trigger for CVE-2026-115560. Keeping session.upload_progress.enabled at 0 closes it."; EHEAD="--- code that switches" ;;
    FATAL-BURSTS) TITLE="Burst of fatal errors"; WHY="Many fatal, parse or uncaught errors within minutes. A fatal interruption is the first half of the GHSA-6wmf-4rv5-p3rp attack."; EFILE=analysis; EHEAD="=== Fatal, parse" ;;
    fatal-errors) TITLE="Fatal errors in the window"; WHY="A few fatal errors happen on any site under development or after a deploy."; EFILE=analysis; EHEAD="=== Fatal, parse" ;;
    LINE0-BURSTS) TITLE="Burst of 'in Unknown on line 0' diagnostics"; WHY="Warnings raised before any script runs, many within minutes. That is how the second half of the GHSA-6wmf-4rv5-p3rp attack looks in the logs."; EFILE=analysis; EHEAD="=== Diagnostics" ;;
    line0) TITLE="'in Unknown on line 0' diagnostics"; WHY="A few appear when PHP-FPM starts, for example a module loaded twice."; EFILE=analysis; EHEAD="=== Diagnostics" ;;
    *) TITLE=$1; WHY="" ;;
  esac
}

# Prints one report section (heading line to the next heading), HTML-escaped.
evidence() {   # $1 = file, $2 = heading prefix
  [ -n "$2" ] && [ -f "$1" ] || return 0
  awk -v p="$2" 'index($0, p) == 1 {on = 1; print; next} on && (/^### / || /^=== /) {exit} on' "$1" | head -80 | esc
}

# One finding as a collapsible row.
html_item() {   # $1 = dir, $2 = key=count
  key=${2%%=*}; n=""; case $2 in *=*) n=${2#*=} ;; esac
  describe "$key"
  ev=$(evidence "$1/$EFILE.txt" "$EHEAD")
  printf '<details><summary><span class="t">%s</span>%s<span class="why">%s</span></summary>' \
    "$(printf '%s' "$TITLE" | esc)" "${n:+<span class=\"n\">$n</span>}" "$(printf '%s' "$WHY" | esc)"
  [ -n "$ev" ] && printf '<pre>%s</pre>' "$ev"
  printf '</details>\n'
}

# Reads one value from the @@STATS lines strider wrote for an app.
stat() {   # $1 = app dir, $2 = key
  sed -n 's/^@@STATS //p' "$1/container.txt" "$1/analysis.txt" 2>/dev/null | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1
}
num() { printf '%s' "${1:-0}" | sed -e ':a' -e 's/\([0-9]\)\([0-9]\{3\}\)\($\|,\)/\1,\2\3/' -e 'ta'; }

# Result cell for a check: Flagged if any of its keys is under review, Not checked if incomplete.
result() {   # keys...
  for k in "$@"; do case " $review " in *" $k "*|*" $k="*) echo flag; return ;; esac; done
  for k in "$@"; do case " $hardening " in *" $k "*) echo action; return ;; esac; done
  for k in "$@"; do case " $incomplete " in *" $k "*|*" $k="*) echo skip; return ;; esac; done
  echo clean
}
row() {   # $1 = check, $2 = what was examined, $3 = advisory step, $4 = result, $5 = outcome when clean
  case $4 in
    flag) r='<span class="res flag">Flagged</span>'; o="Flagged; see Findings." ;;
    action) r='<span class="res todo">Change required</span>'; o="Wrong; see Required settings." ;;
    skip) r='<span class="res skip">Not checked</span>'; o="Not checked." ;;
    info) r='<span class="res info">Not compared</span>'; o="Not compared." ;;
    *)    r='<span class="res clean">Clean</span>'; o=${5:-Nothing found.} ;;
  esac
  printf '<tr><td class="c">%s<span class="step">%s</span></td><td><b class="o">%s</b> %s</td><td>%s</td></tr>\n' \
    "$(printf '%s' "$1" | esc)" "$(printf '%s' "$3" | esc)" "$(printf '%s' "$o" | esc)" "$(printf '%s' "$2" | esc)" "$r"
}
has_note() { case " $notes " in *" $1="*|*" $1 "*) return 0 ;; esac; return 1; }
plural() { [ "$1" = 1 ] && printf '%s' "$2" || printf '%s' "${3:-${2}s}"; }

# The "What we checked" table: each check leads with its outcome, then says what it examined.
html_checks() {   # $1 = app dir
  d=$1
  php=$(stat "$d" php); logstart=$(stat "$d" logstart); req=$(stat "$d" requests); cl=$(stat "$d" clients)
  posts=$(stat "$d" posts); pp=$(stat "$d" putpatch); ll=$(stat "$d" loglines); ips=$(stat "$d" ips)
  sessn=$(stat "$d" sessions); sessdir=$(stat "$d" sessdir); dirs=$(stat "$d" scandirs); ch=$(stat "$d" changed)
  gen=$(stat "$d" generated); shn=$(stat "$d" shellscan); pr=$(stat "$d" procs); co=$(stat "$d" conns)
  cr=$(stat "$d" cron); dv=$(stat "$d" drupal); us=$(stat "$d" users); ad=$(stat "$d" admins)
  mo=$(stat "$d" modules); ex=$(stat "$d" exported); hi=$(stat "$d" history)
  ndirs=$(printf '%s\n' "$dirs" | tr ',' '\n' | sed '/^$/d' | wc -l | tr -d ' ')
  dirs=$(printf '%s' "$dirs" | sed 's/,/, /g')
  echo '<h3 data-moon="What Strider read in the tracks">What we checked</h3><div class="tw"><table class="checks"><thead><tr><th>Check</th><th>Outcome and what we examined</th><th>Result</th></tr></thead><tbody>'
  if [ -n "$php" ]; then
    row "PHP version" "Running PHP $php; the fixed releases are $FIXED_VERSIONS." "AWS 1" "$(result PHP-UNPATCHED PHP-UNSUPPORTED PHP-UNKNOWN)" "Patched."
    setting() { v=${1%%:*}; src=${1#*:}; case $v in na|'') echo "not on this PHP" ;; *) echo "$v ($src)" ;; esac; }
    row "Required PHP settings" "session.upload_progress.enabled $(setting "$(stat "$d" uprog)"), session.use_strict_mode $(setting "$(stat "$d" strict)"), fatal_error_backtraces $(setting "$(stat "$d" feb)"). Values are what the web server's PHP uses: FPM pool overrides first, then FPM's ini files$([ "$(stat "$d" fpm)" = no ] && echo "; PHP-FPM wasn't found, so these are the CLI values")." "PHP advisories" "$(result upload-progress-on strict-mode-off fatal-backtraces-on)" "All correct."
  else
    row "PHP version" "The PHP version could not be read on this run." "AWS 1" skip
  fi
  if [ -n "$req" ]; then
    row "Log coverage" "The access log reaches back to ${logstart:-unknown}, before the review window starts ($FROM UTC)." "Drupal: preserve evidence" "$(result LOGS-TRIMMED)" "Whole window covered."
    if [ "$req" = 0 ]; then
      row "Known attacker addresses" "No requests reached this app in the window; all $(num "$(stat "$d" logtotal)") access-log entries predate $FROM UTC." "AWS 4" "$(result KNOWN-IPS)" "No requests to match."
      row "Upload-progress exploit field" "Searched $(num "$ll") lines of app, error and PHP logs for PHP_SESSION_UPLOAD_PROGRESS. There were no requests in the window to search." "AWS 3" "$(result UPLOAD-PROGRESS-FIELD UPLOAD-PROGRESS-FIELD-IN-LOGS)" "Not present."
      row "Request patterns" "No requests in the window, so no POST, PUT or PATCH activity to review." "AWS 4" "$(result PUT/PATCH POST-BURSTS)" "No requests to review."
    else
      row "Known attacker addresses" "Checked $(num "$req") $(plural "$req" request) from $(num "$cl") $(plural "$cl" client) against the $ips source addresses Amazon published." "AWS 4" "$(result KNOWN-IPS)" "No matches."
      row "Upload-progress exploit field" "Searched $(num "$req") $(plural "$req" request) and $(num "$ll") lines of app, error and PHP logs for PHP_SESSION_UPLOAD_PROGRESS." "AWS 3" "$(result UPLOAD-PROGRESS-FIELD UPLOAD-PROGRESS-FIELD-IN-LOGS)" "Not present."
      row "Request patterns" "Checked $(num "$posts") $(plural "$posts" POST) from $(num "$(stat "$d" postclients)") $(plural "$(stat "$d" postclients)" client) for bursts of $POST_BURST or more to the same page within $POST_BURST_MINUTES minutes, and $(num "$pp") PUT/PATCH $(plural "$pp" request), which browsers never send." "AWS 4" "$(result PUT/PATCH POST-BURSTS)" "No bursts."
    fi
  else
    row "Web traffic" "The access log could not be read, so the request checks did not run." "AWS 3, 4" skip
  fi
  row "PHP crashes and memory errors" "Searched $(num "$ll") lines of app, error and PHP logs for worker crashes, memory exhaustion and timeouts." "Drupal: error logs" "$(result CRASHES MEMORY-ERRORS)" \
    "$(has_note memory-errors && echo "No crashes; a few memory errors, below the alert level." || echo "None found.")"
  row "Fatal and parse errors" "Found $(num "$(stat "$d" fatal)") fatal, parse or uncaught $(plural "$(stat "$d" fatal)" error) in the window; the busiest $FATAL_BURST_MINUTES minutes had $(num "$(stat "$d" fatalmax)"). A fatal interruption is the first half of this attack." "PHP advisory" "$(result FATAL-BURSTS)" \
    "$(has_note fatal-errors && echo "No bursts; a few, below the alert level." || echo "None in the window.")"
  row "Pre-request diagnostics" "Found $(num "$(stat "$d" line0)") $(plural "$(stat "$d" line0)" warning) reported 'in Unknown on line 0', raised before any script runs; the busiest $LINE0_BURST_MINUTES minutes had $(num "$(stat "$d" line0max)")." "PHP advisory" "$(result LINE0-BURSTS)" \
    "$(has_note line0 && echo "No bursts; a few, below the alert level." || echo "None in the window.")"
  if [ -n "$php" ]; then
    if [ "${sessn:-0}" = 0 ]; then
      row "PHP session store" "The PHP session store ($sessdir) held no session files to tamper with; Drupal keeps its sessions in the database." "Drupal: session store" "$(result session-files)" "Empty."
    else
      row "PHP session store" "Inspected $(num "$sessn") session $(plural "$sessn" file) in $sessdir for PHP code, upload-progress keys and malformed IDs." "Drupal: session store" "$(result session-files)" "None tampered with."
    fi
    row "Files written since the window began" "Reviewed $(num "$ch") $(plural "$ch" file) changed since the window began across $ndirs writable folders ($dirs). $(num "$gen") $(plural "$gen" is are) generated by Drupal itself; any other would be listed under Findings." "AWS 5" "$(result files php-in-files)" "None unexplained."
    row "Webshell signatures" "Read $(num "$shn") $(plural "$shn" file) in those folders for code that runs commands sent in a web request, Drupal-generated PHP included." "AWS 5" "$(result shells)" "None found."
    row "Running processes" "Inspected $(num "$pr") running $(plural "$pr" process processes) for shells, downloaders and programs started from /tmp or /dev/shm. $(num "$co") open $(plural "$co" connection) listed in the raw output." "AWS 5" "$(result procs tmp-exe)" "None suspicious."
    row "Persistence" "Listed $(num "$cr") crontab $(plural "$cr" entry entries) and checked ~/.ssh for keys changed since the window began." "Drupal: persistence" "$(result ssh-keys-changed)" "No changes."
    row "Shell history" "Read $(num "$hi") shell history $(plural "$hi" command) for downloaders, reverse shells and persistence." "AWS 5" "$(result shell-history)" "Nothing suspicious."
    if [ "$dv" != none ] && [ -n "$dv" ]; then
      row "Drupal accounts" "Reviewed $(num "$us") $(plural "$us" account) and $(num "$ad") $(plural "$ad" administrator) for accounts created or changed since the window began (Drupal $dv)." "Drupal: accounts" "$(result drupal-admins-changed)" "No unexpected administrators."
      if [ -n "$ex" ]; then
        row "Drupal modules" "Compared $(num "$mo") enabled $(plural "$mo" module) with the $(num "$ex") in exported config." "Drupal: config drift" "$(result modules-not-in-config)" "None unexpected."
      elif [ -n "$mo" ]; then
        row "Drupal modules" "Found $(num "$mo") enabled $(plural "$mo" module), but the site has no exported config to compare them with." "Drupal: config drift" info
      fi
    else
      row "Drupal" "Drush was not available, so the account and module checks did not run." "Drupal" skip
    fi
  else
    if [ "$(result LOGS-ONLY)" = skip ]; then
      row "Inside the container" "Logs-only run: sessions, files, processes, shell history and Drupal were not checked." "AWS 5" skip
    else
      row "Inside the container" "The container checks did not finish, so files, sessions, processes and Drupal were not checked." "AWS 5" skip
    fi
  fi
  echo '</tbody></table></div>'
}

# A card for one app, appended to the per-status file so REVIEW cards come first.
html_card() {   # $1 = status word, $2 = label, $3 = dir, $4 = php line; then $review $incomplete $notes $hardening via globals
  st=$1; rel=${3#"$OUT"/}
  {
    printf '<section class="app %s">\n' "$(echo "$st" | tr '[:upper:]' '[:lower:]')"
    printf '<header><span class="badge">%s</span><h2>%s</h2><span class="meta">%s</span></header>\n' "$([ "$st" = ACTION ] && echo "ACTION REQUIRED" || echo "$st")" "$(printf '%s' "$PTITLE" | esc)" "$(printf '%s · %s' "$2" "$4" | esc)"
    case $st in
      OK) echo '<p class="lead">Every check ran and none of them found a trace of the exploit.</p>' ;;
      INCOMPLETE) echo '<p class="lead">Nothing was found, but some checks could not run, so this is not proof the app is clean.</p>' ;;
      REVIEW) echo '<p class="lead">These findings need a person to look at them.</p>' ;;
      ACTION) echo '<p class="lead">No trace of the exploit, but required PHP settings are wrong. Change them and redeploy.</p>' ;;
    esac
    [ -n "$review" ] && { echo '<h3>Findings</h3>'; for kv in $review; do html_item "$3" "$kv"; done; }
    [ -n "$incomplete" ] && { echo '<h3>Not checked</h3>'; for kv in $incomplete; do html_item "$3" "$kv"; done; }
    case $incomplete in could-not-connect) ;; *) html_checks "$3" ;; esac
    if [ -n "$hardening" ]; then
      n=$(echo $hardening | wc -w | tr -d ' ')
      printf '<div class="todo"><h3>Required settings <span class="n">%s</span></h3>\n' "$n"
      echo '<p>These are not signs of an attack. The PHP and Drupal advisories require these settings, and this app has them wrong.</p>'
      for kv in $hardening; do html_item "$3" "$kv"; done
      printf '<p class="paste">Add this to the app in <code>%s</code>, then redeploy:</p><pre>variables:\n' "$(printf '%s' "$CONFIG_HINT" | esc)"
      echo '  php:'
      case " $hardening " in *" upload-progress-on "*) echo '    session.upload_progress.enabled: 0' ;; esac
      case " $hardening " in *" strict-mode-off "*) echo '    session.use_strict_mode: 1' ;; esac
      case " $hardening " in *" fatal-backtraces-on "*) echo '    fatal_error_backtraces: 0' ;; esac
      echo '</pre></div>'
    fi
    [ -n "$notes" ] && { echo '<h3 class="muted">For context</h3>'; for kv in $notes; do html_item "$3" "$kv"; done; }
    printf '<footer>Raw evidence: '
    for f in analysis.txt container.txt ssh-errors.txt access.log php.access.log $(for e in $ERROR_LOGS; do basename "$e"; done); do
      [ -s "$3/$f" ] && printf '<a href="%s">%s</a> ' "$(printf '%s' "$rel/$f" | esc)" "$f"
    done
    printf '</footer>\n</section>\n'
  } >> "$OUT/.cards-$st.html"
  printf '%s\t%s\t%s\n' "$PTITLE" "$P" "$PENV" >> "$OUT/.sites"
  if [ -n "$hardening" ]; then HARDEN_APPS=$((HARDEN_APPS + 1)); HARDEN_STEPS=$((HARDEN_STEPS + $(echo $hardening | wc -w))); fi
}

html_page() {
  N=$((REVIEW_N + ACTION_N + INCOMPLETE_N + OK_N))
  if [ "$REVIEW_N" -eq 0 ] && [ "$ACTION_N" -eq 0 ] && [ "$INCOMPLETE_N" -eq 0 ]; then
    vmoon="No orc-sign on any path. Strider followed the trail to its end and found it clean."
    vclass=ok; verdict="No trace of the exploit on $([ "$N" -eq 1 ] && echo "the 1 app" || echo "any of the $N apps") checked."
    vsub="Every check ran to completion. The evidence behind that is below."
  elif [ "$REVIEW_N" -gt 0 ]; then
    vmoon="Strider has found orc-sign. Follow the tracks below."
    vclass=review; verdict="$REVIEW_N of $N $([ "$N" -eq 1 ] && echo app || echo apps) $([ "$REVIEW_N" -eq 1 ] && echo needs || echo need) a closer look."
    vsub="The findings are listed first, each with the evidence that raised it."
  elif [ "$ACTION_N" -gt 0 ]; then
    vmoon="The trail is clean, but a gate stands open. Close it."
    vclass=action; verdict="No trace of the exploit, but $ACTION_N of $N $([ "$N" -eq 1 ] && echo app || echo apps) $([ "$ACTION_N" -eq 1 ] && echo needs || echo need) required PHP settings changed."
    vsub="Wrong settings are not signs of an attack. The yellow boxes say what to change."
  else
    vmoon="The trail went cold in places; not every path could be read."
    vclass=incomplete; verdict="Nothing found, but $INCOMPLETE_N of $N $([ "$N" -eq 1 ] && echo app || echo apps) could not be fully checked."
    vsub="See Not checked on each card for what was missed and why."
  fi
  # Totals across every app for the evidence strip.
  t_req=0; t_lt=0; t_ll=0; t_files=0; t_sess=0; t_proc=0; t_users=0
  for d in "$OUT"/*/; do
    [ -f "$d/container.txt" ] || continue
    t_req=$((t_req + $(stat "$d" requests | grep -E '^[0-9]+$' || echo 0)))
    t_lt=$((t_lt + $(stat "$d" logtotal | grep -E '^[0-9]+$' || echo 0)))
    t_ll=$((t_ll + $(stat "$d" loglines | grep -E '^[0-9]+$' || echo 0)))
    t_files=$((t_files + $(stat "$d" shellscan | grep -E '^[0-9]+$' || echo 0)))
    t_sess=$((t_sess + $(stat "$d" sessions | grep -E '^[0-9]+$' || echo 0)))
    t_proc=$((t_proc + $(stat "$d" procs | grep -E '^[0-9]+$' || echo 0)))
    t_users=$((t_users + $(stat "$d" users | grep -E '^[0-9]+$' || echo 0)))
  done
  {
    cat <<'HEAD'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Ithildin report</title>
<style>
:root { --bg:#0e1116; --panel:#151a21; --panel2:#1b212a; --fg:#e6e9ee; --muted:#8b95a3; --line:#262e39; --code:#0b0e12;
  --moon:#c9d7f2; --moon-dim:#7f93b8; --ok:#5fd39a; --ok-bg:rgba(95,211,154,.10); --rev:#ff7b72; --rev-bg:rgba(255,123,114,.10);
  --inc:#e8b85c; --inc-bg:rgba(232,184,92,.10); --todo:#f2d36b; --todo-bg:rgba(242,211,107,.08); color-scheme:dark; }
* { box-sizing:border-box }
body { margin:0; background:var(--bg) radial-gradient(ellipse 900px 380px at 50% -120px, rgba(150,175,230,.13), transparent 70%) no-repeat;
  color:var(--fg); font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; min-height:100vh }
main { max-width:1040px; margin:0 auto; padding:32px 16px 72px }
body::before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.55;
  background-image:radial-gradient(1px 1px at 12% 18%, #c9d7f2, transparent), radial-gradient(1px 1px at 78% 9%, #c9d7f2, transparent),
    radial-gradient(1px 1px at 33% 72%, #9fb1d4, transparent), radial-gradient(1.5px 1.5px at 64% 44%, #c9d7f2, transparent),
    radial-gradient(1px 1px at 88% 66%, #9fb1d4, transparent), radial-gradient(1px 1px at 22% 91%, #c9d7f2, transparent),
    radial-gradient(1px 1px at 51% 27%, #9fb1d4, transparent), radial-gradient(1.5px 1.5px at 6% 52%, #c9d7f2, transparent),
    radial-gradient(1px 1px at 94% 31%, #c9d7f2, transparent), radial-gradient(1px 1px at 43% 96%, #9fb1d4, transparent) }
main { position:relative }
header.top { position:relative; text-align:center; padding-top:58px; margin-bottom:26px }
header.top .arch { position:absolute; top:-8px; left:50%; transform:translateX(-50%); width:min(100%, 820px); height:auto; pointer-events:none }
header.top .brand { justify-content:center }
.brand { display:flex; align-items:center; gap:10px; margin-bottom:14px; color:var(--moon); font-size:13px; letter-spacing:.22em; text-transform:uppercase; font-weight:600 }
.brand svg { flex:none; filter:drop-shadow(0 0 6px rgba(201,215,242,.45)) }
.brand .kind { color:var(--muted); font-weight:400; letter-spacing:.12em }
h1.site { margin:0; font:600 46px/1.1 "Palatino Linotype",Palatino,"Book Antiqua","URW Palladio L",Georgia,serif; color:#f3f5fa;
  letter-spacing:.01em; overflow-wrap:anywhere; text-shadow:0 0 28px rgba(150,175,230,.25) }
.siteinfo { margin:8px 0 0; color:var(--muted); font-size:14px } .siteinfo b { color:var(--fg); font-weight:600 }
.runes { display:flex; align-items:center; gap:14px; margin:18px 0 14px; color:var(--moon-dim); opacity:.75 }
.runes::before, .runes::after { content:""; flex:1; height:1px; background:linear-gradient(90deg, transparent, var(--moon-dim), transparent) }
.runes span { font-size:15px; letter-spacing:.5em; padding-left:.5em; text-shadow:0 0 10px rgba(201,215,242,.5) }
@media (max-width:640px) { h1.site { font-size:34px } header.top { padding-top:40px } }
#egg { background:none; border:0; padding:4px 0 4px .5em; font:inherit; font-size:15px; letter-spacing:.5em; color:inherit; cursor:pointer;
  text-shadow:0 0 10px rgba(201,215,242,.5); transition:color .4s, text-shadow .4s }
#egg:hover, #egg:focus-visible { color:var(--moon); text-shadow:0 0 14px rgba(201,215,242,.95); outline:none }
.moonletters { margin:0 auto 10px; max-width:560px; font:italic 14px/1.5 "Palatino Linotype",Palatino,Georgia,serif; color:var(--moon);
  opacity:0; height:0; overflow:hidden; transition:opacity 1.6s ease }
/* Moon-letter mode */
.moonlit body { background:var(--bg) radial-gradient(ellipse 1000px 520px at 50% -140px, rgba(170,195,245,.26), transparent 70%) no-repeat }
.moonlit body::after { content:""; position:fixed; top:36px; right:6vw; width:84px; height:84px; border-radius:50%; pointer-events:none;
  box-shadow:inset -18px 6px 0 0 #e8eefb; filter:drop-shadow(0 0 22px rgba(220,230,255,.55)); opacity:.85; animation:rise 2.4s ease-out both }
.moonlit body::before { animation:twinkle 3.2s ease-in-out infinite alternate }
.moonlit header.top .arch { filter:brightness(2.2) drop-shadow(0 0 6px rgba(201,215,242,.9)); animation:glow 4s ease-in-out infinite alternate }
.moonlit h1.site { text-shadow:0 0 22px rgba(201,215,242,.85), 0 0 2px #fff; animation:glow 4s ease-in-out infinite alternate }
.moonlit .moonletters { opacity:.95; height:auto; text-shadow:0 0 12px rgba(201,215,242,.8) }
.moonlit h3, .moonlit .method h2 { font-family:"Palatino Linotype",Palatino,Georgia,serif; text-transform:none; letter-spacing:.02em; font-size:14px;
  color:var(--moon); text-shadow:0 0 8px rgba(201,215,242,.6) }
.moonlit .todo h3 { color:var(--todo); text-shadow:0 0 8px rgba(242,211,107,.5) }
.moonlit .app { border-top-color:#c9d7f2; box-shadow:0 0 0 1px rgba(201,215,242,.12), 0 0 34px rgba(150,175,230,.12), 0 12px 32px rgba(0,0,0,.4) }
.moonlit .verdict .big { font-family:"Palatino Linotype",Palatino,Georgia,serif; font-weight:600 }
.moonlit .runes span, .moonlit #egg { color:var(--moon); text-shadow:0 0 16px rgba(201,215,242,1) }
@keyframes twinkle { from { opacity:.35 } to { opacity:.95 } }
@keyframes glow { from { filter:brightness(1.6) drop-shadow(0 0 4px rgba(201,215,242,.6)) } to { filter:brightness(2.4) drop-shadow(0 0 10px rgba(201,215,242,1)) } }
@keyframes rise { from { transform:translateY(60px); opacity:0 } to { transform:none; opacity:.85 } }
@media (prefers-reduced-motion:reduce) { .moonlit * , .moonlit body::before, .moonlit body::after { animation:none !important } }
.tag { color:var(--moon-dim); margin:0 0 4px; font-size:14px }
.sub { color:var(--muted); margin:0; font-size:12.5px }
.verdict { padding:22px 24px; border-radius:12px; margin-bottom:16px; border:1px solid var(--line) }
.verdict .big { font-size:22px; font-weight:650; line-height:1.3 } .verdict .small { color:var(--muted); margin-top:4px; font-size:14px }
.verdict.ok { background:var(--ok-bg); border-color:rgba(95,211,154,.35) } .verdict.ok .big { color:var(--ok) }
.verdict.review { background:var(--rev-bg); border-color:rgba(255,123,114,.35) } .verdict.review .big { color:var(--rev) }
.verdict.action { background:var(--todo-bg); border-color:rgba(242,211,107,.4) } .verdict.action .big { color:var(--todo) }
.app.action { border-top-color:var(--todo) } .action .badge { background:var(--todo-bg); color:var(--todo) }
.res.todo { color:var(--todo); background:var(--todo-bg) }
.verdict.incomplete { background:var(--inc-bg); border-color:rgba(232,184,92,.35) } .verdict.incomplete .big { color:var(--inc) }
.todo-banner { display:flex; gap:12px; align-items:flex-start; padding:12px 16px; margin:-4px 0 16px; border-radius:10px;
  background:var(--todo-bg); border:1px solid rgba(242,211,107,.35); color:#e9dfb8; font-size:14px }
.todo-banner b { color:var(--todo) } .todo-banner .ico { color:var(--todo); font-size:18px; line-height:1.2 }
.todo { margin:20px 0 4px; padding:4px 16px 14px; border-radius:10px; background:var(--todo-bg); border:1px solid rgba(242,211,107,.35);
  border-left:4px solid var(--todo) }
.todo h3 { color:var(--todo) } .todo h3::before { content:"⚑"; color:var(--todo); opacity:1 }
.todo h3 .n { background:rgba(242,211,107,.18); color:var(--todo); text-transform:none; letter-spacing:0 }
.todo > p { margin:0 0 6px; color:#d9d2b4; font-size:13.5px } .todo details { border-top-color:rgba(242,211,107,.2) }
.todo summary .t { color:var(--todo) } .todo .paste { margin-top:12px } .todo code { color:var(--todo) }
.todo pre { border-color:rgba(242,211,107,.25) }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(124px,1fr)); gap:10px; margin-bottom:28px }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px }
.stat b { display:block; font-size:24px; font-weight:650; color:var(--moon); font-variant-numeric:tabular-nums }
.stat span { color:var(--muted); font-size:12.5px }
.app { position:relative; background:linear-gradient(180deg, rgba(201,215,242,.035), transparent 160px), var(--panel); border:1px solid var(--line);
  border-top:3px solid var(--line); border-radius:12px; padding:18px 20px; margin-bottom:18px; box-shadow:0 12px 32px rgba(0,0,0,.35) }
.app::after { content:""; position:absolute; left:20px; right:20px; top:-3px; height:3px; border-radius:3px; pointer-events:none;
  background:linear-gradient(90deg, transparent, rgba(255,255,255,.55), transparent); opacity:.35 }
.app.ok { border-top-color:var(--ok) } .app.review { border-top-color:var(--rev) } .app.incomplete { border-top-color:var(--inc) }
.app header { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap }
.app h2 { font-size:18px; margin:0; overflow-wrap:anywhere } .meta { color:var(--muted); font-size:13px }
.badge { font-size:11px; font-weight:700; letter-spacing:.06em; padding:2px 8px; border-radius:4px }
.ok .badge { background:var(--ok-bg); color:var(--ok) } .review .badge { background:var(--rev-bg); color:var(--rev) }
.incomplete .badge { background:var(--inc-bg); color:var(--inc) }
.lead { margin:8px 0 4px; color:var(--fg) }
h3 { font-size:12px; text-transform:uppercase; letter-spacing:.08em; margin:20px 0 8px; color:var(--moon-dim) }
h3::before { content:"ᛝ"; margin-right:8px; color:var(--moon); opacity:.7; letter-spacing:0 }
b.o { color:var(--fg) } .checks td:nth-child(2) { color:#c3cad5 } h3.muted { color:var(--muted) }
.tw { overflow-x:auto; border:1px solid var(--line); border-radius:8px }
table.checks { width:100%; border-collapse:collapse; font-size:13.5px }
.checks th { text-align:left; font-weight:600; color:var(--muted); font-size:12px; padding:8px 12px; background:var(--panel2); border-bottom:1px solid var(--line) }
.checks td { padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top }
.checks tr:last-child td { border-bottom:0 }
.checks td.c { font-weight:600; min-width:170px } .step { display:block; font-weight:400; color:var(--muted); font-size:11.5px; margin-top:2px }
.checks td:last-child { white-space:nowrap }
.res { font-size:12px; font-weight:650; padding:2px 8px; border-radius:99px }
.res.clean { color:var(--ok); background:var(--ok-bg) } .res.clean::before { content:"✓ " }
.res.flag { color:var(--rev); background:var(--rev-bg) } .res.skip { color:var(--inc); background:var(--inc-bg) }
.res.info { color:var(--muted); background:var(--panel2) }
.checks td { overflow-wrap:anywhere }
@media (max-width:640px) {
  .checks thead { display:none }
  .checks tr { display:grid; grid-template-columns:1fr auto; border-bottom:1px solid var(--line) }
  .checks tr:last-child { border-bottom:0 }
  .checks td { border:0; padding:10px 12px 4px }
  .checks td.c { min-width:0 }
  .checks td:nth-child(2) { grid-column:1 / -1; grid-row:2; padding:0 12px 12px }
  .checks td:nth-child(3) { grid-column:2; grid-row:1 }
}
details { border-top:1px solid var(--line); padding:9px 0 } summary { cursor:pointer; margin-left:16px }
summary .t { font-weight:600 } summary .why { display:block; color:var(--muted); font-size:13px }
.n { display:inline-block; margin-left:8px; padding:0 7px; border-radius:99px; background:var(--panel2); font-size:12px; font-weight:600 }
pre { background:var(--code); border:1px solid var(--line); padding:10px 12px; border-radius:6px; overflow-x:auto; font-size:12px; line-height:1.45; margin:8px 0 0; color:#c8d0db }
footer { margin-top:14px; font-size:12.5px; color:var(--muted) } footer a { color:var(--moon-dim); margin-right:8px }
.method { margin-top:36px; display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px }
.method section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px 20px; font-size:14px }
.method h2 { font-size:15px; margin:0 0 8px; color:var(--moon); font-family:"Palatino Linotype",Palatino,"Book Antiqua",Georgia,serif; font-weight:600 } .method li { margin:4px 0 } .method ol, .method ul { padding-left:20px; margin:0 }
.method a { color:var(--moon) } .method p { margin:0 0 8px; color:var(--muted) }
.colophon { margin-top:10px; color:var(--muted); font-size:12px; text-align:center; font-style:italic; font-family:"Palatino Linotype",Palatino,Georgia,serif }
</style></head><body><main>
<header class="top"><svg class="arch" viewBox="0 0 1000 170" preserveAspectRatio="xMidYMin meet" aria-hidden="true"><defs><path id="st" d="M0-7 1.6-1.6 7 0 1.6 1.6 0 7-1.6 1.6-7 0-1.6-1.6z"/></defs><g fill="none" stroke="#c9d7f2" stroke-width="1.2"><path d="M110 170V96A390 92 0 0 1 890 96V170" opacity=".35"/><path d="M128 170V100A372 82 0 0 1 872 100V170" opacity=".18"/><circle cx="500" cy="26" r="12" opacity=".5"/></g><path d="M504 15a12 12 0 1 0 0 22a9.5 9.5 0 0 1 0-22z" fill="#c9d7f2" opacity=".75"/><g fill="#c9d7f2"><use href="#st" x="380" y="44" opacity=".45"/><use href="#st" x="420" y="34" opacity=".55"/><use href="#st" x="460" y="28" opacity=".65"/><use href="#st" x="540" y="28" opacity=".65"/><use href="#st" x="580" y="34" opacity=".55"/><use href="#st" x="620" y="44" opacity=".45"/><use href="#st" x="500" y="62" opacity=".8" transform="rotate(0)"/></g></svg>
<div class="brand"><svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="13" fill="none" stroke="#c9d7f2" stroke-width="1.5"/><path d="M21 6.5a11 11 0 1 0 0 19a9 9 0 0 1 0-19z" fill="#c9d7f2"/></svg><span>Ithildin</span><span class="kind">forensic review</span></div>
HEAD
    # The h1 is the site that was scanned: one name, or a count with the names under it.
    nsites=$(cut -f1-2 "$OUT/.sites" 2>/dev/null | sort -u | wc -l | tr -d ' ')
    if [ "$nsites" -eq 1 ]; then
      IFS=$'\t' read -r st_title st_proj st_env < "$OUT/.sites"
      printf '<h1 class="site">%s</h1>\n' "$(printf '%s' "$st_title" | esc)"
      printf '<p class="siteinfo">%s project %s · environment <b>%s</b></p>\n' "$(printf '%s' "$PLATFORM_NAME" | esc)" "$(printf '%s' "$st_proj" | esc)" "$(printf '%s' "$st_env" | esc)"
    else
      printf '<h1 class="site">%s sites</h1>\n' "$nsites"
      printf '<p class="siteinfo">%s</p>\n' "$(awk -F'\t' '!seen[$1 FS $2]++ {printf "%s%s (%s)", (n++ ? " · " : ""), $1, $3}' "$OUT/.sites" | esc)"
    fi
    echo '<div class="runes" aria-hidden="true"><span>ᛁᛏᚻᛁᛚᛞᛁᚾ</span></div>'
    echo '<p class="moonletters" aria-hidden="true">Written in moon-letters: the logs were read by this light, and the trail followed to its end.</p>'
    echo '<p class="tag">Forensic review for the October 2026 PHP vulnerabilities (CVE-2026-109618, CVE-2026-109619)</p>'
    printf '<p class="sub">Review window %s → %s UTC · generated %s · tracked by Strider</p>\n' "$FROM" "$TO" "$(date -u +%Y-%m-%dT%H:%MZ)"
    echo '</header>'
    printf '<div class="verdict %s"><div class="big" data-moon="%s">%s</div><div class="small">%s</div></div>\n' "$vclass" "$vmoon" "$verdict" "$vsub"
    if [ "$HARDEN_STEPS" -gt 0 ]; then
      printf '<div class="todo-banner"><span class="ico" aria-hidden="true">⚑</span><div><b>%s required %s to change</b> on %s %s. Not signs of an attack, but the advisories require them: see the yellow %s below.</div></div>\n' \
        "$HARDEN_STEPS" "$([ "$HARDEN_STEPS" -eq 1 ] && echo setting || echo settings)" "$HARDEN_APPS" "$([ "$HARDEN_APPS" -eq 1 ] && echo app || echo apps)" "$([ "$HARDEN_APPS" -eq 1 ] && echo box || echo boxes)"
    fi
    echo '<div class="stats">'
    printf '<div class="stat"><b>%s</b><span>%s</span></div>' "$N" "$([ "$N" -eq 1 ] && echo "app examined" || echo "apps examined")"
    # Zero tiles are left out; the per-app tables still show every count.
    tile() { [ "$1" -gt 0 ] && printf '<div class="stat"><b>%s</b><span>%s</span></div>' "$(num "$1")" "$2"; }
    tile "$t_lt" "access-log entries read"
    tile "$t_req" "web requests in the window"
    tile "$t_ll" "error and app log lines searched"
    tile "$t_files" "files scanned for webshells"
    tile "$t_sess" "PHP sessions inspected"
    tile "$t_proc" "processes inspected"
    tile "$t_users" "Drupal accounts reviewed"
    echo '</div>'
    cat "$OUT/.cards-REVIEW.html" "$OUT/.cards-ACTION.html" "$OUT/.cards-INCOMPLETE.html" "$OUT/.cards-OK.html" 2>/dev/null
    sed "s/@PLATFORM@/$PLATFORM_NAME/g" <<'TAIL'
<div class="method">
<section><h2>How this review was done</h2>
<p>Strider connects to each app's container read-only, saves its logs before anything can rotate them, and works through the published guidance:</p>
<ul>
<li><a href="https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites">Drupal Association: auditing your Drupal sites</a>: error logs, PHP session store, files directories, processes and persistence, accounts and config.</li>
<li>AWS recommended actions: patched PHP (1), PHP_SESSION_UPLOAD_PROGRESS in requests (3), web server logs (4), process execution and file changes (5).</li>
</ul>
<p style="margin-top:8px">Nothing on the servers is changed. Every number in this report was counted during the run, and the raw evidence for each app is linked from its card.</p></section>
<section><h2>What logs can't show</h2>
<ul>
<li>Access logs don't record request bodies, so an upload-progress payload sent in a form body is caught through its side effects (session files, crashes, request patterns), not by reading it directly.</li>
<li>Someone with control of the container could have edited its logs. They are scanned anyway, since an intruder may not have bothered.</li>
<li>A clean result means no trace was found in what the container still holds. Logs @PLATFORM@ has already trimmed are reported as Not checked.</li>
<li>Amazon's attacker addresses belong to shared anonymizers: a match calls for a closer look, and no match proves nothing alone.</li>
</ul></section>
<section><h2>If a finding looks real</h2>
<ol>
<li>Don't redeploy yet if you can avoid it. The container and its mounts are evidence. Contact @PLATFORM@ support.</li>
<li>Keep this report folder; it includes the logs.</li>
<li>Rotate every secret the app could read: database credentials, hash salt, API keys, SMTP credentials, deploy keys.</li>
<li>Check other sites that share those secrets.</li>
<li>Rebuild on patched PHP rather than cleaning in place, and diff settings.php and services.yml against git.</li>
</ol></section>
</div>
<div class="runes"><button type="button" id="egg" title="Speak, friend, and enter" aria-label="Moon-letter mode" aria-pressed="false">ᛁᛏᚻᛁᛚᛞᛁᚾ</button></div>
<p class="colophon">Ithildin · read by the light of the logs; the trail was followed by Strider</p>
</main>
<script>
// Easter egg: click the runes, or type "mellon", for moon-letter mode. Purely cosmetic; findings and evidence don't change.
(function () {
  var root = document.documentElement, egg = document.getElementById("egg");
  var words = [[".badge", {OK: "Safe passage", REVIEW: "Orc-sign", "ACTION REQUIRED": "Gate unbarred", INCOMPLETE: "Trail lost"}],
               [".res", {"Clean": "Unmarked", "Flagged": "Orc-sign", "Not checked": "Trail lost", "Not compared": "Unread", "Change required": "Bar the gate"}]];
  function swap(el, alt, on) {
    if (el.dataset.plain === undefined) el.dataset.plain = el.textContent;
    el.textContent = on && alt ? alt : el.dataset.plain;
  }
  function set(on) {
    root.classList.toggle("moonlit", on);
    egg.setAttribute("aria-pressed", on ? "true" : "false");
    words.forEach(function (w) {
      document.querySelectorAll(w[0]).forEach(function (el) {
        var plain = el.dataset.plain === undefined ? el.textContent : el.dataset.plain;
        swap(el, w[1][plain], on);
      });
    });
    document.querySelectorAll("[data-moon]").forEach(function (el) { swap(el, el.dataset.moon, on); });
  }
  egg.addEventListener("click", function () { set(!root.classList.contains("moonlit")); });
  var typed = "";
  document.addEventListener("keydown", function (e) {
    if (!e.key || e.key.length !== 1) return;
    typed = (typed + e.key.toLowerCase()).slice(-6);
    if (typed === "mellon") set(true);
  });
})();
</script>
</body></html>
TAIL
  } > "$OUT/report.html"
  rm -f "$OUT"/.cards-*.html "$OUT/.sites"
}

# ---------------------------------------------------------------------------
# Main loop.
# ---------------------------------------------------------------------------
OK_N=0; REVIEW_N=0; ACTION_N=0; INCOMPLETE_N=0; HARDEN_APPS=0; HARDEN_STEPS=0
for P in $PROJECTS; do
  PENV=$ENV
  [ -z "$PENV" ] && PENV=$(platform_default_env "$P" 2>/dev/null </dev/null)
  PENV=${PENV:-main}
  PTITLE=$(platform_title "$P" 2>/dev/null </dev/null)
  PTITLE=${PTITLE:-$P}
  APPS=$(platform_apps "$P" "$PENV" 2>/dev/null </dev/null)
  [ -z "$APPS" ] && APPS="_default_"

  for A in $APPS; do
    if [ "$A" = "_default_" ]; then APP=""; label="$P"; else APP=$A; label="$P/$A"; fi
    dir="$OUT/$P-$PENV${APP:+-$APP}"
    mkdir -p "$dir"
    echo "==> $label ($PENV)"

    # Save logs first so they are captured before anything else happens.
    fetch() { platform_ssh "$P" "$PENV" "$APP" "cat '$1' 2>/dev/null" > "$2" 2>/dev/null </dev/null; }
    [ -n "$ACCESS_LOG" ] && fetch "$ACCESS_LOG" "$dir/access.log"
    [ -n "$PHP_ACCESS_LOG" ] && fetch "$PHP_ACCESS_LOG" "$dir/php.access.log"
    for f in $ERROR_LOGS; do fetch "$f" "$dir/$(basename "$f")"; done

    # A config can turn the in-container checks off (local.conf does outside ddev): logs only.
    LOGSONLY=""
    if [ "${CONTAINER_CHECKS:-1}" = 0 ]; then
      LOGSONLY=1
      echo "Container checks skipped (CONTAINER_CHECKS=0, $CONFIG): this run read log files only." > "$dir/container.txt"
    elif ! platform_ssh "$P" "$PENV" "$APP" "bash -s -- '$FROM' '$APP_DIR_VAR' '$APP_DIR_DEFAULT' '$LOG_DIR'" <<<"$REMOTE_SCRIPT" > "$dir/container.txt" 2> "$dir/ssh-errors.txt"; then
      echo "    could not connect (see $dir/ssh-errors.txt)"
      echo "[$label] INCOMPLETE: could not connect - check env name with -e (see $dir/ssh-errors.txt)" >> "$SUMMARY"
      INCOMPLETE_N=$((INCOMPLETE_N + 1))
      echo >> "$SUMMARY"
      review=""; incomplete="could-not-connect"; notes=""; hardening=""
      html_card INCOMPLETE "$label" "$dir" "environment $PENV"
      continue
    fi

    flags=$(analyze "$dir")
    remote=$(grep '^@@SUMMARY' "$dir/container.txt" | sed 's/^@@SUMMARY //')
    phpv=$(sed -n '/^### PHP version/{n;p;}' "$dir/container.txt" | tr -d '[:space:]')
    grep -q '^!! access.log does not reach back' "$dir/analysis.txt" && flags="$flags LOGS-TRIMMED"

    if [ -n "$LOGSONLY" ]; then
      flags="$flags LOGS-ONLY"; patch="not checked, logs only"
    else
      # No summary line means the container checks died part way; don't report OK.
      [ -z "$remote" ] && flags="$flags CONTAINER-CHECKS-INCOMPLETE"
      php_is_patched "$phpv"
      case $? in
        0) patch="patched" ;;
        1) patch="NOT PATCHED"; flags="$flags PHP-UNPATCHED" ;;
        2) patch="UNSUPPORTED BRANCH (no fix released)"; flags="$flags PHP-UNSUPPORTED" ;;
        *) patch="UNKNOWN (version not read)"; flags="$flags PHP-UNKNOWN" ;;
      esac
    fi

    # REVIEW: something to look into. INCOMPLETE: a check couldn't run, so a clean result proves
    # nothing. Notes are normal in small numbers and don't change the status.
    review=""; incomplete=""; notes=""; hardening=""
    for kv in $flags $remote; do
      case $kv in
        *=0) ;;
        upload-progress-on=*|strict-mode-off=*|fatal-backtraces-on=*) hardening="$hardening ${kv%=*}" ;;
        note:*) notes="$notes ${kv#note:}" ;;
        drupal-users-changed=*|no-config-export=*|runtime-serializer-switch=*) notes="$notes ${kv%=1}" ;;
        NO-ACCESS-LOG|CONTAINER-CHECKS-INCOMPLETE|LOGS-TRIMMED|PHP-UNKNOWN|LOGS-ONLY) incomplete="$incomplete $kv" ;;
        *) review="$review $kv" ;;
      esac
    done

    # REVIEW (signs of attack) outranks ACTION (required settings wrong), which outranks INCOMPLETE.
    if [ -n "$review" ]; then status="REVIEW:$review"; REVIEW_N=$((REVIEW_N + 1))
    elif [ -n "$hardening" ]; then status="ACTION:$hardening"; ACTION_N=$((ACTION_N + 1))
    elif [ -n "$incomplete" ]; then status="INCOMPLETE:$incomplete"; INCOMPLETE_N=$((INCOMPLETE_N + 1))
    else status="OK"; OK_N=$((OK_N + 1)); fi
    [ -n "$review$hardening" ] && [ -n "$incomplete" ] && status="$status (also incomplete:$incomplete)"
    {
      echo "[$label] PHP $phpv ($patch)"
      echo "    $status"
      [ -n "$notes" ] && echo "    notes (normal in small numbers):$notes"
      [ -n "$hardening" ] && echo "    required settings to change:$hardening"
      echo "    details: $dir/analysis.txt, $dir/container.txt"
      echo
    } >> "$SUMMARY"
    echo "    PHP $phpv ($patch) - $status"
    html_card "${status%%:*}" "$label" "$dir" "$([ -n "$LOGSONLY" ] && echo "logs only" || echo "PHP $phpv ($patch)") · environment $PENV"
  done
done

{
  if [ "$REVIEW_N" -eq 0 ] && [ "$ACTION_N" -eq 0 ] && [ "$INCOMPLETE_N" -eq 0 ]; then
    echo "RESULT: all $OK_N apps OK - nothing unusual found."
  else
    echo "RESULT: $REVIEW_N to review, $ACTION_N need required settings changed, $INCOMPLETE_N incomplete, $OK_N OK."
  fi
  echo
} | tee -a "$SUMMARY" > "$OUT/RESULT.txt"
html_page

sed -e "s/@PLATFORM@/$PLATFORM_NAME/g" -e "s|@CONFIG_HINT@|$CONFIG_HINT|g" >> "$SUMMARY" <<'EOF'
Status:
  OK          Every check ran and nothing unusual turned up.
  REVIEW      At least one indicator below. Read analysis.txt / container.txt for that app.
  ACTION      No trace of an attack, but required PHP settings are wrong and must be changed.
  INCOMPLETE  Nothing found, but some checks couldn't run, so that isn't proof the app is clean.

How to read this (look for clusters of indicators, not single hits):
  PHP-UNPATCHED / PHP-UNSUPPORTED  Redeploy or rebuild to pick up the fixed image, or move to a supported branch.
  PHP-UNKNOWN        The PHP version could not be read; check container.txt.
  KNOWN-IPS          Requests from Amazon's published source IPs. A hit warrants a closer look; no hit proves nothing.
  PUT/PATCH          Browsers never send multipart bodies on these. Check analysis.txt for who sent them.
  POST-BURSTS        A client sent several POSTs to the same page within minutes. Check who and when in analysis.txt.
  UPLOAD-PROGRESS-FIELD(-IN-LOGS)
                     A logged request names PHP_SESSION_UPLOAD_PROGRESS. Normal Drupal traffic never does.
  CRASHES            PHP-FPM workers died on a signal (segfault/abort). Rare on a healthy site.
  MEMORY-ERRORS      Many memory-exhaustion or timeout errors. A few are normal; dozens in minutes are not.
  session-files      PHP session files with a PHP tag, an upload_progress_ key, or a malformed ID.
  files / php-in-files / shells / tmp-exe / procs / ssh-keys-changed / shell-history
                     Dropped files, webshells or odd processes. Treat as a possible compromise.
  drupal-admins-changed
                     An administrator account was created or changed in the window (accounts from a site
                     install in the window are not counted). Confirm it was you.
  modules-not-in-config
                     Modules enabled in the database that the exported config doesn't list.
  notes              memory-errors, fatal-errors, line0 and drupal-users-changed are normal in small
                     numbers on a busy site; glance at them in container.txt / analysis.txt.
                     no-config-export means the site has no exported module list to compare against.
  NO-ACCESS-LOG      The access log could not be read; the web traffic checks did not run.
  LOGS-ONLY          Only copied log files were read (CONTAINER_CHECKS=0); nothing inside a container was checked.
  CONTAINER-CHECKS-INCOMPLETE
                     The in-container checks stopped before finishing; see container.txt and ssh-errors.txt.
  LOGS-TRIMMED       @PLATFORM@ already discarded part of the window; a clean result there proves nothing.
  ACTION / required settings to change
                     No trace of an attack, but required PHP settings are wrong: session.upload_progress.enabled=0,
                     session.use_strict_mode=1 and, on PHP 8.5, fatal_error_backtraces=0. Set them in php.ini or the
                     FPM pool (variables: php: in @CONFIG_HINT@); ini_set() and .user.ini don't count.
  FATAL-BURSTS       Many fatal/parse/uncaught errors within minutes: the first half of GHSA-6wmf-4rv5-p3rp.
  LINE0-BURSTS       Many "in Unknown on line 0" diagnostics within minutes: the second half of that attack.

If you find something:
  1. Don't redeploy yet if you can avoid it; the container and its mounts are evidence. Contact @PLATFORM@ support.
  2. Keep this report folder (logs included).
  3. Rotate every secret the app could read: DB credentials, hash salt, API keys, SMTP credentials, deploy keys.
  4. Check other sites sharing those secrets.
  5. Rebuild on patched PHP rather than cleaning in place, and diff settings.php / services.yml against git.
EOF

echo
cat "$SUMMARY"
# "latest" always points at the newest report, so there's one path to open.
ln -sfn "$OUT" latest 2>/dev/null
echo "Open in a browser: file://$(pwd)/latest/report.html"
