# Ithildin

Ithildin checks hosted Drupal and PHP sites for traces of the October 2026 PHP vulnerabilities (CVE-2026-109618 and CVE-2026-109619). It follows the two published sets of advice:

- Amazon Threat Intelligence's recommended actions (patch PHP, look for `PHP_SESSION_UPLOAD_PROGRESS` in requests, review web server logs, check for unexpected processes and file changes).
- The Drupal Association's [After the PHP security release: auditing your Drupal sites](https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites).

The scanner is `strider.sh`. It connects to each app over the host's CLI, reads logs and the filesystem without changing anything, and writes a report you open in a browser. Out of the box it talks to Upsun (and Platform.sh). It can also read log files you copied to your own machine or into a ddev site, and a config file describes any other host.

## The names

Strider is the scanner. Aragorn found the hobbits' trail across Rohan from a dropped brooch and footprints in the grass, and that's the job here: reading the small traces an intruder leaves in access logs, session files and writable folders.

Ithildin is the report, and the project as a whole. It's the moon-silver on the Doors of Durin, invisible until the right light hits it. The same idea is behind the moon-letters on Thror's map, which only show under a moon matching the night they were written. That fits forensics. The traces are already in your logs and session files, and they only appear when you look with the right advisory in hand.

## Quick start

You need bash, GNU coreutils/findutils on the app side (standard on Upsun), and the Upsun CLI logged in (`upsun login`).

```bash
git clone https://github.com/Greg-Boggs/Ithildin.git ~/Ithildin
mkdir -p ~/ithildin-reports && cd ~/ithildin-reports
~/Ithildin/strider.sh -p PROJECT_ID -e main
xdg-open latest/report.html
```

With no `-p`, Strider scans every project your account can see, each on its default branch. Other options:

```
-p PROJECT   scan this project (repeat for more)
-e ENV       environment to scan (default: each project's default branch)
-f / -t      review window in UTC, e.g. -f 2026-10-17T00:00:00 (default: 17 Oct 2026 to now)
-c FILE      host config (default: upsun.conf next to strider.sh)
```

Run it from a folder in your home directory. Browsers installed as snaps or flatpaks can't open files under `/tmp`.

## The report

Each run writes `ithildin-report-<time>/` in the current folder and points `latest` at it. Inside:

- `report.html` is the report for people. Every app gets a card with its verdict, a "What we checked" table that leads each check with its outcome and the counts behind it, and links to the raw evidence. It loads nothing from the internet.
- `SUMMARY.txt` and `RESULT.txt` hold the same verdicts as plain text.
- One folder per app with the copied logs, `analysis.txt` (log analysis) and `container.txt` (everything read inside the container).

Each app gets one of three verdicts.

| Verdict | Meaning |
|---|---|
| OK | Every check ran and none found a trace. |
| REVIEW | At least one check found something a person should look at. The card lists each finding with its evidence. |
| INCOMPLETE | Nothing was found, but a check couldn't run (no connection, no access log, log already trimmed). That is not proof the app is clean. |

PHP settings the advisory recommends changing show up separately as yellow "Hardening to do" boxes, with the config to paste. They don't change the verdict.

## What Strider checks

| Check | How | What it can miss |
|---|---|---|
| PHP version | Compares the running PHP with the fixed release for its branch (8.5.12, 8.4.27, 8.3.36, 8.2.35). | Reads the command-line PHP. On Upsun the web server uses the same build. |
| Log coverage | The access log must reach back to the start of the window. | Only the access log is checked for trimming. |
| Known attacker addresses | Exact match of each request's client IP against the 6 addresses Amazon published. | Behind a CDN the log may hold the CDN's address. These are shared anonymizers, so a miss proves nothing. |
| Upload-progress field | Searches the access log and error logs for `PHP_SESSION_UPLOAD_PROGRESS`. | Access logs don't record POST bodies, so this only catches the field in a URL. The session and crash checks catch the side effects. |
| PUT/PATCH and POST bursts | Flags any PUT/PATCH, and any client sending 5 or more POSTs to the same page within 10 minutes. | An attacker spreading requests across many addresses stays under the per-client limit. |
| Crashes and memory errors | PHP-FPM workers dying on a signal always flag. Memory and timeout errors flag at 20 or more. | Not limited to the window. An attacker could have edited the logs; they're read anyway. |
| PHP session store | Session files containing PHP code, `upload_progress_` keys or malformed IDs. | Reads the session folder the command-line PHP is configured with. |
| Files written | Script, `.htaccess` and hidden files changed since the window began, in writable mounts, `/tmp` and `/dev/shm`. Drupal's own generated files, empty files and files not owned by the web user are set aside. | Uses file timestamps, which can be forged. |
| Webshell signatures | Pattern match for code that runs commands from a request, in files under 2 MB, Drupal's generated PHP included. | Obfuscated shells. |
| Processes | One snapshot of running processes: shells, downloaders, anything running from `/tmp` or `/dev/shm`. | Anything that already exited. Upsun workers aren't scanned yet. |
| Persistence | Lists the web user's crontab and checks `~/.ssh` for changed keys. | Upsun crons live in the app config, not crontab. |
| Shell history | Reads every command for downloaders, reverse shells, `base64 -d`, `chmod +x`, and crontab or `authorized_keys` edits. Read-only commands like `crontab -l` don't count. | A webshell's commands never reach shell history. |
| Drupal accounts | Flags administrators created or changed since the window began. Accounts from the first hour after a site install inside the window are ignored. | Only the `administrator` role. Changed permissions on other roles aren't checked. |
| Drupal modules | Compares enabled modules with the exported `core.extension.yml`. | Needs exported config. Sites without it show "Not compared". |

The noise limits (`POST_BURST`, `POST_BURST_MINUTES`, `MEMORY_ERRORS`) sit at the top of `strider.sh`.

## Reading copied logs, or running inside ddev

`local.conf` reads log files from the current folder instead of reaching a host. Copy the server's logs into a folder using Upsun's names (`access.log`, `php.access.log`, `app.log`, `error.log`, `php.log`; missing ones are skipped) and run Strider there.

```bash
cd ~/incident/mysite-logs
~/Ithildin/strider.sh -c ~/Ithildin/local.conf
```

On your own machine this reads the logs only. Scanning a workstation's processes and `/tmp` would only produce noise, so the PHP, session, file, process and Drupal checks are skipped, and the app comes out INCOMPLETE ("logs only") when the logs are clean. Set `STRIDER_LOG_DIR` to read logs from another folder.

Inside a ddev web container (`ddev ssh`), Strider runs the full set of checks against that container as well, including the Drupal account and module checks through drush. That's worth doing when the dev site runs on a copy of the production database. `CONTAINER_CHECKS=1` or `0` overrides the choice either way.

## Using another host

Everything host-specific lives in `upsun.conf`: the CLI calls, log paths, the variable that holds the app root, and the wording in the report. For another host, copy it and change what differs.

```bash
cp upsun.conf myhost.conf
./strider.sh -c myhost.conf -p mysite
```

The config is a bash file Strider sources. It sets variables (`ACCESS_LOG`, `ERROR_LOGS`, `APP_DIR_VAR`, and so on) and defines five functions: `platform_projects`, `platform_default_env`, `platform_title`, `platform_apps` and `platform_ssh`. `tests/althost.conf` is a working example that reaches apps with `docker exec` and keeps its logs in `/srv/logs`.

## Tests

`tests/run-tests.sh` runs Strider end to end against docker containers standing in for hosted apps. It covers a clean site, an unpatched one, a compromised one, a trimmed log, a missing log, an unreachable environment, planted canaries, a second host through `tests/althost.conf`, and `local.conf` both on this machine and inside a container standing in for ddev. It needs docker and the `ddev/ddev-webserver:v1.25.4` image (set `STRIDER_TEST_IMAGE` to use another image with PHP). `STRIDER_KEEP=1` keeps the reports so you can open them.

`tests/seed-upsun.sh -p PROJECT -e ENV` plants harmless `strider-canary` files, a session file, a process and some traffic on a real Upsun test environment, so you can watch Strider flag them. `--clean` removes them. Don't point it at production.

## If a finding looks real

1. Don't redeploy yet. The container and its mounts are evidence. Contact your host's support.
2. Keep the report folder; it includes the logs.
3. Rotate every secret the app could read: database credentials, hash salt, API keys, SMTP credentials, deploy keys.
4. Check other sites that share those secrets.
5. Rebuild on patched PHP rather than cleaning in place, and diff `settings.php` and `services.yml` against git.

## License

GPL-3.0. See [LICENSE](LICENSE).
