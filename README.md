# Ithildin

Checks hosted Drupal/PHP sites for traces of the October 2026 PHP vulnerabilities (CVE-2026-109618, CVE-2026-109619), following Amazon's recommended actions, the [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) and its [23 Oct follow-up](https://www.php.net/archive/2026.php#2026-10-23-1), and the [Drupal Association's audit steps](https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites). Read-only. Works with Upsun out of the box.

Strider (`strider.sh`) is the scanner: it follows the trail. Ithildin is the report: moon-letters that only show in the right light.

## Run it

```bash
git clone https://github.com/Greg-Boggs/Ithildin.git ~/Ithildin
mkdir -p ~/ithildin-reports && cd ~/ithildin-reports
~/Ithildin/strider.sh -p PROJECT_ID -e main      # needs the upsun CLI, logged in
xdg-open latest/report.html
```

No `-p` scans every project you can see. `-f`/`-t` set the review window (default 17 Oct 2026 to now).

Each app gets a verdict:

- **OK**: every check ran, nothing found.
- **REVIEW**: something to look at; the report shows the evidence.
- **ACTION REQUIRED**: no trace of an attack, but required PHP settings are wrong. The report says what to change.
- **INCOMPLETE**: nothing found, but some checks couldn't run, so it's not proof.

## What it checks

| Check | How | What it can miss |
|---|---|---|
| PHP version | Compares the running PHP with the fixed release for its branch (8.5.12, 8.4.27, 8.3.36, 8.2.35). | Reads the command-line PHP. On Upsun the web server uses the same build. |
| Required PHP settings | `session.upload_progress.enabled=0`, `session.use_strict_mode=1`, and `fatal_error_backtraces=0` on PHP 8.5, read from what PHP-FPM uses (pool overrides, then FPM's ini, then the CLI). Also lists `.user.ini` files and code that switches `session.serialize_handler` at runtime. | Hosts without a readable `php-fpm` binary fall back to the CLI values. |
| Log coverage | The access log must reach back to the start of the window. | Only the access log is checked for trimming. |
| Known attacker IPs | Exact match of each client IP against the 6 addresses Amazon published. | Behind a CDN the log may hold the CDN's address. A miss proves nothing. |
| Upload-progress field | Searches the access and error logs for `PHP_SESSION_UPLOAD_PROGRESS`. | Logs don't record POST bodies, so it only catches the field in a URL. |
| PUT/PATCH and POST bursts | Flags any PUT/PATCH, and 5+ POSTs from one client to the same page within 10 minutes. | An attacker spread across many IPs stays under the limit. |
| Crashes and memory errors | Worker crashes always flag; memory and timeout errors flag at 20+. | Not limited to the window. Logs could have been edited. |
| Fatal and parse errors | 10+ fatal, parse or uncaught errors within 10 minutes, inside the window. | Errors the app never logs. |
| Pre-request diagnostics | 10+ warnings reported `in Unknown on line 0` within 10 minutes. | Same. |
| PHP session store | Session files with PHP code, `upload_progress_` keys or malformed IDs. | Reads the session folder the command-line PHP uses. |
| Files written | Script, `.htaccess` and hidden files changed in the window, in writable mounts, `/tmp` and `/dev/shm`. Drupal's own generated files are set aside. | Timestamps can be forged. |
| Webshells | Pattern match for code that runs commands from a request, in files under 2 MB. | Obfuscated shells. |
| Processes | One snapshot: shells, downloaders, anything running from `/tmp`. | Anything that already exited. Upsun workers aren't scanned yet. |
| Persistence | The web user's crontab and changed `~/.ssh` keys. | Upsun crons live in the app config, not crontab. |
| Shell history | Downloaders, reverse shells, `base64 -d`, `chmod +x`, crontab or `authorized_keys` edits. | A webshell's commands never reach shell history. |
| Drupal accounts | Administrators created or changed in the window, ignoring a site install's first hour. | Only the `administrator` role. |
| Drupal modules | Enabled modules compared with exported `core.extension.yml`. | Needs exported config. |

Noise limits are at the top of `strider.sh`.

## Other hosts, copied logs, ddev

Host details (CLI calls, log paths, app root) live in `upsun.conf`. Copy it for another host and run with `-c myhost.conf`.

To scan logs you copied locally, put them in a folder (`access.log`, `app.log`, `error.log`, `php.log`, `php.access.log`) and run `strider.sh -c ~/Ithildin/local.conf` there. Outside ddev it reads the logs only. Inside `ddev ssh` it also runs the container and Drupal checks.

## Tests

`tests/run-tests.sh` runs everything end to end against docker containers (needs the `ddev/ddev-webserver:v1.25.4` image). `tests/seed-upsun.sh` plants harmless canaries on an Upsun test environment.

## License

GPL-3.0
