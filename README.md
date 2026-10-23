# Ithildin

Checks hosted Drupal/PHP sites for traces of the October 2026 PHP vulnerabilities (CVE-2026-109618, CVE-2026-109619), following Amazon's recommended actions and the [Drupal Association's audit steps](https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites). Read-only. Works with Upsun out of the box.

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
- **INCOMPLETE**: nothing found, but some checks couldn't run, so it's not proof.

## What it checks

PHP version, known attacker IPs, `PHP_SESSION_UPLOAD_PROGRESS` in requests, PUT/PATCH and POST bursts, PHP crashes and memory errors, tampered session files, new files and webshells in writable folders, suspicious processes, crontab and SSH keys, shell history, and new Drupal admins or modules. The report's "What we checked" table explains each one. Noise limits are at the top of `strider.sh`.

## Other hosts, copied logs, ddev

Host details (CLI calls, log paths, app root) live in `upsun.conf`. Copy it for another host and run with `-c myhost.conf`.

To scan logs you copied locally, put them in a folder (`access.log`, `app.log`, `error.log`, `php.log`, `php.access.log`) and run `strider.sh -c ~/Ithildin/local.conf` there. Outside ddev it reads the logs only. Inside `ddev ssh` it also runs the container and Drupal checks.

## Tests

`tests/run-tests.sh` runs everything end to end against docker containers (needs the `ddev/ddev-webserver:v1.25.4` image). `tests/seed-upsun.sh` plants harmless canaries on an Upsun test environment.

## License

GPL-3.0
