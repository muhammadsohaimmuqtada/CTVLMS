# Production deployment

CTVLMS production deployments should use Nginx + PHP-FPM. PHP's built-in development server is not a production boundary.

## Files

- `deploy/nginx/ctvlms.conf.example` — HTTPS-only reverse proxy/front-controller profile.
- `deploy/php-fpm/ctvlms.conf` — dedicated `ctvlms` PHP-FPM pool.
- `deploy/ctvlms.env.example` — runtime environment template for `/etc/ctvlms/ctvlms.env`.
- `deploy/systemd/ctvlms-cycle.service` / `.timer` — continuous exposure cycle.
- `deploy/systemd/ctvlms-backup.service` / `.timer` — atomic database backups.
- `bin/production-check.php` — configuration + database readiness preflight.
- `bin/backup-db.sh` / `bin/restore-db.sh` — guarded operational backup/restore.

## Host layout

Create a dedicated service account and directories. The application tree should be owned by root and readable by the `ctvlms` service account; the service account should not be able to modify application code.

```bash
sudo useradd --system --home /opt/ctvlms --shell /usr/sbin/nologin ctvlms || true
sudo install -d -o root -g ctvlms -m 0750 /etc/ctvlms
sudo install -d -o ctvlms -g ctvlms -m 0750 /var/log/ctvlms /var/backups/ctvlms
```

Install the repository at `/opt/ctvlms`, copy `config/config.example.php` to `config/config.php`, and keep `config/config.php` free of secrets. Runtime secrets belong in `/etc/ctvlms/ctvlms.env` or a process secret store.

```bash
sudo cp deploy/ctvlms.env.example /etc/ctvlms/ctvlms.env
sudo chmod 0600 /etc/ctvlms/ctvlms.env
sudo chown root:ctvlms /etc/ctvlms/ctvlms.env
```

Set `CTVLMS_ENV=production`, a real HTTPS `CTVLMS_APP_URL`, a non-root MariaDB application account, and a strong application database password. Keep `CTVLMS_EXECUTE_PATCHES=0` during deployment validation.

## Preflight

Load the environment and run the production preflight before exposing the service:

```bash
set -a
. /etc/ctvlms/ctvlms.env
set +a
php /opt/ctvlms/bin/production-check.php
```

Production preflight rejects HTTP application URLs, root DB application users, placeholder/weak database secrets, invalid environment modes, and unavailable database readiness.

## PHP-FPM

Install the pool file under the PHP-FPM pool directory appropriate to the deployed PHP version. The provided profile uses a dedicated Unix socket and `ctvlms` worker identity. If your package uses a different PHP minor version, update the socket path consistently in both the FPM pool and Nginx profile.

The FPM service environment must receive the CTVLMS runtime variables through the system's supported secret/environment mechanism. Do not make `/etc/ctvlms/ctvlms.env` readable by the web server user merely to solve configuration loading.

## Nginx and TLS

Copy `deploy/nginx/ctvlms.conf.example` into the Nginx site configuration, replace the example hostname and certificate paths, and validate before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

The profile redirects HTTP to HTTPS, enables HSTS, serves only `/public/` as static content, forwards the front controller and `/healthz` to PHP-FPM, denies arbitrary PHP execution, and denies repository/configuration paths and sensitive file extensions.

## Health

`GET /healthz` returns only a minimal database-backed readiness state. It does not expose asset, CVE, credential, exception, or deployment details. Use it for load-balancer readiness rather than general observability.

## Scheduler

Install the existing cycle systemd unit/timer and enable the timer only after production preflight succeeds. The continuous cycle already uses bounded child-process timeouts, remediation leases, staged rollout controls, and explicit patch execution gating.

## Backup

Install and enable `ctvlms-backup.timer`. `bin/backup-db.sh` uses a single-transaction MariaDB dump, writes through an atomic temporary file, verifies gzip integrity, creates a SHA-256 sidecar, uses restrictive permissions, and prunes backups by retention policy.

The application database account must have sufficient privileges for the selected backup mode. In higher-assurance environments, use a separate least-privilege backup account supplied through a dedicated environment file.

## Restore

Restores are deliberately interactive-by-policy: the restore utility refuses to run unless `CTVLMS_RESTORE_CONFIRM=YES` is supplied. It verifies gzip integrity and a SHA-256 sidecar when present before streaming the SQL to MariaDB.

```bash
sudo systemctl stop php8.4-fpm
CTVLMS_RESTORE_CONFIRM=YES /opt/ctvlms/bin/restore-db.sh /var/backups/ctvlms/ctvlms-YYYYmmddTHHMMSSZ.sql.gz
php /opt/ctvlms/bin/production-check.php
sudo systemctl start php8.4-fpm
```

Run schema/migration and application validation after restore before returning the service to traffic.

## Security boundaries

- application code is not writable by the runtime account;
- DB application user is not root;
- secrets are not committed to the repository;
- only the front controller, static public assets, and health endpoint are web reachable;
- TLS terminates at Nginx and session cookies are Secure when `CTVLMS_APP_URL` is HTTPS;
- automatic remediation remains separately gated and disabled by default;
- backup and restore paths use restrictive permissions and explicit operator controls.

This profile is a deployment baseline, not a substitute for host hardening, firewall policy, central secret management, external monitoring, or an independent security review.
