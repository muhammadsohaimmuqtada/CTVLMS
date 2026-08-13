# CTVLMS — Continuous Threat & Vulnerability Lifecycle Management

CTVLMS is an open-source exposure-management and policy-gated remediation platform for authorised infrastructure. It combines network discovery, authenticated endpoint inventory, vulnerability intelligence, explainable applicability analysis, remediation workflow, worker recovery, staged rollout controls, and fresh post-patch verification.

> **Current maturity:** suitable for controlled design-partner / on-prem pilot evaluation. CTVLMS is not yet an independently audited enterprise security product. Keep automatic remediation disabled outside a validated staging environment until inventory, SSH trust, backups, change controls, maintenance windows, canary policy, and rollback procedures have been proven for the deployment.

## Why CTVLMS exists

A CVE in a catalogue does **not** mean an asset is vulnerable. CTVLMS is built around evidence and lifecycle state rather than blind CVE matching:

```text
Authorised discovery ── Managed endpoint inventory
         │                         │
         ├──── service/CPE data    ├──── OS + package/source identity
         │                         │
         └────────────┬────────────┘
                      │
           Vulnerability intelligence
              NVD + distro advisories
                      │
             Applicability engines
                      │
       Confirmed / Potential / Not Affected
                      │
          Policy + backup + approval gates
                      │
              Remediation queue
                      │
       Worker lease + rollout blast-radius gate
                      │
             Package-specific patch
                      │
              Fresh managed inventory
                      │
                Verified Closed
```

## Current capabilities

### Discovery and inventory

- authorised Nmap service discovery with explicit target validation;
- conservative service freshness: closed ports retire services, filtered/unseen ports do not;
- local managed Linux inventory;
- authenticated remote SSH inventory for explicitly managed assets;
- authoritative OS, architecture, kernel, binary package, source package, source version, and upstream-version evidence;
- package identities remain separate from CPEs rather than inventing package CPE mappings;
- inventory runs and freshness are persisted for verification and operations.

### Vulnerability intelligence

- NVD incremental synchronisation;
- targeted exact-CVE refresh;
- legacy NVD configuration backfill;
- preservation of full NVD configuration trees;
- CPE 2.3 and legacy Nmap `cpe:/...` normalisation;
- Debian Security Tracker structured JSON ingestion;
- advisory snapshot provenance and feed-shrink protection;
- distribution-mapping model for trusted cross-distribution relationships;
- package candidate intelligence separated from materialised authoritative findings.

### Applicability

- tri-state `AND` / `OR` / `NEGATE` NVD configuration evaluation;
- platform-aware applicability using authoritative endpoint evidence;
- service versions are not substituted for a different component version embedded in a CPE;
- Debian package ordering uses `dpkg --compare-versions` rather than PHP semantic-version logic;
- source-package + distro-suite package applicability;
- unsupported cross-distribution matches remain candidate/unknown rather than generating hundreds of thousands of false findings;
- explainable JSON evidence for correlation decisions.

### Remediation safety

- automatic execution defaults **off**;
- package-specific remediation only; no general-purpose remote shell;
- package-name validation and fixed command policy;
- Approval and Auto modes;
- verified-backup gate;
- strict SSH host-key verification;
- separate inventory and patch SSH identities/policies;
- maintenance windows and timezone-aware execution;
- worker leases, heartbeats, fencing, expired-lease recovery, bounded retries, and failure classification;
- stale evaluated-version fence: the worker refuses to patch when the live package version no longer matches the version used to create the job;
- staged/canary rollout groups, deterministic canary buckets, concurrency limits, explicit promotion, pause state, and automatic pause after rollout failures.

### Verification and operations

- patch command success alone does not close a finding;
- package remediation requires a managed inventory run newer than patch completion;
- fresh applicability must resolve to Not Affected before `Verified_Closed`;
- continuous-cycle overlap protection and run history;
- minimal database-backed `/healthz` readiness endpoint;
- Nginx + PHP-FPM production deployment baseline;
- production preflight validation;
- atomic MariaDB backup with gzip integrity + SHA-256 sidecar;
- guarded restore workflow;
- systemd timers for continuous cycles and backups.

## Safety model

CTVLMS prefers an explainable unknown over an unjustified remediation decision.

- `Potential` / unknown applicability never becomes automatic patch eligibility.
- Cross-distribution advisory candidates are not authoritative findings without native provider evidence or an explicit trusted mapping.
- A worker losing its lease is fenced from committing state.
- A successful remote command does not rewrite authoritative inventory.
- Closure requires evidence newer than remediation completion.
- Auto remediation must be explicitly enabled by the operator.

## Requirements

Core runtime:

- PHP 8+
- PDO MySQL
- SimpleXML
- MariaDB/MySQL
- Nmap
- OpenSSH client

Production deployment additionally expects Nginx + PHP-FPM. Docker Compose is used by the provided database and pilot-lab workflows.

## Local development start

```bash
cp .env.example .env
cp config/config.example.php config/config.php
```

Set strong, distinct database secrets, then:

```bash
docker compose up -d
php bin/create-admin.php admin@example.com "CTVLMS Administrator"
./ctvlms.sh
```

The PHP built-in server is for development only. Production deployment uses the Nginx/PHP-FPM profile described in [`docs/production-deployment.md`](docs/production-deployment.md).

## Database upgrades

Apply every numbered migration in order. Current `main` includes migrations through:

```text
004 inventory applicability
005 NVD sync state
006 package intelligence
007 package candidate separation
008 remote inventory
009 remediation leases
010 cycle operations
011 remediation rollouts
```

For an existing database:

```bash
for migration in database/migrations/*.sql; do
  mariadb -u root -p ctvlms < "$migration"
done
```

Then backfill historical NVD configuration state in bounded batches:

```bash
php includes/sync_cve.php --backfill-missing 100
```

Repeat until `remaining_unknown` is `0`.

## Inventory

Local endpoint:

```bash
php bin/inventory-local.php <asset-id>
```

Managed SSH endpoint:

```bash
php bin/inventory-ssh.php <asset-id>
```

SSH inventory requires an enabled `asset_inventory_policies` record and key/known-hosts paths supplied through the referenced environment variables.

## Vulnerability intelligence

NVD maintenance:

```bash
export NVD_SYNC_HOURS=24
php includes/sync_cve.php
```

Exact CVE refresh:

```bash
php includes/sync_cve.php --cve CVE-2026-3087
```

Debian package advisory snapshot:

```bash
php bin/sync-package-advisories.php
```

Package coverage:

```bash
php bin/package-coverage.php
php bin/package-coverage.php <asset-id>
```

Coverage distinguishes candidate advisories from authoritative advisory coverage.

## Authorised network discovery

```bash
php bin/scan-network.php 192.168.1.0/24
```

Scan only systems you own or are authorised to assess.

## Remediation

Keep execution disabled during deployment validation:

```bash
export CTVLMS_EXECUTE_PATCHES=0
```

The queue is created from Confirmed eligible exposures and per-asset policy. The worker executes at most one claim at a time:

```bash
php bin/patch-worker.php
```

After a successful patch, refresh managed inventory and verify:

```bash
php bin/inventory-ssh.php <asset-id>
php bin/verify-remediations.php
```

Rollout groups can be controlled with:

```bash
php bin/rollout-control.php
```

See [`docs/remediation-rollouts.md`](docs/remediation-rollouts.md) for staged/canary behavior.

## Continuous cycle

Example controlled cycle:

```bash
export CTVLMS_LOCAL_ASSET_IDS='1'
export CTVLMS_SCAN_TARGETS='127.0.0.1'
export CTVLMS_EXECUTE_PATCHES=0
php bin/continuous-cycle.php
```

Child operations are bounded by timeouts, cycle overlap is prevented, and cycle results are recorded for operations.

## Production deployment

Use the production baseline in [`docs/production-deployment.md`](docs/production-deployment.md):

- dedicated `ctvlms` service identity;
- Nginx TLS termination and front-controller boundary;
- dedicated PHP-FPM pool;
- non-root application DB user;
- external runtime secret environment;
- production preflight;
- minimal readiness endpoint;
- systemd cycle and backup timers;
- backup/restore procedure.

## Release-candidate pilot lab

The repository includes an isolated deterministic 4-node Debian acceptance lab. It uses a synthetic local package and advisory to prove the real CTVLMS remediation machinery without touching the host package manager or relying on an intentionally vulnerable public package.

Run:

```bash
bash lab/bin/full-run.sh
```

It validates:

- remote SSH inventory;
- source-package applicability;
- backup/policy gates;
- canary patch success;
- Approval-mode execution;
- worker lease reclamation;
- stale-version refusal;
- rollout auto-pause after patch failure;
- fresh post-patch closure;
- backup + destructive restore on the isolated lab DB.

See [`lab/README.md`](lab/README.md).

## Testing and CI

Pure policy/parser tests and MariaDB integration tests run in GitHub Actions. CI also validates:

- all PHP syntax;
- all numbered migrations and migration reapplication where required;
- package-scale behavior;
- remote inventory;
- remediation leasing and verification;
- rollout controls;
- production preflight;
- Nginx configuration syntax;
- shell and Python syntax;
- pilot-lab Compose/build contract.

## Commercial support boundary today

A credible first design-partner scope is a controlled on-prem Debian/Linux deployment with authenticated SSH inventory and Approval-mode remediation. Generic NVD/CPE service correlation can cover additional Linux software, but native package-remediation authority should be limited to distributions/providers with explicit evidence.

Not yet claimed as complete enterprise capability:

- Kali-native package advisory authority;
- Ubuntu/RHEL/Rocky/Alma native package providers;
- Windows/macOS remediation;
- SaaS/MSP tenant isolation and billing;
- SAML/OIDC enterprise SSO;
- HA database/reference deployment;
- broad SIEM/ticketing integrations;
- EPSS / CISA KEV prioritisation;
- independent external security audit and penetration test.

## Security boundaries

- PDO prepared statements with emulated prepares disabled;
- server-side RBAC and CSRF validation;
- `password_hash()` / `password_verify()`;
- strict session mode, HttpOnly cookies, SameSite Strict, Secure cookies under HTTPS;
- lifecycle/audit trail;
- privileged risk acceptance with justification;
- strict SSH host-key checking;
- dedicated application DB identity;
- no bundled database admin UI;
- no production-default demo credentials;
- only the front controller, public static assets, and minimal health endpoint are web reachable in the production Nginx profile.

## Project status

CTVLMS has moved beyond the original academic prototype into a controlled pilot-stage security platform. The next proof point is repeated successful release-candidate lab runs followed by a small real design-partner fleet under Approval mode, not feature-count expansion.
