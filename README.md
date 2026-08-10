# CTVLMS — Continuous Threat & Vulnerability Lifecycle Management

CTVLMS is an open-source exposure-management platform under active development. It combines authorised asset discovery, managed endpoint inventory, NVD vulnerability intelligence, evidence-backed applicability evaluation, vulnerability lifecycle management, policy-gated remediation, and post-remediation verification.

> CTVLMS is not yet an independently audited enterprise security product. Keep automatic remediation disabled until your inventory, backups, SSH trust, change controls, and rollback procedures have been validated in a lab/staging environment.

## Pipeline

```text
NVD CVE + full applicability configuration
                  +
Nmap network/service evidence
                  +
Managed endpoint OS/package evidence
                  ↓
Tri-state applicability evaluation
     TRUE / FALSE / UNKNOWN
                  ↓
Confirmed / Not Affected / Potential
                  ↓
Policy + backup + approval gates
                  ↓
Package-specific remediation
                  ↓
Fresh post-patch verification
                  ↓
Verified Closed
```

## Reliability principles

- A CVE in the catalogue does not imply an asset is affected.
- CTVLMS preserves NVD `AND` / `OR` / `NEGATE` configuration structure instead of flattening compound applicability into a blind match.
- Nmap CPE URI bindings (`cpe:/...`) and NVD CPE 2.3 strings are both normalized.
- Service-banner versions are not substituted for a different component version embedded in a CPE.
- Missing OS evidence remains `Potential`; authoritative platform conflicts can resolve applicability to `Not Affected`.
- Network services are retired only from explicit closed-port evidence. Filtered/unseen ports are not treated as proof that a service disappeared.
- Automatic remediation is package-specific and policy-gated; it is not a general-purpose remote shell.
- `Verified Closed` requires fresh post-remediation evidence.

## Core components

- PHP web portal with RBAC, CSRF protection, session hardening, audit logging, and lifecycle controls
- MariaDB/MySQL relational model
- NVD CVE/CPE synchronisation
- Nmap authorised network discovery
- Managed endpoint facts and Linux `dpkg` package inventory
- Exposure intelligence with evidence payloads and tri-state compound applicability
- Patch policies, backup gates, remediation jobs, and verification
- Incidents, threat actors, IOCs, engagements, findings, and reporting

## Production-style quick start

Requirements: PHP 8+, PDO MySQL, SimpleXML, MariaDB/MySQL, Nmap, OpenSSH client, and Docker Compose if using the provided database container.

```bash
cp .env.example .env
cp config/config.example.php config/config.php
```

Set strong, distinct values in `.env` for:

```text
CTVLMS_DB_ROOT_PASSWORD
CTVLMS_DB_PASSWORD
```

A fresh default Docker database is intentionally **empty of demo business data**:

```bash
docker compose up -d
```

Create the first administrator interactively:

```bash
php bin/create-admin.php admin@example.com "CTVLMS Administrator"
```

Start the local portal:

```bash
./ctvlms.sh
```

The development router serves application traffic through `index.php` and static content only from `public/`; SQL, configuration, tests, and repository internals are not direct static resources.

### Explicit demo mode

Demo/course fixtures are opt-in:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d
```

Never use seeded demo credentials or data in a shared deployment.

## Existing database upgrade

Apply migrations in order. Current deployments require migrations `004` and `005` after the existing v2 migrations:

```bash
mariadb -u root -p ctvlms < database/migrations/004_inventory_applicability.sql
mariadb -u root -p ctvlms < database/migrations/005_nvd_sync_state.sql
```

Migration `004` adds inventory freshness, authoritative asset facts/platform CPEs, and storage for full NVD configuration trees. Migration `005` records whether each CVE has been refreshed through the full-configuration importer, so an older CVE that still needs backfill can be distinguished from an NVD record that legitimately has no applicability configuration.

After upgrading an existing database, backfill old CVE rows in bounded batches:

```bash
php includes/sync_cve.php --backfill-missing 100
```

Repeat until `remaining_unknown` is `0`. For a specific CVE that must be refreshed immediately:

```bash
php includes/sync_cve.php --cve CVE-2026-3087
```

## Managed endpoint inventory

Network discovery and endpoint inventory have deliberately different trust levels. Nmap is used for remotely observed network evidence; endpoint inventory is used for authoritative OS/package facts.

For the machine running CTVLMS, after its asset exists:

```bash
php bin/inventory-local.php <asset-id>
```

This records hostname, OS family/name/version, architecture, kernel, platform CPE evidence, and installed `dpkg` packages when available.

The continuous cycle can refresh selected local assets before correlation:

```bash
export CTVLMS_LOCAL_ASSET_IDS='1'
export CTVLMS_SCAN_TARGETS='127.0.0.1'
export CTVLMS_EXECUTE_PATCHES=0
php bin/continuous-cycle.php
```

## NVD intelligence

Incremental maintenance uses recently modified CVEs:

```bash
export NVD_SYNC_HOURS=24
php includes/sync_cve.php
```

Refresh one or more known CVEs directly:

```bash
php includes/sync_cve.php --cve CVE-2026-3087 CVE-2026-0001
```

Backfill legacy rows whose full configuration state has not yet been populated:

```bash
php includes/sync_cve.php --backfill-missing 100
```

An NVD API key is recommended for sustained use:

```bash
export NVD_API_KEY='...'
```

CTVLMS stores both flattened CPE criteria for candidate indexing and the original NVD configuration JSON for compound applicability evaluation. Each refreshed vulnerability is also marked `Present` or `None` for NVD configuration state; untouched legacy rows remain `Unknown` until refreshed.

## Authorised network discovery

```bash
php bin/scan-network.php 192.168.1.0/24
```

Targets must be valid IP/CIDR values and are passed to Nmap as a process argument array, not interpolated through a shell. Scan only systems you own or are authorised to assess.

## Remediation safety

Automatic execution defaults off:

```bash
export CTVLMS_EXECUTE_PATCHES=0
```

Supported package managers are currently `apt`, `dnf`, `yum`, and `apk`. Execution requires a Confirmed software exposure, package metadata, an asset patch policy, SSH transport, strict host-key verification, and backup evidence when policy requires it.

```bash
php bin/patch-worker.php
php bin/verify-remediations.php
```

Use restricted patching accounts and narrowly scoped non-interactive `sudo` rules. Test rollback and maintenance-window procedures before enabling Auto mode.

## Testing

Local pure-policy/parser tests:

```bash
php tests/v2_policy_test.php
php tests/inventory_test.php
php tests/nvd_parser_test.php
php tests/remediation_policy_test.php
```

GitHub Actions additionally boots MariaDB, applies the complete schema/migration chain, and executes database integration tests covering service freshness and compound applicability state changes.

## Security boundaries

- PDO prepared statements and disabled emulated prepares
- server-side RBAC
- CSRF validation for state-changing web actions
- `password_hash()` / `password_verify()`
- strict session mode, HttpOnly cookies, SameSite Strict, Secure cookies when HTTPS is configured
- audit trail for security/lifecycle actions
- risk acceptance restricted to Admin/Vulnerability Manager with justification
- strict SSH host-key checking and key paths referenced through environment variables
- default Docker application account separated from the database root account
- demo seeding opt-in instead of production-default
- bundled database administration UI is not part of the runtime product

## Current limitations / roadmap

CTVLMS is materially stronger than the original academic v2 foundation, but these remain production-readiness work rather than hidden assumptions:

- remote managed-inventory collector/agent with signed identity and secure enrollment
- authoritative distro advisory/backport matching for Linux packages instead of relying only on NVD/CPE
- package-to-CPE/advisory normalization across distributions
- EPSS and CISA KEV prioritisation
- multi-tenancy and tenant isolation for MSP/SaaS deployment
- job leasing/recovery for interrupted remediation workers
- staged/canary patch waves and tested rollback orchestration
- reverse-proxy/TLS production deployment profile and secret-manager integration
- SIEM/ticketing integrations, metrics/health endpoints, and operational SLOs
- independent security review and deployment hardening

The product should prefer an explainable `Potential` over a destructive false-positive remediation, and should prefer stale/unknown inventory over an unjustified false-negative closure.
