# CTVLMS — Continuous Threat & Vulnerability Lifecycle Management

CTVLMS is an open-source exposure-management platform under active development. It combines authorised asset discovery, managed endpoint inventory, NVD vulnerability intelligence, evidence-backed applicability evaluation, vulnerability lifecycle management, policy-gated remediation, and post-remediation verification.

> CTVLMS is not yet an independently audited enterprise security product. Keep automatic remediation disabled until your inventory, backups, SSH trust, change controls, and rollback procedures have been validated in a lab/staging environment.

## Pipeline

```text
NVD CVE/CPE configuration ── Nmap/service and CPE inventory
                │                         │
                └──── existing CPE applicability engine

Distribution advisory ── source package/version ── OS suite facts
                │                         │
                └──── package applicability engine

Both engines produce explainable Confirmed / Not Affected / Potential
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
- Debian package versions are ordered by `dpkg --compare-versions`, including epochs, revisions, `~`, and distribution suffixes.
- Package advisories are correlated by authoritative source-package identity; package names are never converted into invented CPEs.
- A Debian advisory for a Kali-modified package remains `Potential` unless an explicit, justified distribution mapping exists.
- Network services are retired only from explicit closed-port evidence. Filtered/unseen ports are not treated as proof that a service disappeared.
- Automatic remediation is package-specific and policy-gated; it is not a general-purpose remote shell.
- `Verified Closed` requires fresh post-remediation evidence.

## Core components

- PHP web portal with RBAC, CSRF protection, session hardening, audit logging, and lifecycle controls
- MariaDB/MySQL relational model
- NVD CVE/CPE synchronisation
- Nmap authorised network discovery
- Managed endpoint facts and Linux `dpkg` package inventory
- Streamed Debian Security Tracker JSON ingestion with explicit provider provenance
- A separate distribution-package applicability engine and package coverage metrics
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

Fixture users are inactive and have no usable password. Run `bin/create-admin.php` to create a login after starting demo mode. Never use demo data in a shared deployment.

## Existing database upgrade

Apply every migration in numeric order. Current deployments additionally require migration `006`:

```bash
mariadb -u root -p ctvlms < database/migrations/004_inventory_applicability.sql
mariadb -u root -p ctvlms < database/migrations/005_nvd_sync_state.sql
mariadb -u root -p ctvlms < database/migrations/006_package_intelligence.sql
```

Migration `004` adds inventory freshness, authoritative asset facts/platform CPEs, and storage for full NVD configuration trees. Migration `005` records NVD configuration refresh state. Migration `006` adds normalized binary/source package identity, distribution advisories and sync provenance, package evaluation state, correlation indexes, and the package-advisory exposure type. It is idempotent and does not reset existing data.

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

This records hostname, distribution/suite, OS family/name/version, architecture, kernel, platform CPE evidence, and installed `dpkg` packages when available. The collector uses native `dpkg-query` fields for binary package/version, architecture, source package/version, and upstream source version. Those values live in `asset_package_inventory`; compatibility rows remain in `asset_software`, with `cpe=NULL` rather than a fabricated package CPE. Every identity records its package manager, inventory source, authoritative flag, freshness, and active state.

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

## Distribution package intelligence

Distribution intelligence is provider-based. The initial `DebianSecurityTrackerProvider` consumes Debian Security Tracker's structured JSON snapshot and streams one source-package object at a time, avoiding HTML scraping and unbounded whole-feed decoding. Ingestion is transactional, records the provider/source URL and sync run, and removes records absent from a successfully ingested replacement snapshot.

Sync the current Debian snapshot:

```bash
php bin/sync-package-advisories.php
```

For an offline mirror or deterministic fixture:

```bash
php bin/sync-package-advisories.php --file /path/to/debian-tracker.json
```

HTTP access uses HTTPS, bounded response size, timeouts, and retries. A failed fetch or parse leaves the previously committed advisory snapshot intact. The provider interface can ingest future Kali-native records using `distribution=kali` without changing the core evaluation algorithm.

Debian Tracker data is source-package and suite specific, but it does not prove that a Kali rebuild has identical patch provenance. Therefore Debian-to-Kali candidates are retained as `Potential` with a `kali_debian_mapping_unjustified` reason. They are never promoted to Confirmed/Not Affected and never become remediation eligible merely because their version string resembles Debian's.

### Package coverage semantics

Package coverage is independent of Nmap/NVD CPE coverage. Read global counts or scope them to one asset:

```bash
php bin/package-coverage.php
php bin/package-coverage.php 7
```

The JSON reports packages discovered, packages with source identity, packages evaluated, packages with advisory coverage, confirmed-vulnerable packages, fixed/not-affected packages, and unknown/unmapped packages. `packages_evaluated` is based on explicit evaluation-state rows, not the presence of a handful of CPE-bearing components. Thus an endpoint with 5,000 packages and four CPE matches cannot appear fully covered.

Package evidence records binary/source identity, installed binary/source versions, CVE/advisory, endpoint and advisory distribution/suite, fixed version, dpkg comparison result, provider, and decision reason. `Potential` represents unknown applicability; it is not a vulnerability confirmation.

### Two complementary finding sources

- NVD/CPE findings describe product/platform applicability from Nmap services, explicit software CPEs, and NVD configuration trees. This engine is unchanged and continues to use its existing CPE version logic.
- Distribution-package findings describe installed source packages using the endpoint's authoritative distro/suite and the distro provider's fixed/status rules. They do not require or create CPEs.

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

Supported package managers are currently `apt`, `dnf`, `yum`, and `apk`. Execution requires a Confirmed software exposure, validated authoritative package identity for package-advisory findings, an asset patch policy, approval or Auto policy as configured, SSH transport, strict host-key verification, and backup evidence when policy requires it. `Potential`/Unknown package findings cannot queue jobs. `CTVLMS_EXECUTE_PATCHES` remains off unless an operator explicitly sets it to `1`.

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
php tests/package_intelligence_test.php
php tests/nvd_parser_test.php
php tests/remediation_policy_test.php
```

GitHub Actions additionally boots MariaDB, applies every numbered migration, and executes database integration tests covering service freshness, compound CPE applicability, and inventory → advisory → package exposure/evidence correlation. Unit fixtures require no network.

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
- a Kali-native advisory provider and explicit Debian/Kali provenance mappings
- distribution providers beyond Debian/Kali and richer binary-to-source mappings outside `dpkg`
- EPSS and CISA KEV prioritisation
- multi-tenancy and tenant isolation for MSP/SaaS deployment
- job leasing/recovery for interrupted remediation workers
- staged/canary patch waves and tested rollback orchestration
- reverse-proxy/TLS production deployment profile and secret-manager integration
- SIEM/ticketing integrations, metrics/health endpoints, and operational SLOs
- independent security review and deployment hardening

The product should prefer an explainable `Potential` over a destructive false-positive remediation, and should prefer stale/unknown inventory over an unjustified false-negative closure.
