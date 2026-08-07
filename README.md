# CTVLMS — Cyber Threat & Vulnerability Lifecycle Management System

CTVLMS is a cybersecurity asset, exposure, vulnerability-lifecycle, incident, threat-intelligence, red-team, and remediation management project.

The v2 foundation evolves the original database coursework into an **asset-aware continuous exposure management pipeline**:

```text
NVD CVE update
      ↓
NVD CPE applicability + version ranges
      ↓
Managed asset / software / network-service inventory
      ↓
Evidence-backed correlation
      ↓
Potential or Confirmed exposure
      ↓
Policy + backup gate
      ↓
Package-specific remediation job
      ↓
Post-patch version verification
      ↓
Verified Closed
```

> **Important:** CTVLMS is still an academic/open-source development project, not an independently audited production security product. Automatic remediation must be tested in a lab/staging environment before use on important systems.

## What makes CTVLMS different

A CVE existing in the vulnerability database does **not** automatically mean every asset is vulnerable.

CTVLMS keeps three layers separate:

1. **Inventory evidence** — observed network services and managed software versions.
2. **Applicability evidence** — NVD CPE criteria and vulnerable version ranges.
3. **Remediation state** — policy decisions, patch jobs, verification evidence, and lifecycle closure.

Complex NVD configurations containing additional `AND`/platform/negation conditions are deliberately classified as **Potential** rather than blindly auto-confirmed from a single CPE match.

## Core domains

- Users and role-based access control
- Assets and criticality
- Vulnerability catalogue and NVD synchronization
- Asset/vulnerability lifecycle
- Exposure intelligence
- Network service inventory
- Managed software inventory
- Patch policies and backup evidence
- Remediation jobs and verification
- Threat actors and IOCs
- Incidents
- Red-team/pentest engagements and scope
- Findings
- Audit history
- SQL reporting/dashboarding

## Lifecycle integrity

The asset-vulnerability workflow enforces explicit transitions:

```text
Discovered
  → Triaged
  → Confirmed
  → Remediation In Progress
  → Remediated
  → Verified Closed
```

`Risk Accepted` is a privileged terminal path requiring an Admin or Vulnerability Manager plus written justification. `Verified Closed` requires a verified remediation record.

Automated package remediation creates a normal remediation record; it does not bypass the lifecycle.

## Continuous exposure engine

### NVD ingestion

`includes/sync_cve.php` imports recently modified NVD CVEs and their CPE applicability data.

Recommended environment variables:

```bash
export NVD_API_KEY='your-nvd-api-key'
export NVD_SYNC_HOURS=6
```

Run manually:

```bash
php includes/sync_cve.php
```

### Network discovery

CTVLMS can run Nmap service detection against an authorised IP or CIDR and ingest hosts, ports, products, versions, and CPE observations:

```bash
php bin/scan-network.php 192.168.1.0/24
```

The target argument is validated as an IP/CIDR and is passed to Nmap without a shell.

### Correlation

Observed service/software CPEs are matched against NVD CPE/version applicability. Results are shown under:

```text
Assets & Vulns → Exposure Intelligence
```

Exposure states include:

- Potential
- Confirmed
- Remediation Queued
- Remediating
- Remediated
- Verification Failed
- Verified Closed
- Not Affected

### Automatic remediation

Automatic remediation is intentionally narrow. The worker is **not a generic remote-command system**.

Currently supported automated actions are package upgrades through:

- `apt`
- `dnf`
- `yum`
- `apk`

Execution requires:

- a Confirmed software exposure
- package-manager/package metadata in `asset_software`
- an asset patch policy
- `Auto` mode or explicit approval
- SSH transport
- strict SSH host-key verification
- an SSH private-key path referenced through an environment variable
- valid backup evidence when the policy requires it

Run one patch job:

```bash
php bin/patch-worker.php
```

Verify remediated exposures:

```bash
php bin/verify-remediations.php
```

A successful package-manager command is **not** enough to close a vulnerability. CTVLMS re-evaluates the patched version against the vulnerable CPE range. Only a no-longer-affected result becomes `Verified Closed`.

## Continuous cycle

One scheduler-friendly cycle performs NVD ingestion, authorised scanning, correlation, queueing, optional Auto remediation, and verification:

```bash
export CTVLMS_SCAN_TARGETS='192.168.1.0/24,10.0.0.10'
export CTVLMS_EXECUTE_PATCHES=0
php bin/continuous-cycle.php
```

`CTVLMS_EXECUTE_PATCHES=0` is the safe default. Set it to `1` only after patch policies, backup evidence, SSH trust, package inventory, and rollback procedures have been tested.

Systemd unit examples are provided under `deploy/systemd/`. The timer runs a cycle every 10 minutes.

## Database setup

### Requirements

- PHP 8.0+
- MySQL 8+ or MariaDB 10.5+
- PDO MySQL
- SimpleXML
- Nmap for network discovery
- OpenSSH client for SSH-managed remediation

### Manual database initialization

```bash
mysql -u root -p < database/schema.sql
mysql -u root -p ctvlms < database/seed.sql
mysql -u root -p ctvlms < database/migrations/002_exposure_engine.sql
mysql -u root -p ctvlms < database/migrations/003_remediation_verification.sql
```

Configure the application:

```bash
cp config/config.example.php config/config.php
# edit config/config.php
```

Start locally:

```bash
./ctvlms.sh
```

### Docker database

```bash
export CTVLMS_DB_ROOT_PASSWORD='use-a-strong-local-password'
docker compose up -d
```

The database is bound to `127.0.0.1:3306`, not all network interfaces. Fresh Docker volumes automatically apply the base schema, seed, and v2 migrations.

## Configuring an Auto-managed asset

The database stores policy metadata but **not SSH private keys**.

Example policy:

```sql
INSERT INTO asset_patch_policies
    (assetID, mode, transport, sshUser, sshKeyEnv, requireVerifiedBackup)
VALUES
    (1, 'Auto', 'SSH', 'ctvlms-patcher', 'CTVLMS_SSH_KEY_SERVER01', TRUE)
ON DUPLICATE KEY UPDATE
    mode = VALUES(mode),
    transport = VALUES(transport),
    sshUser = VALUES(sshUser),
    sshKeyEnv = VALUES(sshKeyEnv),
    requireVerifiedBackup = VALUES(requireVerifiedBackup);
```

Register current backup evidence:

```sql
INSERT INTO asset_backup_evidence
    (assetID, source, referenceValue, lastVerifiedAt, validUntil)
VALUES
    (1, 'snapshot-system', 'snapshot-123', NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR))
ON DUPLICATE KEY UPDATE
    source = VALUES(source),
    referenceValue = VALUES(referenceValue),
    lastVerifiedAt = VALUES(lastVerifiedAt),
    validUntil = VALUES(validUntil);
```

Then expose the SSH key path to the worker process:

```bash
export CTVLMS_SSH_KEY_SERVER01=/etc/ctvlms/keys/server01_ed25519
```

Use a restricted patching account and test its exact `sudo` permissions before enabling Auto mode.

## Security controls

| Area | Implementation |
|---|---|
| SQL injection | PDO prepared statements and parameter binding |
| Output encoding | HTML escaping for user-controlled output |
| CSRF | Per-session random tokens validated on state-changing requests |
| Password storage | `password_hash()` / `password_verify()` |
| Sessions | strict mode, HttpOnly cookies, SameSite Strict, session ID rotation |
| Authorization | server-side RBAC |
| Risk acceptance | privileged role + justification |
| Remediation verification | authenticated human or evidence-backed automated verification |
| Red-team scope | findings must target an asset in the selected engagement scope |
| Auditability | security and lifecycle actions recorded in the audit log |
| Auto patch scope | fixed package-manager actions only; no arbitrary remote command input |
| SSH | BatchMode and StrictHostKeyChecking enabled |

## Testing and CI

GitHub Actions validates:

- PHP syntax
- lifecycle transition policy
- CPE parsing
- exact/range matching
- complex NVD configuration downgrade behavior
- package-version override behavior
- Python syntax
- shell syntax

Run policy tests locally:

```bash
php tests/v2_policy_test.php
```

## Current limitations

The v2 foundation is intentionally conservative:

- NVD/CPE is currently the primary vulnerability applicability source.
- Linux package auto-remediation requires accurate package + CPE inventory.
- Network appliances/firmware are detected and flagged but are **not** blindly auto-flashed.
- Compound NVD applicability remains Potential until all conditions can be verified.
- Auto remediation currently supports SSH-managed Linux package managers only.
- Enterprise features such as multi-tenancy, distributed agents, signed job transport, EPSS/CISA KEV prioritization, SIEM integrations, and staged canary patch waves are future work.

These constraints are deliberate: CTVLMS should prefer an explainable Potential result over a destructive false-positive patch.
