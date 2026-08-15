# First Real Debian Staging Validation

This runbook is the release-candidate gate between the deterministic Docker pilot lab and a design-partner deployment.

The first real fleet is deliberately small: **2 or 3 Debian staging VMs that you own or are explicitly authorised to administer**. Do not use production assets for this phase.

## Frozen release candidate

The deterministic release-candidate evidence is frozen on:

```text
release/v0.9.0-rc1
a1e5d7ecc75637792bfa88a9a2a5c90ca62b51df
```

`main` may continue to gain staging tooling. Do not silently move the frozen release branch during validation.

## Safety rules

For the first real staging fleet:

- every asset must be marked `Staging`;
- managed inventory must use SSH;
- patch transport must use a separate SSH identity;
- remediation mode must be `Approval`;
- `allowMajorUpgrade = 0`;
- `allowReboot = 0`;
- `requireVerifiedBackup = 1`;
- automatic patch execution stays disabled during inventory/correlation;
- only **one** remediation job may be Approved/Running across the selected fleet at a time;
- patch only during a configured maintenance window;
- after execution, immediately disable `CTVLMS_EXECUTE_PATCHES` again;
- closure requires fresh post-patch inventory and `verify-remediations.php`.

## 1. Build 2–3 real Debian staging VMs

Use normal VMs (for example KVM/VirtualBox/VMware/cloud test instances), not the deterministic `lab/` containers. Recommended minimum:

- Debian 12 or the exact Debian release you intend to support first;
- 2 vCPU;
- 2 GiB RAM;
- snapshot/backup capability;
- SSH reachable only from the CTVLMS host or management network;
- no production data.

Record each VM's IP address before enrollment.

## 2. Create least-privilege SSH identities

Use one account for inventory and a different account for patch execution.

Inventory should be read-only. Patch sudoers should permit only the package-manager commands CTVLMS needs, not a general shell.

Pin host keys in a dedicated known-hosts file. Never use `StrictHostKeyChecking=no` for this validation.

Expose file paths to CTVLMS through environment variables such as:

```bash
export CTVLMS_STAGE_INV_KEY=/etc/ctvlms/ssh/staging-inventory
export CTVLMS_STAGE_PATCH_KEY=/etc/ctvlms/ssh/staging-patcher
export CTVLMS_STAGE_KNOWN_HOSTS=/etc/ctvlms/ssh/staging-known-hosts
```

The database stores only those environment-variable names, not private-key material.

## 3. Enroll the assets

Create the assets normally and mark their environment as `Staging`. Then configure:

- `asset_inventory_policies.mode = SSH`;
- inventory SSH user/key/known-hosts references;
- `asset_patch_policies.mode = Approval`;
- `asset_patch_policies.transport = SSH`;
- patch SSH user/key/known-hosts references;
- `requireVerifiedBackup = 1`;
- `allowMajorUpgrade = 0`;
- `allowReboot = 0`;
- an explicit maintenance window.

Record the resulting asset IDs.

## 4. Run the staging policy gate

Keep execution disabled:

```bash
export CTVLMS_EXECUTE_PATCHES=0
php bin/staging-pilot.php preflight 12,13
```

For three assets:

```bash
php bin/staging-pilot.php preflight 12,13,14
```

The command fails closed if the fleet is not exactly 2–3 assets, an asset is not `Staging`, SSH policies are incomplete, Auto mode is enabled, safety flags are relaxed, or a remediation job is already running.

Backup/inventory absence is surfaced as a warning during preparation because those gates are established in the next steps.

## 5. Capture authoritative inventory

Run the normal remote collector for every selected asset:

```bash
php bin/inventory-ssh.php 12
php bin/inventory-ssh.php 13
```

Then rerun the staging gate and inspect the report:

```bash
php bin/staging-pilot.php preflight 12,13
php bin/staging-pilot.php report 12,13
```

Do not continue if inventory fails or package/source identity is unexpectedly incomplete.

## 6. Load real Debian vulnerability intelligence

Synchronise the live provider:

```bash
php bin/sync-package-advisories.php
```

Evaluate the selected fleet with the existing package engine and inspect findings in CTVLMS. Do not manufacture a finding merely to make the staging run pass.

Choose a **real, low-blast-radius package finding** where:

- Debian provider evidence is authoritative for the VM release;
- installed package/source identity is authoritative;
- a fixed version is available from the configured repository;
- the change does not require a major distribution upgrade or automatic reboot.

If no appropriate real finding exists, wait for one or intentionally install an older package version only in these disposable staging VMs under your own change control. Do not weaken repository trust or download arbitrary vulnerable packages.

## 7. Record valid backup evidence

Take a VM snapshot or equivalent recoverable backup. Record its evidence in `asset_backup_evidence` with a current `lastVerifiedAt` and a bounded `validUntil`.

Do not approve a patch until the backup gate is valid.

## 8. Queue and explicitly approve exactly one job

Let normal CTVLMS correlation/policy create the remediation job. In Approval mode it must remain `Awaiting_Approval` until an operator explicitly approves it.

Approve only one low-risk job across the selected fleet.

Confirm:

```bash
php bin/staging-pilot.php report 12,13
```

The report should show exactly one approved job and zero running jobs before the maintenance window.

## 9. Pass the execution gate

Only inside the planned maintenance window:

```bash
export CTVLMS_EXECUTE_PATCHES=1
php bin/staging-pilot.php execute-gate 12,13 <approved-job-id>
```

The gate is read-only. It does **not** patch anything. It verifies that the selected job belongs to the explicit staging fleet, is Approved, still has queued applicability, uses Approval+SSH policy, has valid backup evidence, and is the only Approved/Running job across the fleet.

If the gate returns `"ok": true`, execute one worker claim:

```bash
php bin/patch-worker.php
```

Immediately disable execution again:

```bash
export CTVLMS_EXECUTE_PATCHES=0
```

Never leave automatic execution enabled while observing the first real fleet.

## 10. Fresh inventory and verification

Refresh the patched asset with the normal managed collector:

```bash
php bin/inventory-ssh.php <patched-asset-id>
```

Re-evaluate applicability, then:

```bash
php bin/verify-remediations.php
```

Expected successful lifecycle:

```text
Confirmed
  -> Remediation_Queued
  -> Remediating
  -> Remediated
  -> fresh inventory
  -> applicability Not_Affected
  -> Verified_Closed
```

A successful SSH command alone is not sufficient for closure.

## 11. Observe repeated cycles

Keep remediation in Approval mode and execution disabled. Run normal continuous cycles for multiple intervals and inspect:

- inventory freshness;
- advisory/correlation stability;
- job idempotency;
- no re-opening of stable `Verified_Closed` findings;
- no stuck leases;
- no unexpected queued jobs;
- health/readiness;
- backup availability;
- logs and operator-facing failure reasons.

Run:

```bash
php bin/staging-pilot.php report 12,13
```

at each observation checkpoint.

## Exit criteria for a paid design-partner pilot

All of the following should be true before moving beyond internal staging:

1. the frozen deterministic pilot lab passes repeatedly;
2. 2–3 real Debian staging VMs inventory successfully over pinned SSH trust;
3. a real authoritative package finding is correlated without manual fabrication;
4. one Approval-mode package remediation succeeds inside a maintenance window;
5. fresh inventory proves the fixed version;
6. verification reaches `Verified_Closed`;
7. at least one intentionally induced operational failure is handled safely (for example SSH interruption before execution, not a destructive package failure);
8. backups can be restored independently of CTVLMS;
9. several subsequent cycles remain stable with execution disabled;
10. no unresolved P0/P1 defect remains from the staging run.

Passing this gate supports a **controlled on-prem design-partner pilot**. It does not establish enterprise maturity, HA, multi-tenancy, non-Debian package authority, or an independent security audit.
