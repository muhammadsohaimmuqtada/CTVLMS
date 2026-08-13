# CTVLMS Pilot Release-Candidate Lab

This lab is a disposable, deterministic acceptance environment for proving the CTVLMS remediation lifecycle without touching the host OS or depending on a publicly vulnerable package.

## What it proves

Five isolated Debian 12 SSH targets are created on a private Docker bridge network. Every target starts with a synthetic package `ctvlms-lab-pkg` at version `1.0`. An internal flat apt repository exposes version `1.1`. A synthetic lab-only advisory (`CVE-2099-7701`) declares `1.1` as the fixed version.

The acceptance runner proves:

1. authenticated read-only SSH inventory;
2. authoritative Debian package/source identity;
3. native distribution advisory correlation;
4. normal remediation queue policy and backup gate;
5. canary patch execution through the real patch worker;
6. the real next-cycle order `fresh inventory -> correlation -> verification` preserves verification-owned state;
7. fresh post-patch inventory before `Verified_Closed`;
8. stable Not_Affected evidence does not downgrade `Verified_Closed`;
9. Approval-mode remediation;
10. expired worker lease reclamation after a simulated worker crash;
11. stale evaluated-version fencing after an out-of-band package change;
12. queued remediation cancellation when fresh authoritative evidence makes the patch unnecessary;
13. failed patch classification and automatic rollout pause;
14. database backup checksum and destructive restore on the isolated lab DB.

The fixture CVE is synthetic and must never be represented as a real vulnerability finding.

## Isolation

- The lab uses a dedicated MariaDB container exposed only on `127.0.0.1:33306`.
- Lab PHP tooling refuses to run unless `CTVLMS_LAB_MODE=1` and the database endpoint is exactly the isolated lab endpoint.
- SSH targets are reachable only on the Docker bridge subnet `172.28.77.0/24`; no target SSH port is published to the LAN.
- The lab generates a fresh ephemeral Ed25519 keypair on every start under `lab/.state/`; private keys are gitignored and removed on teardown.
- The one-command runner temporarily uses the env-driven config template and restores the user's ignored local `config/config.php` byte-for-byte on exit.
- The normal CTVLMS database and the host package manager are never used for remediation.

## One-command acceptance run

Requirements: Docker Compose, PHP with PDO MySQL, MariaDB client tools, OpenSSH client, and `ssh-keygen`/`ssh-keyscan`.

```bash
cd ~/CTVLMS
bash lab/bin/full-run.sh
```

The default run tears down containers and removes generated keys after completion.

To inspect the final state before teardown:

```bash
CTVLMS_LAB_KEEP=1 bash lab/bin/full-run.sh
```

Then load the lab environment if you want to inspect the database or rerun a command:

```bash
source lab/.state/env.sh
php bin/package-coverage.php
```

Tear it down explicitly when finished:

```bash
bash lab/bin/down.sh
```

## Expected high-level result

A successful run ends with:

```text
ALL PILOT LAB ACCEPTANCE GATES PASSED
PASS: backup checksum, mutation, destructive restore, and restored-state verification
CTVLMS pilot release-candidate lab: PASS
```

Expected scenario outcomes:

- `ctvlms-lab-canary`: package `1.0 -> 1.1`; correlation runs before verification on the next cycle but cannot erase `Remediated`; verification closes; later correlation preserves `Verified_Closed`.
- `ctvlms-lab-general`: operator approval is required; an abandoned lease is expired and safely reclaimed; package `1.0 -> 1.1`; next-cycle correlation preserves the pending verification state and verification closes.
- `ctvlms-lab-stale`: package is changed out of band before the queued worker executes; the worker refuses to patch stale applicability and records `inventory_changed`; fresh evaluation resolves the package as not affected. The existing lifecycle record intentionally remains open for operator reconciliation because the fix was not executed/verified through the tracked remediation workflow.
- `ctvlms-lab-cancel`: package changes out of band and fresh inventory/correlation happens before execution; the queued job becomes `Cancelled` with `applicability_changed` rather than remaining stuck or patching unnecessarily.
- `ctvlms-lab-failure`: patch cannot obtain an updated package; the job fails and its rollout group automatically pauses.

## What this does not prove

This lab is deterministic release-candidate evidence, not a substitute for a customer pilot. It does not prove WAN latency behavior, real customer SSH policy, enterprise IAM, HA database operation, every Debian package edge case, non-Debian providers, or an independent security assessment.

A release candidate should pass this lab repeatedly before it is offered to a design partner.
