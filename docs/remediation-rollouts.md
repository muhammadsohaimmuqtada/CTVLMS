# Remediation rollouts

CTVLMS can optionally place managed assets into staged remediation rollout groups. Assets with no rollout-group assignment preserve the existing remediation behaviour.

A rollout group has three phases:

- `Canary`: only the deterministic canary subset is allowed to execute remediation jobs.
- `General`: all assigned assets may execute, subject to the group's concurrency ceiling.
- `Paused`: no assigned asset may execute a remediation job.

Canary membership is deterministic for a `(groupID, assetID)` pair, so restarting workers does not reshuffle the blast radius. A job blocked by rollout policy is safely released from its lease, does not consume a patch attempt, returns the exposure/lifecycle to the queued/confirmed state, and is deferred before being reconsidered.

## Create and assign

```bash
php bin/rollout-control.php create production-linux 10 2
php bin/rollout-control.php assign 1 7
php bin/rollout-control.php status 1
```

The example creates a 10% canary with at most two concurrently running remediation jobs across the group.

## Promote or pause

Promotion is explicit rather than automatic:

```bash
php bin/rollout-control.php phase 1 General "Canary validation approved in change window CHG-1234"
```

Pause immediately when operators need to stop new execution:

```bash
php bin/rollout-control.php phase 1 Paused "Application error rate increased during rollout"
```

Return to canary mode after investigation:

```bash
php bin/rollout-control.php phase 1 Canary "Rollback complete; resume limited validation"
```

Every create/assignment/phase/defer/outcome transition is recorded in `remediation_rollout_events`.

## Failure containment

Groups default to automatic pause after the configured failure threshold. Post-execution failures such as an upgrade failure, unknown execution outcome, or unchanged package version are recorded as rollout failures. Preflight connectivity failures and stale-inventory aborts do not count as blast-radius failures because no package mutation was attempted.

Automatic pause stops future execution for the group. It does **not** attempt an automatic package downgrade. Package rollback is distribution- and repository-dependent and must not be assumed safe merely because an earlier version string is known.

## Safety boundaries

Rollout policy is an additional gate. It does not bypass or weaken existing requirements for:

- authoritative package/advisory identity;
- patch-policy mode and approval;
- maintenance windows;
- backup evidence when required;
- strict SSH host-key verification;
- fenced worker leases and heartbeats;
- exact pre-patch version validation;
- fresh inventory before `Verified Closed`.

Keep `CTVLMS_EXECUTE_PATCHES=0` until the complete workflow has been validated against disposable targets.
