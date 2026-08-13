# Package intelligence scaling hardening

CTVLMS separates package advisory candidates from exposure findings.

A cross-distribution candidate, such as a Kali package with a matching Debian source-package CVE and no trusted distribution mapping, is summarized in `package_evaluation_state`. It does not create an `exposure_matches` row and cannot queue remediation.

Authoritative package findings require a provider whose distribution and suite match the endpoint facts, or a future explicit trusted mapping. Native authoritative findings continue to use Debian `dpkg --compare-versions` semantics and retain evidence-backed Confirmed, Not Affected, or Potential outcomes.

Coverage metrics distinguish candidate intelligence from authoritative advisory coverage. This prevents an unsupported distribution from appearing fully covered simply because another distribution contains source-package advisories.

Advisory snapshot replacement also has a preflight guard. Unless explicitly overridden, an unexpectedly small replacement snapshot is rejected before the existing good provider dataset is replaced. Environment controls are `CTVLMS_ADVISORY_MIN_RECORDS`, `CTVLMS_ADVISORY_MIN_RATIO`, and `CTVLMS_ALLOW_ADVISORY_SHRINK=1`. The CLI also supports `--allow-shrink` for intentional provider resets.
