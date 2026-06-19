# CTVLMS Schema Rationale

This document outlines the design decisions and normalization rationale behind the Cyber Threat & Vulnerability Lifecycle Management System (CTVLMS) database schema.

## Normalization Decisions

The schema is designed to 3rd Normal Form (3NF) to ensure data integrity and eliminate redundancy:

1. **Atomic Attributes**: All attributes hold atomic values (e.g., `fullName`, `email`, `cveID`).
2. **No Partial Dependencies**: Every non-key attribute is fully dependent on the primary key. For example, in the `assets` table, `assetName`, `osPlatform`, and `criticality` depend entirely on `assetID`.
3. **No Transitive Dependencies**: Non-key attributes do not depend on other non-key attributes. Instead of storing user details directly on the `assets` table, we store an `ownerUserID` foreign key referencing the `users` table.

## Why Junction Tables?

The system models complex, real-world cybersecurity relationships that are inherently Many-to-Many (N:M). Junction tables resolve these relationships into two One-to-Many (1:N) relationships, maintaining normalization:

1. **`asset_vulnerabilities`**: An asset can have many vulnerabilities, and a specific vulnerability (like Log4Shell) can affect many assets. This table links `assetID` and `vulnID`.
2. **`engagement_assets`**: A red team engagement typically scopes multiple target assets, and a single asset might be tested across multiple different engagements over time. This table links `engagementID` and `assetID`.

## Why Does `status` Live on `asset_vulnerabilities`?

A common anti-pattern in vulnerability management schemas is placing the `status` directly on the `vulnerabilities` table. We explicitly placed it on the junction table (`asset_vulnerabilities`) for the following crucial reasons:

1. **Lifecycle Granularity**: A single vulnerability (e.g., CVE-2024-3094) might be "Remediated" on a Development workstation (`WS-DEV-01`) but still "Discovered" and unpatched on a Production web server (`WEB-PROD-01`). If `status` lived on the `vulnerabilities` table, we could only track the status globally, losing the ability to track remediation progress per asset.
2. **Accurate Tracking**: Placing `status`, `discoveredDate`, `dueDate`, and `closedDate` on the junction table allows analysts to accurately track SLAs and remediation timelines for individual instances of a vulnerability.

## Foreign Key Constraints

We used specific `ON DELETE` rules to maintain referential integrity without destroying historical context:

- **`ON DELETE CASCADE`**: Used on junction tables (`asset_vulnerabilities`, `engagement_assets`) and child findings/remediations. If an asset is deleted, all its associated vulnerability instances and findings are automatically removed to prevent orphaned records.
- **`ON DELETE SET NULL`**: Used for User references (e.g., `ownerUserID`, `assignedToUserID`, `discoveredByUserID`) and Threat Actor references. If an employee leaves the company and their User record is deleted, we do *not* want to delete the Incident they were investigating. Instead, the assignment simply becomes `NULL`.
