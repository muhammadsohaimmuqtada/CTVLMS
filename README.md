# CTVLMS — Cyber Threat & Vulnerability Lifecycle Management System

CTVLMS is an academic full-stack database project for tracking security assets, vulnerabilities, incidents, threat intelligence, red-team engagements, remediation work, and audit history in one application.

The project was built to combine database design with practical security controls such as role-based access control, prepared queries, CSRF protection, password hashing, session hardening, and audit logging.

> **Academic / demonstration project:** this repository is intended for coursework, local evaluation, and portfolio use. It has not been independently security-audited and should not be exposed to the public internet without additional hardening.

## Stack

- PHP 8+
- MySQL / MariaDB
- Bootstrap 5
- Chart.js

## Core capabilities

### Vulnerability lifecycle tracking

Track vulnerabilities against assets through discovery, triage, confirmation, remediation, and verification states.

### Role-based access control

The application defines separate operational roles including:

- Admin
- SOC Analyst
- Red Teamer
- Vulnerability Manager
- Viewer

Authorization checks are enforced server-side rather than being limited to interface visibility.

### Security operations data model

The schema covers:

- users and roles
- assets
- vulnerabilities
- asset/vulnerability relationships
- threat actors
- indicators of compromise
- incidents
- engagements and engagement assets
- findings
- remediations
- audit records

### Dashboard and reporting

The application uses SQL aggregation, joins, subqueries, and Chart.js visualizations to surface current security state and reporting metrics.

### NVD integration

Server-side integration can retrieve CVE information from the NIST National Vulnerability Database for use in the local vulnerability workflow.

## Security controls demonstrated

| Area | Implementation |
|---|---|
| SQL injection | PDO prepared statements and parameter binding |
| Output encoding | HTML escaping for user-controlled output |
| CSRF | Per-session tokens validated on state-changing requests |
| Password storage | `password_hash()` / bcrypt-compatible verification |
| Sessions | hardened cookie settings and session ID rotation |
| Authorization | server-side role checks |
| Auditability | application activity recorded in the audit log |

These controls demonstrate secure-design concepts but should not be interpreted as a production security certification.

## Database design

The schema is normalized around operational security domains and includes foreign keys, constraints, and indexes. An interactive ERD viewer is included in `schema_viewer.html`.

The project also demonstrates SQL concepts including:

- multi-table joins
- aggregate reporting
- `GROUP BY`
- correlated subqueries
- `UNION` queries
- lifecycle/status queries

## Quick start

### Requirements

- PHP 8.0+
- MySQL 8.0+ or MariaDB 10.5+
- PHP extensions required by the application

### Local launcher

```bash
./ctvlms.sh
```

### Manual setup

```bash
sudo systemctl start mariadb

mysql -u root -p < database/schema.sql
mysql -u root -p ctvlms < database/seed.sql

cp config/config.example.php config/config.php
# Update the local database settings in config/config.php

php -S localhost:8000 -t .
```

## Development credentials

The seed dataset includes demonstration accounts for the predefined roles. These credentials are intended only for local development and should be replaced before any shared or network-accessible deployment.

## Project purpose

CTVLMS is primarily a database-systems project with a cybersecurity domain model. Its value is in demonstrating relational schema design, access-control modeling, reporting queries, CRUD workflows, and secure web-development practices in one application.
