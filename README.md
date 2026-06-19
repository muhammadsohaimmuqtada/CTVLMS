# CTVLMS — Cyber Threat & Vulnerability Lifecycle Management System

A full-stack web application for tracking cybersecurity threats, vulnerabilities,
assets, incidents, red team engagements, and remediations — with role-based access
control, audit logging, a real-time dashboard, and a comprehensive reports engine.

> **Course**: Database Systems  
> **Stack**: PHP 8+ · MySQL/MariaDB · Bootstrap 5 · Chart.js

---

## Features

- **12-table normalized schema** with proper foreign keys, CHECK constraints, and indexes
- **Full CRUD** on all entities (Assets, Vulnerabilities, Threat Actors, IOCs, Incidents, Engagements, Findings, Remediations)
- **Vulnerability Lifecycle Board** — track status from Discovered → Triaged → Confirmed → Remediation → Verified Closed
- **Role-Based Access Control** — 5 roles (Admin, SOC Analyst, Red Teamer, Vuln Manager, Viewer) with granular permissions
- **Interactive Dashboard** — 4 Chart.js visualizations + attention feed
- **Reports Page** — runs all 12 query-bank queries (JOINs, subqueries, aggregation, UNION, views)
- **Audit Logging** — every CREATE, UPDATE, DELETE, STATUS_CHANGE, LOGIN, LOGOUT is tracked
- **Security by design** — PDO prepared statements, htmlspecialchars, bcrypt passwords, CSRF tokens, session hardening

---

## Quick Start

### Prerequisites

- PHP 8.0+ with extensions: `pdo_mysql`, `mbstring`, `json`, `session`, `openssl`
- MySQL 8.0+ or MariaDB 10.5+

### 1. Start the Database

```bash
# If using local MariaDB/MySQL:
sudo systemctl start mariadb    # or: sudo systemctl start mysql

# Or use Docker:
docker-compose up -d
```

### 2. Import Schema & Seed Data

```bash
mysql -u root -p < database/schema.sql
mysql -u root -p ctvlms < database/seed.sql
```

### 3. Configure Credentials

```bash
cp config/config.example.php config/config.php
# Edit config/config.php with your database credentials
```

### 4. Run the Application

```bash
php -S localhost:8000
```

Open **http://localhost:8000** in your browser.

---

## Default Login Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@ctvlms.local | Admin@123 |
| SOC Analyst | soc.analyst@ctvlms.local | Admin@123 |
| Red Teamer | red.teamer@ctvlms.local | Admin@123 |
| Vuln Manager | vuln.manager@ctvlms.local | Admin@123 |
| Viewer | viewer@ctvlms.local | Admin@123 |

> ⚠️ Change these passwords after first login in a real deployment.

---

## Database Schema (ERD)

The schema consists of 12 tables organized into 4 logical groups:

### Core Assets & Vulnerabilities
- `users` — System users with role-based access
- `assets` — IT assets being protected/tested
- `vulnerabilities` — CVE-linked vulnerability catalog
- `asset_vulnerabilities` — **Junction table** linking assets to vulns with lifecycle status

### Threat Intelligence
- `threat_actors` — Known APT groups and threat actors
- `indicators_of_compromise` — IOCs linked to threat actors

### Incident Response
- `incidents` — Security incidents linked to assets, actors, and vulnerabilities

### Red Team Operations
- `engagements` — Pentest/red team engagements
- `engagement_assets` — **Junction table** for engagement scope
- `findings` — Red team findings from engagements
- `remediations` — Fix actions tracked against asset vulnerabilities

### Audit
- `audit_log` — Complete audit trail of all system actions

---

## Query Bank

The Reports page demonstrates 12 queries covering:

1. **INNER JOIN** — Assets with open vulnerabilities
2. **LEFT JOIN** — All assets with vulnerability counts
3. **Multi-table JOIN** — Full incident reports
4. **JOIN + GROUP BY + HAVING** — Critical assets with 3+ unresolved vulns
5. **Correlated subquery** — Vulns with above-average CVSS
6. **Subquery with IN** — Assets in active engagements
7. **Three-way JOIN** — High/critical red team findings
8. **Aggregation** — Mean time to remediate by criticality
9. **RIGHT JOIN** — IOCs with attributed actors
10. **UNION** — Combined attention feed
11. **View** — Open lifecycle dashboard view
12. **Self-contained** — Top 5 most attacked assets

---

## Project Structure

```
ctvlms/
├── config/              # Database credentials & connection
├── database/            # Schema, seed data, query bank
├── includes/            # Auth, CSRF, audit, helpers, layout
├── pages/               # All page files (CRUD + dashboard + reports)
├── public/              # Static assets (CSS, JS)
├── index.php            # Front controller / router
├── docker-compose.yml   # Optional Docker setup
└── README.md
```

---

## Security Measures

| Threat | Mitigation |
|--------|-----------|
| SQL Injection | PDO prepared statements with bound parameters everywhere |
| XSS | All output escaped with `htmlspecialchars()` via `e()` helper |
| CSRF | Token on every POST form, validated server-side |
| Password Storage | `password_hash()` with bcrypt, verified with `password_verify()` |
| Session Fixation | `session_regenerate_id(true)` on login |
| Session Hijacking | HttpOnly, SameSite=Strict, strict mode cookies |
| Credential Exposure | `config.php` gitignored, example template committed |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | PHP 8.4 (procedural with PDO) |
| Database | MariaDB 11.8 / MySQL 8.0+ |
| Frontend | Bootstrap 5.3 (CDN) |
| Charts | Chart.js 4.x (CDN) |
| Icons | Bootstrap Icons (CDN) |
| Fonts | Inter, JetBrains Mono (Google Fonts) |
| Server | PHP built-in development server |
