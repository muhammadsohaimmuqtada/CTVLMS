# 🛡️ CTVLMS — Cyber Threat & Vulnerability Lifecycle Management System

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-10.5+-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)
![Security](https://img.shields.io/badge/Security-Hardened-2ea44f?style=for-the-badge)

A full-stack enterprise web application designed to track cybersecurity threats, vulnerabilities, assets, incidents, red team engagements, and remediations. Built with a robust **Role-Based Access Control (RBAC)** architecture, strict audit logging, a real-time dashboard, and a comprehensive database reports engine.

> **Course**: Database Systems  
> **Stack**: PHP 8+ · MySQL/MariaDB · Bootstrap 5 · Chart.js

---

## ✨ Core Features

- **12-Table Normalized Schema** — 3NF compliant with proper foreign keys, `CHECK` constraints, and indexes.
- **Vulnerability Lifecycle Board** — Track the exact state of vulnerabilities per asset (Discovered → Triaged → Confirmed → Remediation → Verified Closed).
- **Role-Based Access Control** — 5 distinct roles (`Admin`, `SOC Analyst`, `Red Teamer`, `Vuln Manager`, `Viewer`) with granular backend permission enforcement.
- **Interactive Dashboard** — Dynamic Chart.js visualizations built directly from real-time database queries, plus a live attention feed.
- **NIST NVD Integration** — Server-side API sync to fetch real-world CVE data from the US Government's National Vulnerability Database.
- **Audit Logging** — Immutable tracking of every `CREATE`, `UPDATE`, `DELETE`, `STATUS_CHANGE`, `LOGIN`, and `LOGOUT` across the entire platform.
- **Security by Design** — PDO prepared statements (SQLi protection), `htmlspecialchars` (XSS protection), bcrypt password hashing, CSRF tokens, and strict session hardening.

---

## 🚀 Quick Start & Installation

### Prerequisites
- PHP 8.0+ (with extensions: `pdo_mysql`, `mbstring`, `json`, `session`, `openssl`)
- MySQL 8.0+ or MariaDB 10.5+
- Linux/Unix environment (recommended)

### 1. Unified Launcher (Easiest Way)
If you are on a Linux environment (like Kali), we have provided a single launcher script that handles the database and servers automatically:
```bash
./ctvlms.sh
```
*This will start MariaDB, the Web Portal on port 8000, and the Admin Tools on port 8080.*

### 2. Manual Setup
If you prefer to start the services manually:

```bash
# Start the Database
sudo systemctl start mariadb

# Import Schema & Seed Data
mysql -u root -p < database/schema.sql
mysql -u root -p ctvlms < database/seed.sql

# Configure Credentials
cp config/config.example.php config/config.php
# Edit config/config.php with your local database credentials

# Run the Application
php -S localhost:8000 -t .
```

---

## 🔑 Default Credentials

| Role | Email | Password |
|------|-------|----------|
| **Admin** | `admin@ctvlms.local` | `Admin@123` |
| **SOC Analyst** | `soc.analyst@ctvlms.local` | `Admin@123` |
| **Red Teamer** | `red.teamer@ctvlms.local` | `Admin@123` |
| **Vuln Manager** | `vuln.manager@ctvlms.local` | `Admin@123` |
| **Viewer** | `viewer@ctvlms.local` | `Admin@123` |

> ⚠️ *These are seed credentials for development and demonstration purposes. Ensure passwords are changed in a production deployment.*

---

## 🗄️ Database Architecture (ERD)

We have included a highly professional, interactive, drag-and-drop Entity Relationship Diagram (ERD) visualizer!  
**Open `schema_viewer.html` in your browser to view the interactive schema.**

The database consists of **12 tables** organized into 5 logical domains:

1. **Identity & Access** (`users`)
2. **Assets & Vulnerabilities** (`assets`, `vulnerabilities`, `asset_vulnerabilities`)
3. **Threat Intelligence** (`threat_actors`, `indicators_of_compromise`)
4. **Incident Response** (`incidents`)
5. **Red Team & Remediation** (`engagements`, `engagement_assets`, `findings`, `remediations`)
6. **System Audit** (`audit_log`)

---

## 📊 Advanced Query Bank

The backend executes complex SQL operations to build the dashboard and reports. The query bank demonstrates:
- **Multi-table JOINs** (INNER, LEFT, RIGHT, and 3-way JOINs)
- **Aggregations & GROUP BY** (Mean time to remediate, Severity distributions)
- **Correlated Subqueries** (Assets with above-average CVSS scores)
- **UNION operations** (Combined attention feed of recent incidents and vulns)

---

## 🛡️ Security Posture

| Threat Vector | Applied Mitigation Strategy |
|--------|-----------|
| **SQL Injection (SQLi)** | 100% PDO prepared statements with strongly bound parameters. |
| **Cross-Site Scripting (XSS)** | All user-supplied output is strictly escaped with `htmlspecialchars()` via a global `e()` helper. |
| **Cross-Site Request Forgery (CSRF)** | Cryptographically secure tokens generated on session creation and validated on every POST endpoint. |
| **Broken Authentication** | Passwords hashed using `bcrypt`. Verification via `password_verify()`. |
| **Session Hijacking** | Enforced `HttpOnly`, `SameSite=Strict`, and strict mode cookies. `session_regenerate_id(true)` applied on login/logout. |

---

*Developed for Academic/Viva Purposes. Do not expose to the internet without proper firewall and TLS configuration.*
