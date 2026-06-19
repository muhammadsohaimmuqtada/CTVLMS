-- =====================================================================
-- CTVLMS — Seed Data
-- Realistic cybersecurity data for demo / course presentation
-- All passwords: Admin@123 (bcrypt hashed)
-- =====================================================================

USE ctvlms;

-- ----- 1. USERS (one per role) -----
INSERT INTO users (fullName, email, passwordHash, role, isActive) VALUES
('Sarah Chen',       'admin@ctvlms.local',        '$2y$12$iXyJMgrWtrmWAvDNvyL0EeLl4IgkDvdgtcIYW1FMTf58FSMzCQ4N2', 'Admin',        TRUE),
('Marcus Williams',  'soc.analyst@ctvlms.local',  '$2y$12$iXyJMgrWtrmWAvDNvyL0EeLl4IgkDvdgtcIYW1FMTf58FSMzCQ4N2', 'SOC_Analyst',  TRUE),
('Alex Rivera',      'red.teamer@ctvlms.local',   '$2y$12$iXyJMgrWtrmWAvDNvyL0EeLl4IgkDvdgtcIYW1FMTf58FSMzCQ4N2', 'Red_Teamer',   TRUE),
('Priya Patel',      'vuln.manager@ctvlms.local', '$2y$12$iXyJMgrWtrmWAvDNvyL0EeLl4IgkDvdgtcIYW1FMTf58FSMzCQ4N2', 'Vuln_Manager', TRUE),
('Jordan Blake',     'viewer@ctvlms.local',       '$2y$12$iXyJMgrWtrmWAvDNvyL0EeLl4IgkDvdgtcIYW1FMTf58FSMzCQ4N2', 'Viewer',       TRUE);

-- ----- 2. ASSETS (10 mixed types) -----
INSERT INTO assets (assetName, assetType, ipAddress, osPlatform, ownerUserID, criticality, environment) VALUES
('WEB-PROD-01',    'Web_App',         '10.0.1.10',  'Ubuntu 22.04 / Nginx',         1, 'Critical',  'Production'),
('DB-PROD-01',     'Database',        '10.0.1.20',  'Ubuntu 22.04 / MySQL 8.0',     1, 'Critical',  'Production'),
('APP-PROD-01',    'Server',          '10.0.1.30',  'RHEL 9 / Java 17',             4, 'High',      'Production'),
('FW-EDGE-01',     'Network_Device',  '10.0.0.1',   'Fortinet FortiOS 7.4',         1, 'Critical',  'Production'),
('WS-DEV-01',      'Workstation',     '10.0.2.50',  'Windows 11 Pro',               3, 'Medium',    'Development'),
('CLOUD-AWS-01',   'Cloud_Resource',  NULL,          'AWS EC2 / Amazon Linux 2023',  4, 'High',      'Production'),
('IOT-SENSOR-01',  'IoT_Device',      '10.0.3.100', 'Embedded Linux',               2, 'Low',       'Production'),
('WEB-STG-01',     'Web_App',         '10.0.4.10',  'Ubuntu 22.04 / Apache',        4, 'Medium',    'Staging'),
('VPN-GW-01',      'Network_Device',  '10.0.0.5',   'OpenVPN / Ubuntu 22.04',       1, 'High',      'Production'),
('MAIL-PROD-01',   'Server',          '10.0.1.40',  'Ubuntu 22.04 / Postfix',       2, 'High',      'Production');

-- ----- 3. VULNERABILITIES (15 real CVEs + internal) -----
INSERT INTO vulnerabilities (cveID, title, description, cvssScore, severity, cwe, publishedDate) VALUES
('CVE-2021-44228', 'Apache Log4j RCE (Log4Shell)',          'Remote code execution via JNDI lookup in Log4j 2.x',                            10.0, 'Critical', 'CWE-502',  '2021-12-10'),
('CVE-2023-34362', 'MOVEit Transfer SQL Injection',         'SQL injection in MOVEit Transfer web application',                               9.8,  'Critical', 'CWE-89',   '2023-06-02'),
('CVE-2024-3094',  'XZ Utils Backdoor',                     'Malicious code in xz/liblzma allowing SSH auth bypass',                         10.0, 'Critical', 'CWE-506',  '2024-03-29'),
('CVE-2023-44487', 'HTTP/2 Rapid Reset DDoS',               'HTTP/2 protocol vulnerability enabling DDoS amplification',                     7.5,  'High',     'CWE-400',  '2023-10-10'),
('CVE-2024-21762', 'FortiOS Out-of-Bound Write',            'Out-of-bounds write in FortiOS SSL VPN allows RCE',                             9.6,  'Critical', 'CWE-787',  '2024-02-09'),
('CVE-2023-22515', 'Atlassian Confluence Broken Auth',      'Broken access control in Confluence Data Center',                               9.8,  'Critical', 'CWE-284',  '2023-10-04'),
('CVE-2023-4966',  'Citrix NetScaler Bleed',                'Information disclosure in Citrix NetScaler ADC',                                 9.4,  'Critical', 'CWE-119',  '2023-10-10'),
('CVE-2024-0012',  'PAN-OS Auth Bypass',                    'Authentication bypass in Palo Alto Networks PAN-OS management interface',       9.8,  'Critical', 'CWE-306',  '2024-11-18'),
('CVE-2022-27925', 'Zimbra RCE (Mbox Path Traversal)',      'Remote code execution via directory traversal in Zimbra',                       7.2,  'High',     'CWE-22',   '2022-04-21'),
('CVE-2023-23397', 'Microsoft Outlook Elevation of Privilege','NTLM credential theft via crafted Outlook reminder',                           9.8,  'Critical', 'CWE-294',  '2023-03-14'),
('CVE-2021-26855', 'ProxyLogon (Exchange Server SSRF)',      'Server-side request forgery in Microsoft Exchange Server',                      9.8,  'Critical', 'CWE-918',  '2021-03-02'),
(NULL,             'Weak SSH Configuration',                 'SSH server allows weak ciphers and password authentication',                    5.3,  'Medium',   'CWE-327',  NULL),
(NULL,             'Missing HTTP Security Headers',          'Application missing HSTS, X-Frame-Options, CSP headers',                       4.3,  'Medium',   'CWE-693',  NULL),
(NULL,             'Default SNMP Community String',          'SNMP v2c using default community string "public"',                              7.5,  'High',     'CWE-798',  NULL),
(NULL,             'TLS 1.0/1.1 Still Enabled',             'Server supports deprecated TLS versions',                                        5.9,  'Medium',   'CWE-326',  NULL);

-- ----- 4. ASSET_VULNERABILITIES (20+ mappings, various statuses) -----
INSERT INTO asset_vulnerabilities (assetID, vulnID, status, discoveredDate, triagedByUserID, dueDate, closedDate, notes) VALUES
(3,  1,  'Remediated',              '2023-12-11', 2, '2023-12-18', '2023-12-15', 'Upgraded Log4j to 2.17.1'),
(3,  4,  'Confirmed',               '2023-10-12', 2, '2023-11-12', NULL,         'HTTP/2 module needs update on APP-PROD-01'),
(1,  2,  'Risk_Accepted',           '2023-06-05', 4, '2023-07-05', '2023-06-20', 'MOVEit not in direct use; monitoring only'),
(4,  5,  'Remediation_In_Progress', '2024-02-12', 2, '2024-03-01', NULL,         'FortiOS upgrade scheduled for maintenance window'),
(1,  6,  'Discovered',              '2023-10-06', NULL, NULL,       NULL,         'Confluence instance reachable from web tier'),
(2,  1,  'Verified_Closed',         '2023-12-11', 4, '2023-12-18', '2023-12-14', 'Log4j not directly used; verified no transitive deps'),
(6,  7,  'Triaged',                 '2023-10-15', 2, '2023-11-15', NULL,         'Cloud NetScaler needs patching'),
(5,  10, 'Remediated',              '2023-03-16', 2, '2023-03-23', '2023-03-20', 'Outlook patched via Windows Update'),
(10, 11, 'Remediation_In_Progress', '2023-03-05', 4, '2023-03-15', NULL,         'Exchange CU being tested in staging'),
(1,  12, 'Confirmed',               '2024-01-10', 2, '2024-02-10', NULL,         'SSH hardening needed on web server'),
(4,  14, 'Discovered',              '2024-01-15', NULL, NULL,       NULL,         'SNMP default string found during scan'),
(9,  12, 'Triaged',                 '2024-01-10', 2, '2024-02-10', NULL,         'VPN gateway SSH needs hardening'),
(1,  13, 'Remediation_In_Progress', '2024-01-12', 4, '2024-02-12', NULL,         'Adding security headers to Nginx config'),
(7,  15, 'Discovered',              '2024-02-01', NULL, NULL,       NULL,         'IoT sensor only supports TLS 1.1'),
(8,  13, 'Confirmed',               '2024-01-14', 2, '2024-02-14', NULL,         'Staging web app missing security headers'),
(3,  9,  'Triaged',                 '2024-03-01', 2, '2024-04-01', NULL,         'Zimbra path traversal check on app server'),
(6,  8,  'Discovered',              '2024-11-20', NULL, NULL,       NULL,         'PAN-OS management interface exposed'),
(10, 12, 'Confirmed',               '2024-01-10', 2, '2024-02-10', NULL,         'Mail server SSH needs hardening'),
(5,  15, 'Remediation_In_Progress', '2024-02-05', 4, '2024-03-05', NULL,         'Disabling TLS 1.0/1.1 on dev workstation'),
(2,  12, 'Discovered',              '2024-01-10', NULL, NULL,       NULL,         'Database server SSH weak config');

-- ----- 5. THREAT_ACTORS (5 APT groups) -----
INSERT INTO threat_actors (actorName, aliasNames, motivation, originCountry, description) VALUES
('APT29',        'Cozy Bear, Midnight Blizzard, NOBELIUM', 'Espionage',   'Russia',       'Russian SVR-linked group; SolarWinds, Microsoft cloud campaigns'),
('Lazarus Group','Hidden Cobra, ZINC, Diamond Sleet',      'Financial',   'North Korea',  'DPRK state-sponsored; cryptocurrency theft, ransomware, espionage'),
('FIN7',         'Carbanak, Navigator Group',              'Financial',   'Russia',       'Financially-motivated cybercrime; retail POS, hospitality sectors'),
('APT41',        'Double Dragon, Barium, Wicked Panda',    'Espionage',   'China',        'Chinese dual-espionage/cybercrime group; supply chain attacks'),
('Volt Typhoon', 'Bronze Silhouette, Vanguard Panda',      'Disruption',  'China',        'Chinese state actor targeting US critical infrastructure via LOTL');

-- ----- 6. INDICATORS_OF_COMPROMISE (12 IOCs) -----
INSERT INTO indicators_of_compromise (actorID, iocType, iocValue, mitreTechnique, firstSeen, lastSeen, confidenceLevel) VALUES
(1, 'IP',        '185.56.83.129',               'T1071', '2023-06-01', '2024-01-15', 'High'),
(1, 'Domain',    'svr-updates.nightowl[.]com',  'T1566', '2023-05-10', '2023-12-20', 'High'),
(2, 'File_Hash', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2', 'T1059', '2024-01-05', '2024-03-10', 'High'),
(2, 'Domain',    'crypto-bridge-api[.]xyz',      'T1105', '2024-02-01', '2024-04-15', 'Medium'),
(3, 'Email',     'invoice-support@fin7corp[.]com','T1566', '2023-08-15', '2024-02-20', 'Medium'),
(3, 'IP',        '91.234.99.42',                'T1071', '2023-09-01', '2024-01-30', 'High'),
(4, 'File_Hash', 'f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2', 'T1195', '2023-07-20', '2024-03-05', 'Medium'),
(4, 'URL',       'hxxps://updates.apt41-c2[.]net/stage2', 'T1105', '2023-11-01', '2024-02-28', 'High'),
(5, 'IP',        '103.43.18.57',                'T1090', '2024-01-10', '2024-06-01', 'High'),
(5, 'Registry_Key', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SysHealthMon', 'T1547', '2024-02-15', '2024-05-20', 'Medium'),
(NULL, 'IP',     '45.33.32.156',                'T1046', '2024-03-01', '2024-03-01', 'Low'),
(NULL, 'Domain', 'suspicious-login-check[.]io',  'T1566', '2024-04-10', '2024-04-10', 'Low');

-- ----- 7. INCIDENTS (6 incidents) -----
INSERT INTO incidents (title, assetID, actorID, relatedVulnID, severity, status, detectedDate, closedDate, assignedToUserID, description) VALUES
('Log4Shell Exploitation Attempt on APP-PROD-01',   3, 2, 1,  'Critical', 'Closed',        '2023-12-12 03:45:00', '2023-12-15 18:00:00', 2, 'WAF detected JNDI lookup patterns in POST payloads targeting /api/login endpoint. Attack originated from Lazarus-linked IP.'),
('Brute Force Attack on VPN Gateway',               9, NULL, NULL, 'High',  'Contained',     '2024-01-20 14:30:00', NULL, 2, 'Over 50,000 authentication attempts from distributed IPs against VPN-GW-01 in 2 hours.'),
('Phishing Campaign Targeting Finance Team',        5, 3, 10, 'High',     'Investigating', '2024-02-14 09:15:00', NULL, 2, 'Multiple users received emails with malicious .docx attachments exploiting Outlook vuln. FIN7 TTPs observed.'),
('Suspicious Outbound Traffic from IoT Sensor',     7, 5, NULL,'Medium',   'Open',          '2024-03-05 22:10:00', NULL, NULL, 'IoT-SENSOR-01 sending unexpected DNS queries to external resolvers. Possible Volt Typhoon LOTL activity.'),
('FortiOS Management Interface Compromise',         4, 1, 5,  'Critical', 'Eradicated',    '2024-02-15 06:00:00', NULL, 2, 'APT29 exploited CVE-2024-21762 on FW-EDGE-01. Lateral movement detected to internal subnet.'),
('Unauthorized Database Query Spike',               2, NULL, NULL, 'Medium','Recovered',    '2024-04-01 11:30:00', NULL, 4, 'Unusual spike in SELECT queries against sensitive tables from application service account.');

-- ----- 8. ENGAGEMENTS (3 engagements) -----
INSERT INTO engagements (engagementName, engagementType, leadUserID, startDate, endDate, status, scopeSummary) VALUES
('Q1 2024 External Pentest',           'Pentest',          3, '2024-01-15', '2024-02-15', 'Completed', 'External perimeter assessment of production web applications and network devices.'),
('Red Team Exercise — Lateral Movement','Red_Team',         3, '2024-03-01', '2024-04-30', 'In_Progress','Assumed-breach scenario starting from compromised developer workstation. Test lateral movement and data exfiltration paths.'),
('Cloud Infrastructure Vuln Assessment','Vuln_Assessment',  4, '2024-02-01', '2024-02-28', 'Completed', 'Comprehensive vulnerability assessment of AWS cloud resources and configurations.');

-- ----- 9. ENGAGEMENT_ASSETS (scope) -----
INSERT INTO engagement_assets (engagementID, assetID) VALUES
(1, 1), (1, 4), (1, 9), (1, 10),       -- Pentest: web, firewall, VPN, mail
(2, 5), (2, 3), (2, 2), (2, 1),        -- Red team: dev workstation → app → db → web
(3, 6);                                  -- Cloud assessment: CLOUD-AWS-01

-- ----- 10. FINDINGS (8 red team / pentest findings) -----
INSERT INTO findings (engagementID, assetID, vulnID, discoveredByUserID, title, riskRating, exploitedSuccessfully, proofOfConcept, recommendation, reportedDate) VALUES
(1, 1,  6,   3, 'Confluence Broken Access Control',        'Critical', TRUE,  'Accessed /setup/setupadministrator.action without authentication. Full admin access achieved.', 'Restrict Confluence setup endpoints. Apply CVE-2023-22515 patch immediately.', '2024-01-20'),
(1, 4,  5,   3, 'FortiOS SSL VPN Pre-Auth RCE',            'Critical', TRUE,  'Exploited CVE-2024-21762 via crafted HTTP request to /remote/hostcheck_validate. Reverse shell obtained.', 'Upgrade FortiOS to 7.4.3 or later. Restrict management interface access.', '2024-01-25'),
(1, 9,  12,  3, 'VPN Gateway Weak SSH Config',             'Medium',   FALSE, 'SSH server accepts CBC ciphers and allows password auth. Brute-force partially successful in lab.', 'Disable CBC ciphers, enforce key-based auth, implement fail2ban.', '2024-01-28'),
(1, 10, NULL, 3, 'Mail Server Open Relay Misconfiguration', 'High',    TRUE,  'Successfully relayed email through MAIL-PROD-01 from external IP without authentication.', 'Configure Postfix to reject relay from untrusted networks.', '2024-02-01'),
(2, 5,  10,  3, 'Outlook Credential Theft via Phishing',   'High',    TRUE,  'Crafted .msg file with UNC path triggered NTLM hash leak. Hash cracked in 4 hours.', 'Deploy latest Outlook patches. Implement NTLM relay protections.', '2024-03-10'),
(2, 3,  1,   3, 'Lateral Movement via Log4j on APP-PROD',  'Critical', TRUE,  'From compromised workstation, exploited residual Log4j vuln on internal app server. Achieved SYSTEM.', 'Complete Log4j remediation on all internal services. Segment network.', '2024-03-18'),
(2, 2,  NULL, 3, 'Database Credential in Source Code',      'High',    TRUE,  'Found hardcoded MySQL credentials in Git repository. Used to access DB-PROD-01 directly.', 'Rotate all database credentials. Implement secrets management (Vault/AWS SM).', '2024-03-22'),
(3, 6,  NULL, 4, 'S3 Bucket Public Access Enabled',         'High',    FALSE, 'AWS S3 bucket "ctvlms-backups" had public read ACL. Contains database backups.', 'Enable S3 Block Public Access. Review all bucket policies.', '2024-02-10');

-- ----- 11. REMEDIATIONS (6 remediation actions) -----
INSERT INTO remediations (assetVulnID, assignedToUserID, actionTaken, remediationType, startedDate, completedDate, verifiedByUserID, verificationDate) VALUES
(1,  4, 'Upgraded Log4j from 2.14.1 to 2.17.1 on APP-PROD-01. Restarted all Java services.',       'Patch',                  '2023-12-12', '2023-12-15', 2, '2023-12-16'),
(6,  4, 'Verified MySQL connector does not bundle Log4j. Confirmed no transitive Log4j dependency.', 'Compensating_Control',   '2023-12-12', '2023-12-14', 4, '2023-12-15'),
(8,  4, 'Deployed March 2023 Outlook security update via WSUS to all workstations.',                 'Patch',                  '2023-03-17', '2023-03-20', 2, '2023-03-21'),
(4,  4, 'FortiOS upgrade from 7.4.1 to 7.4.3 scheduled. Awaiting change approval.',                 'Patch',                  '2024-02-15', NULL,         NULL, NULL),
(13, 4, 'Adding Content-Security-Policy, X-Frame-Options, HSTS headers to Nginx vhost.',            'Configuration_Change',   '2024-01-20', NULL,         NULL, NULL),
(3,  4, 'MOVEit Transfer not in active use. Risk accepted with quarterly review commitment.',        'Risk_Acceptance',        '2023-06-10', '2023-06-20', 1, '2023-06-20');

-- ----- 12. AUDIT_LOG (initial seed entries) -----
INSERT INTO audit_log (userID, actionType, tableAffected, recordID, actionDetail) VALUES
(1, 'SYSTEM_INIT', 'system', NULL, 'Database initialized with seed data'),
(1, 'CREATE', 'users', 1, 'Created admin user: Sarah Chen'),
(1, 'CREATE', 'users', 2, 'Created SOC analyst: Marcus Williams'),
(1, 'CREATE', 'users', 3, 'Created red teamer: Alex Rivera'),
(1, 'CREATE', 'users', 4, 'Created vuln manager: Priya Patel'),
(1, 'CREATE', 'users', 5, 'Created viewer: Jordan Blake');

-- ----- Create the View from query bank -----
CREATE OR REPLACE VIEW vw_open_lifecycle AS
SELECT a.assetName, v.cveID, v.severity, av.status, av.discoveredDate, av.dueDate,
       DATEDIFF(CURDATE(), av.discoveredDate) AS daysOpen
FROM asset_vulnerabilities av
JOIN assets a ON av.assetID = a.assetID
JOIN vulnerabilities v ON av.vulnID = v.vulnID
WHERE av.status NOT IN ('Remediated','Verified_Closed');
