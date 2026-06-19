-- =====================================================================
-- Cyber Threat & Vulnerability Lifecycle Management System (CTVLMS)
-- Database Schema (MySQL 8.0+)
-- =====================================================================

CREATE DATABASE IF NOT EXISTS ctvlms;
USE ctvlms;

-- ---------------------------------------------------------------------
-- 1. USERS  (analysts, red teamers, admins, managers)
-- ---------------------------------------------------------------------
CREATE TABLE users (
    userID INT AUTO_INCREMENT PRIMARY KEY,
    fullName VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    passwordHash VARCHAR(255) NOT NULL,
    role ENUM('Admin','SOC_Analyst','Red_Teamer','Vuln_Manager','Viewer') NOT NULL DEFAULT 'Viewer',
    isActive BOOLEAN NOT NULL DEFAULT TRUE,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 2. ASSETS  (anything being protected / tested)
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    assetID INT AUTO_INCREMENT PRIMARY KEY,
    assetName VARCHAR(150) NOT NULL,
    assetType ENUM('Server','Workstation','Network_Device','Web_App','Database','Cloud_Resource','IoT_Device') NOT NULL,
    ipAddress VARCHAR(45),
    osPlatform VARCHAR(100),
    ownerUserID INT,
    criticality ENUM('Low','Medium','High','Critical') NOT NULL DEFAULT 'Medium',
    environment ENUM('Production','Staging','Development','Test') NOT NULL DEFAULT 'Production',
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ownerUserID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 3. VULNERABILITIES  (CVE-linked or custom findings catalog)
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    vulnID INT AUTO_INCREMENT PRIMARY KEY,
    cveID VARCHAR(20) UNIQUE,                 -- e.g. CVE-2024-3094, NULL if internal finding
    title VARCHAR(200) NOT NULL,
    description TEXT,
    cvssScore DECIMAL(3,1) CHECK (cvssScore BETWEEN 0.0 AND 10.0),
    severity ENUM('Low','Medium','High','Critical') NOT NULL,
    cwe VARCHAR(20),                          -- e.g. CWE-79
    publishedDate DATE,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 4. ASSET_VULNERABILITIES  (junction: which assets have which vulns)
--    This is the heart of the LIFECYCLE -- status lives here, per asset.
-- ---------------------------------------------------------------------
CREATE TABLE asset_vulnerabilities (
    assetVulnID INT AUTO_INCREMENT PRIMARY KEY,
    assetID INT NOT NULL,
    vulnID INT NOT NULL,
    status ENUM('Discovered','Triaged','Confirmed','Remediation_In_Progress',
                'Remediated','Verified_Closed','Risk_Accepted') NOT NULL DEFAULT 'Discovered',
    discoveredDate DATE NOT NULL,
    triagedByUserID INT,
    dueDate DATE,
    closedDate DATE,
    notes TEXT,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (vulnID) REFERENCES vulnerabilities(vulnID) ON DELETE CASCADE,
    FOREIGN KEY (triagedByUserID) REFERENCES users(userID) ON DELETE SET NULL,
    UNIQUE KEY uq_asset_vuln (assetID, vulnID)
);

-- ---------------------------------------------------------------------
-- 5. THREAT_ACTORS
-- ---------------------------------------------------------------------
CREATE TABLE threat_actors (
    actorID INT AUTO_INCREMENT PRIMARY KEY,
    actorName VARCHAR(150) NOT NULL,           -- e.g. "APT29", "Lazarus Group"
    aliasNames VARCHAR(255),
    motivation ENUM('Financial','Espionage','Hacktivism','Disruption','Unknown') DEFAULT 'Unknown',
    originCountry VARCHAR(100),
    description TEXT
);

-- ---------------------------------------------------------------------
-- 6. INDICATORS_OF_COMPROMISE (IOCs)
-- ---------------------------------------------------------------------
CREATE TABLE indicators_of_compromise (
    iocID INT AUTO_INCREMENT PRIMARY KEY,
    actorID INT,
    iocType ENUM('IP','Domain','URL','File_Hash','Email','Registry_Key') NOT NULL,
    iocValue VARCHAR(255) NOT NULL,
    mitreTechnique VARCHAR(20),                -- e.g. T1566
    firstSeen DATE,
    lastSeen DATE,
    confidenceLevel ENUM('Low','Medium','High') DEFAULT 'Medium',
    FOREIGN KEY (actorID) REFERENCES threat_actors(actorID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 7. INCIDENTS  (real security incidents)
-- ---------------------------------------------------------------------
CREATE TABLE incidents (
    incidentID INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    assetID INT NOT NULL,
    actorID INT,                               -- attributed threat actor, if known
    relatedVulnID INT,                         -- vuln exploited to cause this incident
    severity ENUM('Low','Medium','High','Critical') NOT NULL,
    status ENUM('Open','Investigating','Contained','Eradicated','Recovered','Closed') NOT NULL DEFAULT 'Open',
    detectedDate DATETIME NOT NULL,
    closedDate DATETIME,
    assignedToUserID INT,
    description TEXT,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (actorID) REFERENCES threat_actors(actorID) ON DELETE SET NULL,
    FOREIGN KEY (relatedVulnID) REFERENCES vulnerabilities(vulnID) ON DELETE SET NULL,
    FOREIGN KEY (assignedToUserID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 8. ENGAGEMENTS  (red team / pentest engagements)
-- ---------------------------------------------------------------------
CREATE TABLE engagements (
    engagementID INT AUTO_INCREMENT PRIMARY KEY,
    engagementName VARCHAR(200) NOT NULL,
    engagementType ENUM('Pentest','Red_Team','Purple_Team','Vuln_Assessment') NOT NULL,
    leadUserID INT,
    startDate DATE NOT NULL,
    endDate DATE,
    status ENUM('Planned','In_Progress','Completed','Cancelled') NOT NULL DEFAULT 'Planned',
    scopeSummary TEXT,
    FOREIGN KEY (leadUserID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 9. ENGAGEMENT_ASSETS  (junction: scope -- which assets are in scope)
-- ---------------------------------------------------------------------
CREATE TABLE engagement_assets (
    engagementAssetID INT AUTO_INCREMENT PRIMARY KEY,
    engagementID INT NOT NULL,
    assetID INT NOT NULL,
    FOREIGN KEY (engagementID) REFERENCES engagements(engagementID) ON DELETE CASCADE,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    UNIQUE KEY uq_engagement_asset (engagementID, assetID)
);

-- ---------------------------------------------------------------------
-- 10. FINDINGS  (red team findings -- linked to engagement + vuln)
-- ---------------------------------------------------------------------
CREATE TABLE findings (
    findingID INT AUTO_INCREMENT PRIMARY KEY,
    engagementID INT NOT NULL,
    assetID INT NOT NULL,
    vulnID INT,                                -- nullable: novel finding may not map to catalog yet
    discoveredByUserID INT,
    title VARCHAR(200) NOT NULL,
    riskRating ENUM('Low','Medium','High','Critical') NOT NULL,
    exploitedSuccessfully BOOLEAN DEFAULT FALSE,
    proofOfConcept TEXT,
    recommendation TEXT,
    reportedDate DATE NOT NULL,
    FOREIGN KEY (engagementID) REFERENCES engagements(engagementID) ON DELETE CASCADE,
    FOREIGN KEY (assetID) REFERENCES assets(assetID) ON DELETE CASCADE,
    FOREIGN KEY (vulnID) REFERENCES vulnerabilities(vulnID) ON DELETE SET NULL,
    FOREIGN KEY (discoveredByUserID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 11. REMEDIATIONS  (patch/fix actions tracked against asset_vulnerabilities)
-- ---------------------------------------------------------------------
CREATE TABLE remediations (
    remediationID INT AUTO_INCREMENT PRIMARY KEY,
    assetVulnID INT NOT NULL,
    assignedToUserID INT,
    actionTaken TEXT NOT NULL,
    remediationType ENUM('Patch','Configuration_Change','Compensating_Control','Decommission','Risk_Acceptance') NOT NULL,
    startedDate DATE,
    completedDate DATE,
    verifiedByUserID INT,
    verificationDate DATE,
    FOREIGN KEY (assetVulnID) REFERENCES asset_vulnerabilities(assetVulnID) ON DELETE CASCADE,
    FOREIGN KEY (assignedToUserID) REFERENCES users(userID) ON DELETE SET NULL,
    FOREIGN KEY (verifiedByUserID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- 12. AUDIT_LOG  (who changed what, when -- standard for a security tool)
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    logID INT AUTO_INCREMENT PRIMARY KEY,
    userID INT,
    actionType VARCHAR(50) NOT NULL,           -- e.g. 'STATUS_CHANGE', 'CREATE', 'DELETE'
    tableAffected VARCHAR(50) NOT NULL,
    recordID INT,
    actionDetail TEXT,
    actionTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userID) REFERENCES users(userID) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------
-- INDEXES for common lookups
-- ---------------------------------------------------------------------
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_assetvuln_status ON asset_vulnerabilities(status);
CREATE INDEX idx_incident_status ON incidents(status);
CREATE INDEX idx_ioc_value ON indicators_of_compromise(iocValue);
