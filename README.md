# 🛡️ SENTRIX SHIELD: Autonomous Security Monitoring & Incident Response Platform

[![CRIMEATHON'26](https://img.shields.io/badge/CRIMEATHON'26-Selection%20Round-blue.svg)](https://github.com)
[![Track](https://img.shields.io/badge/Track-DEFENSE-success.svg)](https://github.com)
[![Team](https://img.shields.io/badge/Team-SENTRIX-green.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg)](https://flask.palletsprojects.com)
[![Tests](https://img.shields.io/badge/Tests-63%2F63%20Passing-brightgreen.svg)](run_tests.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **CRIMEATHON’26 — Case NS-26-014: The Northstar Learning Services Investigation**  
> **Team:** SENTRIX (SIMATS Cyber Club) | **Selected Track:** DEFENSE  
> *All data is strictly synthetic and derived directly from the official case dossier (E01–E12).*

---

## 📑 Executive Summary

On **12 October 2026**, Northstar Skills Academy experienced an unauthorized data exfiltration incident resulting in the external download of **2,300 active learner profiles** (486 KB CSV). A third-party attendance integration credential (`svc_rollcall` / `rc-prod-01`) was abused from an unrecognized external IP (`203.0.113.77`).

**Confirmed Vulnerabilities (Direct Log Evidence):**
1. **Credential Hygiene Failure:** Integration `INT-01` had been active for **approximately 7 months** (created 04-Mar-2026) with **no expiration date** (`expires: never`) and no scheduled rotation in the register (`E05`, `E12`).
2. **Excessive Privileges:** The connector was assigned broad permissions (`learner.search`, `learner.export`, `course.read`), violating least-privilege standards (`NS-SEC-04`, `E08`).
3. **Unrestricted Network Ingress:** The API Gateway lacked source IP allowlisting, permitting requests from external host `203.0.113.77` (`E03`, `E09`).
4. **Absent Telemetry & Rate Limiting:** No real-time alerts or export approval workflows existed; incident was discovered hours later by Finance (`E06 HD-1069`, `E12`).
5. **Separate Offboarding Defect:** Former technician `former.ajay` authenticated on 09-Oct after leaving on 30-Sep (`A006`, `E01`); violates Rule 7 but does not establish responsibility for the external incident.

**Investigated Hypotheses vs. Unknowns:**
* *Hypothesis:* Credential exposure occurred externally (investigated via ticket `HD-1058` screenshot attachment or config read).
* *Unknowns:* Whether the screenshot in `HD-1058` actually revealed secrets (contents unverified); physical identity of the human operator behind `203.0.113.77`; and whether records were distributed onward.

---

## 🚀 The Defense Solution: SENTRIX SHIELD

**SENTRIX SHIELD** is a four-pillar, zero-trust defense platform engineered to detect, prevent, and remediate multi-stage credential abuse and bulk data exfiltration:

```
+-------------------------------------------------------------------------+
|                           SENTRIX SHIELD                                |
+--------------------+--------------------+-------------------------------+
|  1. SIEM TELEMETRY | 2. ZERO-TRUST GATE | 3. VAULT LIFECYCLE | 4. UI    |
|  Real-time Ingest  | IP Allowlisting    | 90-Day Auto Rotate | Live UI  |
|  Heuristic Scores  | Role Scoping (403) | 1-Click Revocation | Timeline |
|  Severity (0-100)  | Export Ceilings    | Short-Lived Tokens | Playbook |
+--------------------+--------------------+--------------------+----------+
```

1. **Real-Time SIEM Ingestion & Anomaly Correlation:** Ingests authentication, API, configuration, and storage audit logs. Evaluates heuristic severity ratings (0–100, measuring policy impact, not compromise probabilities) and alerts on off-subnet requests and rate spikes.
2. **Zero-Trust Hardened API Gateway:** Enforces strict source-IP allowlisting (`10.10.4.12`), restricts connector scopes strictly to `attendance.read` (`403 Forbidden` on unauthorized paths), and enforces export record ceilings.
3. **Automated Credential Lifecycle Manager:** Replaces unexpiring keys with short-lived tokens and simulated automated vault rotation.
4. **Interactive Cyber Command Dashboard:** Cyberpunk SOC dashboard featuring live threat scoring, real-time log streaming, interactive timeline reconstruction, evidence dossiers, attack simulation, and verification controls.

---

## 📂 Project Repository Structure

```
crimathon/
├── app.py                           # Main Flask REST API & Web Server (Auth, RBAC & ipaddress Hardened)
├── requirements.txt                 # Dependencies (Flask, Flask-CORS, python-pptx)
├── run_tests.py                     # Comprehensive Security Test Suite (63/63 Tests Across 20 Categories)
├── PROBLEM_STATEMENT.md             # One-Page Problem Statement (Markdown)
├── PROBLEM_STATEMENT.html           # Print-Ready A4 Single-Page Problem Statement (HTML/CSS)
├── SENTRIX_SHIELD_PRESENTATION.pptx # 10-Slide Technical Evaluation Pitch Deck
├── create_presentation.py           # Presentation Generation Script
├── LICENSE                          # MIT Open-Source License
├── README.md                        # Complete Documentation & Setup Guide
├── static/
│   └── index.html                   # High-Performance Cyberpunk Single-Page Dashboard
├── data/
│   ├── __init__.py
│   ├── loader.py                    # Dynamic Evidence Loader & SHA-256 Integrity Verification
│   ├── logs.py                      # Authentic Security & Audit Event Telemetry (E01–E12)
│   └── evidence.py                  # Official Evidence Dossier (E01–E12 Mappings)
├── analysis/
│   ├── __init__.py
│   ├── anomaly.py                   # Heuristic & SIEM Anomaly Detection Engine
│   └── timeline.py                  # Chronological Attack Timeline Reconstructor
└── FULL PACK/                       # Official Case Evidence & Simulation Tools
    ├── EVIDENCE/                    # Raw CSV, JSON, TXT Logs (E01 to E12)
    └── SAFE_SIMULATION/             # Local Mock API Server & Test Harness
```

---

## ⚡ Quick Start & Execution

### 1. Installation
Ensure Python 3.10+ is installed:
```bash
# Clone the repository (or navigate to directory)
cd crimathon

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Verification Test Suite
Run the 63-point automated security verification suite across 20 categories:
```bash
python run_tests.py
```
*Expected Output: `63 PASSED, 0 FAILED (100% Success Rate)`*

### 3. Launch the SENTRIX SHIELD Web Platform
Start the Flask application:
```bash
python app.py
```
Open your browser and navigate to: **`http://localhost:5000`**

---

## 🔒 Security Architecture & Defensive Controls

### 1. Flask API Authentication & Role-Based Access Control (RBAC)
Every single `/api/*` endpoint strictly enforces cryptographic Bearer token validation via `@require_auth` and `@require_role` decorators:
- **Admin Role:** `Authorization: Bearer sentrix-admin-token-2026-auth` (Permits configuration rotation, test execution, report downloads, simulation).
- **Analyst Role:** `Authorization: Bearer sentrix-analyst-token-2026-auth` (Permits telemetry read, audit inspections, test execution, report downloads; rotation returns `403 Forbidden`).
- **Unauthenticated Requests:** Returns `401 Unauthorized` across all `/api/*` routes.

### 2. Network Boundary Verification (`ipaddress` Module)
Firewall IP evaluations validate input formats strictly using Python's standard `ipaddress.ip_address` library. Subnet containment checks use `ipaddress.ip_network`:
- Approved Internal Subnets: `10.10.4.0/24` (Vendor Connector), `198.51.100.0/24` (Campus Management), `10.10.8.0/24` (Database Cluster), `127.0.0.0/8` (Localhost Loopback).
- Malformed inputs (e.g., `999.999.999.999`, `invalid_ip`) immediately return `400 Bad Request`.
- Inbound requests from `203.0.113.77` are rejected with `DENIED (Off-Subnet External IP)`.

### 3. Server-Side RBAC Enforcement
The `/api/test-role` endpoint enforces server-side role validation matrices rather than trusting client-supplied permissions:
- `attendance.read`: Authorized for `/v1/attendance` ONLY. Denied for `/v1/learners/search` and `/v1/learners/export`.
- `learner.search`: Authorized for `/v1/learners/search`. Denied for `/v1/learners/export`.
- `learner.export`: Authorized for `/v1/learners/export`.

### 4. Explicit CORS Origin Protection
Cross-Origin Resource Sharing is strictly constrained to authorized origins (`http://127.0.0.1:5000`, `http://localhost:5000`) without wildcards (`*`).

### 5. Simulated Vault Credential Rotation
The credential rotation endpoint `/api/rotate-credential` is explicitly labeled and audited as a **SIMULATED DEMONSTRATION** (`status: "SIMULATED_DEMONSTRATION"`, `real_credential_rotated: false`), demonstrating secret rotation workflows safely without claiming direct integration with an unconfigured physical secret vault.

---

## 🔬 Local Safe Simulation (Isolated Security Control Tests)

Test the localized mock API gateway directly with isolated security controls:

```bash
cd "FULL PACK/SAFE_SIMULATION"

# Test 1: Start Hardened Gateway
python mock_api_server.py --mode hardened --port 8765

# Test 2: In a second terminal, execute the official verification harness
python test_hardened_api.py
```
*Results: Validates 7 core assertions:*
1. Authorized attendance permitted from whitelisted IP (`10.10.4.12`) -> HTTP 200
2. Learner search denied to attendance role -> HTTP 403
3. Bulk export denied to attendance role (least-privilege boundary) -> HTTP 403
4. Unapproved external source IP (`203.0.113.77`) blocked -> HTTP 403
5. Invalid/revoked tokens rejected -> HTTP 403
6. **ISOLATED EXPORT LIMIT:** Bulk export > 100 records blocked by record ceiling -> HTTP 400
7. **ISOLATED EXPORT LIMIT:** Small export <= 100 records permitted for authorized role -> HTTP 200

---

## 📊 REST API Endpoints

| Method | Endpoint | Access Level | Description |
|:---:|---|:---:|---|
| `GET` | `/` | Public | Serves the interactive Single-Page Application (SPA) dashboard |
| `GET` | `/api/dashboard` | Bearer (Analyst/Admin)| Telemetry summary, active threat score, and case metrics |
| `GET` | `/api/logs` | Bearer (Analyst/Admin)| Security log stream from authentic E01–E12 records |
| `GET` | `/api/alerts` | Bearer (Analyst/Admin)| Active SIEM real-time alerts with heuristic severity scores |
| `GET` | `/api/timeline` | Bearer (Analyst/Admin)| Incident timeline with MITRE ATT&CK tactics & hypothesis status |
| `GET` | `/api/policies` | Bearer (Analyst/Admin)| Security hardening policies, current gaps, and recommendations |
| `GET` | `/api/evidence` | Bearer (Analyst/Admin)| Evidence catalog with E01–E12 cross-references and risk ratings |
| `GET` | `/api/evidence/integrity`| Bearer (Analyst/Admin)| Dynamic SHA-256 cryptographic hashes and verification status |
| `GET` | `/api/evidence/raw/<eid>`| Bearer (Analyst/Admin)| Secure raw case dossier artifact inspector for E01–E12 |
| `GET` | `/api/credential-audit`| Bearer (Analyst/Admin)| Service and staff account lifecycle compliance audit (~7 mos age) |
| `GET` | `/api/anomaly-detection`| Bearer (Analyst/Admin)| Returns real-time heuristic anomaly detection results |
| `POST` | `/api/test-ip` | Bearer (Analyst/Admin)| Evaluates inbound IP with Python `ipaddress` against firewall rules |
| `POST` | `/api/test-role` | Bearer (Analyst/Admin)| Tests role authorization with server-side RBAC validation |
| `POST` | `/api/simulate` | Bearer (Analyst/Admin)| Simulates multi-stage attack and tests defense controls |
| `POST` | `/api/rotate-credential`| Bearer (Admin Only)| Executes simulated vault credential rotation demonstration |
| `POST` | `/api/run-tests` | Bearer (Analyst/Admin)| Executes 63-point test harness and returns JSON results |
| `GET` | `/api/export-report`| Bearer (Analyst/Admin)| Downloads full forensic case report in JSON format |
| `GET` | `/api/export-report/csv`| Bearer (Analyst/Admin)| Downloads complete forensic findings and timeline as CSV |

---

## 🔍 Case Evidence Cross-Reference (E01–E12)

| Evidence ID | Title | Key Forensic Finding | Correlated Events |
|:---:|---|---|---|
| **E01** | Authentication Logs | External token auth from `203.0.113.77`; former staff persistence | `A011`, `A012`, `A013`, `A006` |
| **E02** | ClassBridge Audit | Mass learner search & export for 2,300 profiles | `P003`, `P004`, `P005`, `P006` |
| **E03** | API Gateway Logs | Client `rollcall-prod` accessed `/v1/learners/export` (HTTP 200) | `R003`, `R004`, `R006` |
| **E04** | CampusVault Logs | 486 KB learner archive downloaded twice to `203.0.113.77` | `C002`, `C003`, `C004` |
| **E05** | Integration Register | `INT-01`: ~7 mos active, excessive scopes, `expires: never`, no IP whitelist | `INT-01` |
| **E06** | HelpDesk Tickets | Config screenshot attachment in `HD-1058` (unverified); surprise export in `HD-1069` | `HD-1058`, `HD-1069` |
| **E07** | Account Register | Context on IT Ops, Finance, and unrevoked former staff | `EMP-001` to `EMP-004`, `SVC-001` |
| **E08** | Security Policy | Violations of `NS-SEC-04` Rules 1 (Vault), 2 (Least Privilege), 3 (Rotation) | Rules 1 through 7 |
| **E09** | Network Observations | Initial external connection `N001` (03:15); normal subnet `N002` (03:25) | `N001`, `N002` |
| **E10** | Vendor Comms | RollCall security confirms no export scheduled; node `10.10.4.12` idle | `VND-221`, `INT-REQ-18` |
| **E11** | Configuration Audit | `credential_config_read` at 03:16:35 immediately preceding API attack | `CHG-882`, `CHG-883`, `CHG-884` |
| **E12** | Incident Note | Separates direct logs from hypotheses; human identity remains unproven | `E12-NOTE` |

---

## 👥 Team & Submission Information

* **Competition:** CRIMEATHON’26 Selection Round (SIMATS Students)
* **Team Name:** SENTRIX
* **Track:** DEFENSE
* **Submission Deliverables:**
  1. `PROBLEM_STATEMENT.md` & `PROBLEM_STATEMENT.html` (Strict 1-Page Problem Statement)
  2. Complete Source Code & Test Suite (GitHub Ready)
  3. `SENTRIX_SHIELD_PRESENTATION.pptx` (10-Slide Presentation Deck)
  4. Video Walkthrough Demonstration Guide

*Licensed under the MIT License.*
