# 🛡️ SENTRIX SHIELD: Autonomous Security Monitoring & Incident Response Platform

[![CRIMEATHON'26](https://img.shields.io/badge/CRIMEATHON'26-Selection%20Round-blue.svg)](https://github.com)
[![Track](https://img.shields.io/badge/Track-DEFENSE-success.svg)](https://github.com)
[![Team](https://img.shields.io/badge/Team-SENTRIX-green.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg)](https://flask.palletsprojects.com)
[![Tests](https://img.shields.io/badge/Tests-33%2F33%20Passing-brightgreen.svg)](run_tests.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **CRIMEATHON’26 — Case NS-26-014: The Northstar Learning Services Investigation**  
> **Team:** SENTRIX (SIMATS Cyber Club) | **Selected Track:** DEFENSE  
> *All data is strictly synthetic and simulated for authorized cybersecurity investigation training.*

---

## 📑 Executive Summary

On **12 October 2026**, Northstar Skills Academy experienced a critical security incident resulting in the unauthorized export of **2,300 active learner profiles** (486 KB). Forensic correlation of authentication, API, cloud repository, and configuration logs revealed that a third-party attendance integration credential (`svc_rollcall` / `rc-prod-01`) was abused from an unrecognized external IP (`203.0.113.77`).

**Root Vulnerabilities Identified:**
1. **Zero Credential Hygiene:** The API key had no expiry date (`expires: never`) and had not been rotated in over 14 months (`INT-01`, `E05`).
2. **Excessive Privileges:** The attendance connector held `learner.search` and `learner.export` permissions, violating least-privilege standards (`NS-SEC-04`, `E08`).
3. **Unrestricted Network Ingress:** The API Gateway lacked source IP allowlisting, permitting connections from external host `203.0.113.77` (`E03`, `E09`).
4. **Secret Spillage:** IT Analyst attached an unredacted screenshot of integration settings to ticket `HD-1058` (`E06`).
5. **Absent Telemetry & Rate Limiting:** No real-time anomaly alerts or export approval workflows existed (`E11`, `E12`).

---

## 🚀 The Defense Solution: SENTRIX SHIELD

**SENTRIX SHIELD** is a four-pillar, defense-in-depth platform engineered to detect, prevent, and remediate multi-stage credential abuse and data exfiltration attacks:

```
+-------------------------------------------------------------------------+
|                           SENTRIX SHIELD                                |
+--------------------+--------------------+-------------------------------+
|  1. SIEM TELEMETRY | 2. ZERO-TRUST GATE | 3. VAULT LIFECYCLE | 4. UI    |
|  Real-time Ingest  | IP Allowlisting    | 90-Day Auto Rotate | Live UI  |
|  Heuristic Anomaly | Role Scoping (403) | 1-Click Revocation | Timeline |
|  Risk Score (0-100)| Export Ceilings    | Short-Lived Tokens | Playbook |
+--------------------+--------------------+--------------------+----------+
```

1. **Real-Time SIEM Ingestion & Anomaly Correlation:** Analyzes logs across Identity, ClassBridge, CampusVault, and API Gateways. Computes composite risk scores (0–100) and detects off-subnet access, query velocity spikes, and off-hours config reads.
2. **Zero-Trust Hardened API Gateway:** Enforces strict IP allowlisting (`10.10.4.12`), restricts connector scopes strictly to `attendance.read`, and rejects unauthorized queries (`403 Forbidden`).
3. **Automated Credential Lifecycle Manager:** Eliminates unexpiring keys, enforces mandatory 90-day rotation, and provides one-click token revocation and re-issuance.
4. **Interactive Cyber Command Dashboard:** Cyberpunk-themed web dashboard featuring live threat scoring, real-time log streaming, interactive timeline reconstruction, evidence dossiers, attack simulation, and verification controls.

---

## 📂 Project Repository Structure

```
crimathon/
├── app.py                           # Main Flask REST API & Web Server
├── requirements.txt                 # Dependencies (Flask, Flask-CORS, python-pptx)
├── run_tests.py                     # Automated Verification Test Suite (33/33 Tests)
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
│   ├── logs.py                      # Synthetic Security & Audit Event Telemetry
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
Run the 33-point automated security verification suite:
```bash
python run_tests.py
```
*Expected Output: `33 PASSED, 0 FAILED (100% Success Rate)`*

### 3. Launch the SENTRIX SHIELD Web Platform
Start the Flask application:
```bash
python app.py
```
Open your browser and navigate to: **`http://localhost:5000`**

---

## 🔬 Local Safe Simulation (Hardened vs. Vulnerable Mode)

Test the localized mock API gateway directly:

```bash
cd "FULL PACK/SAFE_SIMULATION"

# Test 1: Start Hardened Gateway
python mock_api_server.py --mode hardened --port 8765

# Test 2: In a second terminal, execute the official verification harness
python test_hardened_api.py
```
*Results: Validates 5 core assertions: authorized attendance permitted (200), learner search denied (403), bulk export denied (403), external IP blocked (403), and invalid tokens rejected (403).*

---

## 📊 REST API Endpoints

| Method | Endpoint | Description |
|:---:|---|---|
| `GET` | `/` | Serves the interactive Single-Page Application (SPA) dashboard |
| `GET` | `/api/dashboard` | Dashboard telemetry summary, active threat level, and record metrics |
| `GET` | `/api/logs` | Security log stream (filterable by `category` and `severity`) |
| `GET` | `/api/alerts` | Active SIEM real-time alerts derived from anomaly engine |
| `GET` | `/api/timeline` | Incident timeline with MITRE ATT&CK tactics |
| `GET` | `/api/policies` | Security hardening policies, current gaps, and recommendations |
| `GET` | `/api/evidence` | Evidence catalog with E01–E12 cross-references and risk ratings |
| `GET` | `/api/credential-audit`| Service and staff account lifecycle compliance audit |
| `POST` | `/api/simulate` | Simulates multi-stage attack kill-chain and tests defense controls |
| `POST` | `/api/rotate-credential`| Executes one-click automated credential rotation |
| `GET` | `/api/anomaly-detection`| Returns real-time heuristic anomaly detection results |

---

## 🔍 Case Evidence Cross-Reference (E01–E12)

| Evidence ID | Title | Key Forensic Finding | Correlated Events |
|:---:|---|---|---|
| **E01** | Authentication Logs | External token auth from `203.0.113.77`; former staff persistence | `A011`, `A012`, `A013`, `A006` |
| **E02** | ClassBridge Audit | Mass learner search & export for 2,300 profiles | `P003`, `P004`, `P005`, `P006` |
| **E03** | API Gateway Logs | Client `rollcall-prod` accessed `/v1/learners/export` (HTTP 200) | `R003`, `R004`, `R006` |
| **E04** | CampusVault Logs | 486 KB learner archive downloaded twice to `203.0.113.77` | `C002`, `C003`, `C004` |
| **E05** | Integration Register | `INT-01`: excessive permissions, `expires: never`, no IP whitelist | `INT-01` |
| **E06** | HelpDesk Tickets | Config screenshot attached in `HD-1058`; surprise export in `HD-1069` | `HD-1058`, `HD-1069` |
| **E07** | Account Register | Context on IT Ops, Finance, and unrevoked former staff | `EMP-001` to `EMP-004`, `SVC-001` |
| **E08** | Security Policy | Violations of `NS-SEC-04` Rules 1 (Vault), 2 (Least Privilege), 3 (Rotation) | Rules 1 through 7 |
| **E09** | Network Observations | Initial external connection `N001` (03:15); normal subnet `N002` (03:25) | `N001`, `N002` |
| **E10** | Vendor Comms | RollCall security confirms no export scheduled; node `10.10.4.12` idle | `VND-221`, `INT-REQ-18` |
| **E11** | Configuration Audit | `credential_config_read` at 03:16:35 immediately preceding API attack | `CHG-882`, `CHG-883`, `CHG-884` |
| **E12** | Incident Note | Separates direct logs from assumptions; human identity remains unproven | `E12-NOTE` |

---

## 🎬 Demo Video Walkthrough Guide (2-Minute Script)

When recording your demonstration video:
1. **0:00 - 0:25 (Executive Overview & Incident Context):** Show the header and **Dashboard Tab**. Explain Northstar Skills Academy incident, threat level (CRITICAL, Score: 98), and 2,300 records exposed.
2. **0:25 - 0:50 (Evidence & Chronology):** Click the **Evidence Tab** to showcase E01–E12 cards and filter by Critical. Navigate to the **Timeline Tab** to show the 10-phase kill chain from screenshot leakage to exfiltration.
3. **0:50 - 1:20 (Anomaly Detection & Defense Controls):** Open the **Analysis Tab** to highlight the rule triggers. Move to the **Defense Tab** and demonstrate the **Credential Rotation Simulator** by clicking "Rotate Credential" to show instant token renewal.
4. **1:20 - 1:45 (Live Attack Simulation):** Open the **Simulate Tab** and click "Start Attack Simulation". Show the 5-step attack sequence and demonstrate how SENTRIX SHIELD's hardened gateway blocks unauthorized export attempts.
5. **1:45 - 2:00 (Automated Test Verification):** Switch to terminal and run `python run_tests.py` to show all 33 verification tests passing with 100% success rate. Conclude with Team SENTRIX motto: *"Think. Investigate. Innovate."*

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
