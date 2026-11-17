# SENTRIX SHIELD: Autonomous Security Monitoring & Incident Response Platform
**CRIMEATHON’26 — Selection Round Problem Statement (Case NS-26-014)**  
**Team:** SENTRIX | **Track Selected:** DEFENSE | **Institution:** SIMATS

---

### 1. Problem Identification
On **12 October 2026**, Northstar Skills Academy experienced an unauthorized data exfiltration incident compromising **2,300 active learner profiles** (486 KB CSV). A third-party attendance service identity (`svc_rollcall` / `rc-prod-01`) was abused from an unrecognized external IP address (`203.0.113.77`). Forensic correlation reveals the following core security issues:
* **Credential Hygiene Failure:** Integration `INT-01` had been active for **approximately 7 months** (created 04-Mar-2026) with **no expiration date** (`expires: never`) and **no scheduled rotation** in the register (E05, E12).
* **Least-Privilege Role Violation:** The connector was assigned broad permissions (`learner.search`, `learner.export`, `course.read`), far exceeding its attendance sync role (E05, E08).
* **Network Boundary Absence:** Ingress restrictions were unconfigured (`ip_restriction: not configured`), allowing requests from external IP `203.0.113.77` (E03, E05, E09).
* **Zero-Day Telemetry Gap:** No real-time alerting or velocity controls flagged off-hours bulk exports; incident was discovered hours later by Finance (E06 HD-1069, E12).

### 2. Supporting Evidence & Correlated Event Cross-Reference
The table below correlates confirmed events directly from the official case dossier (**E01–E12**):
| Evidence Source | Key Event / Record IDs | Timestamp (IST) | Observed Technical Finding |
|---|---|---|---|
| **E01: Auth Logs** | `A011`, `A012`, `A013` | 12-Oct 03:16–03:19 | Service identity `svc_rollcall` authenticated from external IP `203.0.113.77`. |
| **E01 & E07: Identity** | `A006`, `EMP-004` | 09-Oct 09:13:44 | Former staff `former.ajay` authenticated post-departure (Rule 7 violation; separate offboarding flaw). |
| **E11: Config Audit** | `CHG-882`, `CHG-883` | 12-Oct 03:16:35, 03:17:30 | Unauthorized read of integration settings (`credential_config_read`), followed by export job creation. |
| **E02 & E03: Gateway** | `P003-P006`, `R003-R006`| 12-Oct 03:16–03:19 | Queried 2,300 learners, invoked `POST /v1/learners/export` (HTTP 200), dumped attendance. |
| **E04: CampusVault** | `C002`, `C003`, `C004` | 12-Oct 03:20–03:24 | Listed and downloaded `learners-20261012.csv` (486,200 bytes) twice to external host. |
| **E05: Integration Reg.**| `INT-01` | Active (04-Mar) | Assigned excessive scopes (`learner.export`), `expires: never`, `ip_restriction: not configured`. |
| **E06: HelpDesk** | `HD-1058`, `HD-1069` | 09-Oct & 12-Oct | Ticket `HD-1058` listed screenshot attachment (contents unverified); `HD-1069` logged Finance discovery. |
| **E08 & E09: Policy/Net** | `NS-SEC-04`, `N001`, `N002`| 12-Oct 03:15–03:25 | Policy Rules 1–5 violated; `N001` logged external connection; `N002` logged normal subnet resumption. |
| **E10: Vendor Comms** | `VND-221` | 13-Oct 12:30 | Vendor confirmed no bulk export planned and internal node `10.10.4.12` was inactive during breach. |

### 3. Confirmed Observations vs. Assumptions & Unknowns
* **Direct Observations (Confirmed):** API key `rc-prod-01` was used from external IP `203.0.113.77` to read configuration (`CHG-882`), trigger bulk export (`R004`), and download 2,300 learner records twice from CampusVault (`C003`, `C004`). Integration `INT-01` had no expiry and no IP restriction.
* **Investigated Hypotheses (Supported):** Credential was obtained externally (exposure during ticket exchange or config harvesting).
* **Forensic Unknowns (Explicitly Not Claimed):** Physical human identity behind `203.0.113.77`; whether the screenshot attachment in `HD-1058` actually revealed plaintext secrets; and whether exfiltrated records were distributed onward.

### 4. Technical & Business Impact
* **Technical:** Bulk exfiltration of 2,300 learner PII records; total bypass of network and role boundaries; lack of forensic alerting.
* **Business & Legal:** Substantial liability under the Digital Personal Data Protection (DPDP) Act; reputational damage; breach of vendor SLA.

### 5. Proposed Scope & Intended Outcome
* **Scope:** Design and validate **SENTRIX SHIELD** across ClassBridge, CampusVault, and RollCall Connect using synthetic records and local mock APIs.
* **Intended Outcome:** (1) Zero unauthorized API access from unapproved IPs; (2) Automatic least-privilege role boundaries (denying `learner.export` to attendance connectors); (3) Dynamic credential rotation with strict 90-day TTL; (4) Sub-second SIEM anomaly alerts with heuristic severity scoring (0–100).

### 6. Selected Track (DEFENSE) & Proposed Technical Solution
1. **SIEM Telemetry & Anomaly Engine:** Ingests authentication, API, and cloud storage logs in real time, scoring heuristic severity (0–100) and triggering alerts for off-subnet requests and query velocity spikes.
2. **Zero-Trust Hardened API Gateway:** Enforces strict IP allowlisting (`10.10.4.12`), restricts connector scopes strictly to `attendance.read` (returning `403 Forbidden` on `/v1/learners/*`), and enforces export record ceilings.
3. **Automated Credential Lifecycle Manager:** Replaces unexpiring keys with short-lived tokens and one-click automated vault rotation.
4. **Interactive Command Center:** Cyber SOC dashboard providing threat scoring, evidence dossiers, visual timeline, attack simulation, and automated compliance test execution.
