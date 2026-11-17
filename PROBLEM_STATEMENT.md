# SENTRIX SHIELD: Autonomous Security Monitoring & Incident Response Platform
**CRIMEATHON’26 — Selection Round Problem Statement (Case NS-26-014)**  
**Team:** SENTRIX | **Track Selected:** DEFENSE | **Institution:** SIMATS

---

### 1. Problem Identification
On **12 October 2026**, Northstar Skills Academy experienced an unauthorized data exfiltration incident compromising **2,300 active learner profiles** (486 KB CSV). The compromise occurred when a third-party attendance integration credential (`svc_rollcall` / `rc-prod-01`) was abused from an unapproved external IP address (`203.0.113.77`). The root causes encompass: (a) **Credential Hygiene Failure**—the API key had no expiration date, no rotation in over 14 months, and leaked into an IT support ticket screenshot; (b) **Privilege Violation**—the connector held excessive permissions (`learner.search`, `learner.export`) far exceeding its attendance sync role; (c) **Network Enforcement Gap**—the gateway permitted requests from any external network; and (d) **Zero-Day Telemetry Gap**—no alerting or velocity controls flagged off-hours bulk exports.

### 2. Supporting Evidence & Correlated Event IDs
The table below correlates events directly from the official case dossier (**E01–E12**):
| Evidence Source | Key Event / Record IDs | Timestamp (IST) | Observed Technical Finding |
|---|---|---|---|
| **E01: Auth Logs** | `A011`, `A012`, `A013` | 12-Oct 03:16–03:19 | Service identity `svc_rollcall` authenticated from non-whitelisted external IP `203.0.113.77`. |
| **E11: Config Audit** | `CHG-882`, `CHG-883` | 12-Oct 03:16:35, 03:17:30 | Unauthorized read of integration settings (`credential_config_read`), followed by export job creation. |
| **E02: ClassBridge** | `P003`, `P004`, `P006` | 12-Oct 03:16–03:19 | `svc_rollcall` queried 2,300 learners, invoked `learner.export`, and pulled all attendance records. |
| **E03: API Gateway** | `R003`, `R004`, `R006` | 12-Oct 03:16–03:19 | Client `rollcall-prod` (`rc-prod-01`) accessed `/v1/learners/export` from `203.0.113.77` with HTTP 200. |
| **E04: CampusVault** | `C002`, `C003`, `C004` | 12-Oct 03:20–03:24 | Object `learners-20261012.csv` (486,200 bytes) listed and downloaded twice to external IP. |
| **E05: Integration Reg.**| `INT-01` | Created 04-Mar-2026 | Assigned excessive scopes (`learner.export`), `expires: never`, and `ip_restriction: not configured`. |
| **E06: HelpDesk** | `HD-1058`, `HD-1069` | 09-Oct 15:42 / 12-Oct | Ticket HD-1058 archived unredacted config screenshot; HD-1069 logged Finance discovering unexpected export. |
| **E08: Security Policy** | `NS-SEC-04` Rules 1–5 | Effective 01-Apr-2026 | Direct violations of secrets storage (Rule 1), least privilege (Rule 2), rotation (Rule 3), and export approvals (Rule 5). |
| **E09: Network Log** | `N001`, `N002` | 12-Oct 03:15:55, 03:25 | First inbound connection from `203.0.113.77`; normal subnet `10.10.4.12` resumed at 03:25 IST. |
| **E10: Vendor Comms** | `VND-221` | 13-Oct 12:30 | RollCall security confirmed no bulk export was scheduled and connector node `10.10.4.12` was inactive during breach. |

### 3. Confirmed Observations vs. Assumptions & Unknowns
* **Direct Observations (Confirmed):** Credential `rc-prod-01` was used from external IP `203.0.113.77` to read configuration (`CHG-882`), trigger an unauthorized learner export (`R004`), and download 2,300 learner records from CampusVault twice (`C003`, `C004`). The integration lacked IP restriction and expiration (`INT-01`).
* **Strongly Supported Inference:** The credential was compromised via the unredacted screenshot in ticket `HD-1058` or configuration extraction before off-hours API abuse.
* **Assumptions & Unknowns:** The exact human identity behind `203.0.113.77` is unverified. Whether exfiltrated records were distributed onward to darknet or competitors remains unconfirmed.

### 4. Technical & Business Impact
* **Technical:** Bulk exfiltration of 2,300 student Personally Identifiable Information (PII) records (names, contact details, enrollment IDs); degradation of ClassBridge query response times; bypass of perimeter controls.
* **Business & Legal:** Substantial regulatory penalties under Indian Digital Personal Data Protection (DPDP) compliance frameworks; severe institutional reputational erosion among students and guardians; breach of SLA and trust with third-party vendors.

### 5. Proposed Scope & Intended Outcome
* **Scope:** Design and validate **SENTRIX SHIELD**—a defense-in-depth platform targeting the ClassBridge API, CampusVault repository, and RollCall Connect service identities using synthetic datasets and local mock environments.
* **Intended Outcome:** (1) Zero unauthorized API access from unapproved IPs; (2) Automatic enforcement of least-privilege role boundaries (denying `learner.export` to attendance sync identities); (3) Dynamic credential rotation with strict 90-day TTL; (4) Sub-second SIEM detection of off-hours configuration reads and bulk query anomalies.

### 6. Selected Track & Proposed Defense Solution: SENTRIX SHIELD
We selected the **DEFENSE** track to build proactive and reactive controls:
1. **SIEM Correlation & Anomaly Engine:** Ingests authentication, API, and cloud storage logs in real time, scoring risk (0–100) and triggering alerts for anomalous off-subnet access and rate spikes.
2. **Zero-Trust Hardened API Gateway:** Enforces strict source-IP whitelisting (`10.10.4.12`), denies unauthorized scopes (`403 Forbidden` on `/v1/learners/*`), and enforces record-count export ceilings.
3. **Automated Credential Lifecycle Manager:** Replaces unexpiring static tokens with short-lived tokens and one-click automated rotation.
4. **Interactive Incident Response Dashboard:** Real-time web UI visualizing the attack kill-chain, evidence catalog, anomaly breakdown, and security controls verification.
