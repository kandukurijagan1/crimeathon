"""
data/evidence.py — Evidence Dossier Catalog for Sentrix Shield
==============================================================
Directly derived from Official Case Dossier NS-26-014 (E01–E12).
Distinguishes confirmed direct log observations from hypotheses and unknowns.
Risk scores are heuristic severity ratings (0–100), not probabilities of compromise.
"""

EVIDENCE_CATALOG = [
    {
        "id": "E01",
        "file": "E01_Authentication_Logs.csv",
        "title": "Authentication Logs (External Service Identity Usage)",
        "category": "Authentication",
        "severity": "critical",
        "heuristic_score": 95,
        "timestamp": "2026-10-12T03:16:32+05:30",
        "source": "Northstar Identity Service",
        "confirmation_status": "CONFIRMED (Direct Log Observation)",
        "summary": (
            "Service identity 'svc_rollcall' authenticated via token from external IP 203.0.113.77 "
            "(Events A011, A012, A013). Routine daily connector authentications strictly originate from "
            "internal integration node 10.10.4.12 at approximately 02:01 IST (Events A003, A004, A008, A010). "
            "Separately, Event A006 records former support technician former.ajay successfully authenticating on "
            "09-Oct after leaving on 2026-09-30 (violating NS-SEC-04 Rule 7); this indicates an offboarding defect "
            "but does not establish responsibility for the external RollCall incident."
        ),
        "indicators": [
            "Token authentication from unapproved external IP 203.0.113.77 (A011, A012, A013)",
            "Off-hours access window at 03:16–03:19 IST",
            "Separate identity governance issue: former staff account persistence (A006)"
        ],
        "related_events": ["A011", "A012", "A013", "A006", "A007", "A010"],
    },
    {
        "id": "E02",
        "file": "E02_ClassBridge_Audit_Logs.csv",
        "title": "ClassBridge Learner Portal Audit Logs",
        "category": "Portal Audit",
        "severity": "critical",
        "heuristic_score": 98,
        "timestamp": "2026-10-12T03:16:41+05:30",
        "source": "ClassBridge Portal",
        "confirmation_status": "CONFIRMED (Direct Log Observation)",
        "summary": (
            "Service identity 'svc_rollcall' executed an unauthorized learner search for all 2,300 active profiles "
            "(P003), invoked bulk export 'learners/basic-profile' for 2,300 records (P004), read 42 courses (P005), "
            "and pulled 2,300 attendance records (P006) from external IP 203.0.113.77. Normal connector operation "
            "is strictly scoped to 238–241 weekly attendance records (P001, P002, P008, P009)."
        ),
        "indicators": [
            "Mass learner query returning 2,300 records (P003)",
            "Bulk profile export of 2,300 records (P004)",
            "Exceeded operational attendance scope by querying basic profiles and course catalog"
        ],
        "related_events": ["P003", "P004", "P005", "P006"],
    },
    {
        "id": "E03",
        "file": "E03_API_Gateway_Logs.csv",
        "title": "API Gateway Request Logs",
        "category": "API Gateway",
        "severity": "critical",
        "heuristic_score": 96,
        "timestamp": "2026-10-12T03:16:40+05:30",
        "source": "API Gateway",
        "confirmation_status": "CONFIRMED (Direct Log Observation)",
        "summary": (
            "Client identifier 'rollcall-prod' using API key ID 'rc-prod-01' from external host 203.0.113.77 "
            "received HTTP 200 OK responses on GET /v1/learners/search (R003) and POST /v1/learners/export (R004), "
            "returning 2,300 learner records each. Gateway lacked rate limits and source-IP boundary enforcement."
        ),
        "indicators": [
            "Attendance client executing non-attendance export endpoints (R004)",
            "HTTP 200 success on unapproved external IP 203.0.113.77",
            "Lack of gateway request throttling or role scoping"
        ],
        "related_events": ["R003", "R004", "R005", "R006"],
    },
    {
        "id": "E04",
        "file": "E04_CampusVault_Audit_Logs.csv",
        "title": "CampusVault Cloud Repository Logs",
        "category": "Data Exfiltration",
        "severity": "critical",
        "heuristic_score": 100,
        "timestamp": "2026-10-12T03:20:12+05:30",
        "source": "CampusVault Cloud Storage",
        "confirmation_status": "CONFIRMED (Direct Log Observation)",
        "summary": (
            "Principal 'rollcall-prod' listed learner-exports/ folder (C002) and downloaded "
            "'learner-exports/learners-20261012.csv' (486,200 bytes) twice at 03:21:03 (C003) and 03:24:48 (C004) "
            "from external IP 203.0.113.77. Confirms data exfiltration of the generated learner database."
        ),
        "indicators": [
            "Listing of exported learner files in cloud repository (C002)",
            "Two full external downloads of 486,200 bytes file (C003, C004)",
            "No Data Loss Prevention (DLP) or download authorization approval workflow"
        ],
        "related_events": ["C002", "C003", "C004"],
    },
    {
        "id": "E05",
        "file": "E05_Integration_Register.csv",
        "title": "Integration Register (Configuration Analysis)",
        "category": "Configuration Governance",
        "severity": "high",
        "heuristic_score": 88,
        "timestamp": "2026-03-04T00:00:00+05:30",
        "source": "IT Operations Register",
        "confirmation_status": "CONFIRMED (Direct Register Record)",
        "summary": (
            "Integration INT-01 (RollCall Connect) was created on 2026-03-04 (active approximately 7 months at the "
            "time of incident). Record confirms it was assigned excessive permissions ('attendance.read; learner.search; "
            "learner.export; course.read'), had 'expires: never', and 'ip_restriction: not configured'. "
            "Direct violation of NS-SEC-04 Rules 2 (least privilege), 3 (rotation/expiry), and 4 (source network restrictions)."
        ),
        "indicators": [
            "Excessive permission scope ('learner.export' granted to an attendance connector)",
            "No expiration date ('never') and no scheduled rotation in register",
            "No source IP restriction configured ('not configured')"
        ],
        "related_events": ["INT-01"],
    },
    {
        "id": "E06",
        "file": "E06_HelpDesk_Tickets.csv",
        "title": "HelpDesk Support Communications",
        "category": "Investigation Hypothesis",
        "severity": "high",
        "heuristic_score": 80,
        "timestamp": "2026-10-09T15:42:00+05:30",
        "source": "HelpDesk Lite",
        "confirmation_status": "HYPOTHESIS / UNVERIFIED (Investigated Possibility)",
        "summary": (
            "Ticket HD-1058 records IT Analyst Ananya Raman noting that vendor support requested the integration "
            "client identifier and a screenshot of the configuration page, with a screenshot attachment listed in the "
            "ticket archive. IMPORTANT: The screenshot's actual contents are not provided in the evidence, so it is UNKNOWN "
            "whether it exposed secrets. Exposure via this ticket is an investigated hypothesis, NOT a confirmed fact. "
            "Separately, ticket HD-1069 confirms Finance discovered the unexpected learner export on 12-Oct at 09:15 IST."
        ),
        "indicators": [
            "Screenshot attachment recorded in ticket archive during vendor troubleshooting (HD-1058)",
            "Delayed incident discovery initiated by Finance report rather than automated security alert (HD-1069)",
            "Contents of screenshot remain unverified in supplied evidence"
        ],
        "related_events": ["HD-1058", "HD-1069", "HD-1041", "HD-1062"],
    },
    {
        "id": "E07",
        "file": "E07_Staff_and_Service_Account_Register.csv",
        "title": "Staff & Service Account Register",
        "category": "Identity Context",
        "severity": "medium",
        "heuristic_score": 60,
        "timestamp": "2026-10-12T00:00:00+05:30",
        "source": "HR & IT IAM Directory",
        "confirmation_status": "CONFIRMED (Direct Register Record)",
        "summary": (
            "Catalogs roles: Ananya Raman (EMP-001, IT Ops), Rahul Kumar (EMP-002, IT Admin), Meera Shah (EMP-003, Finance), "
            "Ajay Prakash (EMP-004, former support tech, departed 2026-09-30), and SVC-001 (svc_rollcall vendor integration). "
            "Confirms Ajay Prakash had left the organization prior to the incident."
        ),
        "indicators": [
            "Recorded departure date of former staff (2026-09-30)",
            "Role distinctions between IT Operations, Finance, and vendor service identities"
        ],
        "related_events": ["EMP-001", "EMP-002", "EMP-004", "SVC-001"],
    },
    {
        "id": "E08",
        "file": "E08_Information_Security_Policy_Extract.txt",
        "title": "Information Security Standard (NS-SEC-04 v2.1)",
        "category": "Security Governance",
        "severity": "medium",
        "heuristic_score": 70,
        "timestamp": "2026-04-01T00:00:00+05:30",
        "source": "Information Security Office",
        "confirmation_status": "CONFIRMED (Documented Standard)",
        "summary": (
            "Formal security baseline against which observations are measured: (1) Credentials must not be placed in support "
            "tickets/screenshots; (2) Integrations must receive least privilege; (3) Production credentials must have expiry or rotation; "
            "(4) Integrations should be restricted to documented source networks; (5) Bulk exports require approval; (6) Unusual access "
            "must be reviewed; (7) Former staff accounts must be disabled on or before last day."
        ),
        "indicators": [
            "Formal institutional security rules",
            "Clear benchmark establishing operational non-compliance"
        ],
        "related_events": ["NS-SEC-04-R1", "NS-SEC-04-R2", "NS-SEC-04-R3", "NS-SEC-04-R4", "NS-SEC-04-R5", "NS-SEC-04-R7"],
    },
    {
        "id": "E09",
        "file": "E09_Network_Observations.csv",
        "title": "Network Perimeter Observations",
        "category": "Network Telemetry",
        "severity": "critical",
        "heuristic_score": 92,
        "timestamp": "2026-10-12T03:15:55+05:30",
        "source": "Edge Firewall / Flow Logs",
        "confirmation_status": "CONFIRMED (Direct Log Observation)",
        "summary": (
            "Event N001 notes first observed inbound connection from unrecognized external IP 203.0.113.77 using RollCall "
            "client ID. Event N002 confirms the scheduled legitimate connector resumed attendance requests from internal "
            "subnet 10.10.4.12 at 03:25:00 IST, defining a distinct 10-minute external breach window."
        ),
        "indicators": [
            "Clear source network separation: external 203.0.113.77 vs internal 10.10.4.12",
            "Time-bounded 10-minute anomaly window (03:15:55 to 03:25:00 IST)"
        ],
        "related_events": ["N001", "N002"],
    },
    {
        "id": "E10",
        "file": "E10_Vendor_And_Internal_Communications.json",
        "title": "Vendor & Internal Communications",
        "category": "Vendor Telemetry",
        "severity": "medium",
        "heuristic_score": 65,
        "timestamp": "2026-10-13T12:30:00+05:30",
        "source": "Email Archive",
        "confirmation_status": "CONFIRMED (Direct Communication Record)",
        "summary": (
            "Message VND-221 from RollCall Security confirms routine maintenance occurred on 12-Oct, no bulk learner export "
            "was planned, and connector node 10.10.4.12 had no record of production changes during the breach window. "
            "Vendor states credential or configuration exposure is one possibility under review."
        ),
        "indicators": [
            "Vendor refutes scheduling any bulk learner export",
            "Vendor confirms legitimate connector operates from 10.10.4.12",
            "Points to credential exposure rather than internal vendor infrastructure compromise"
        ],
        "related_events": ["VND-221", "INT-REQ-18"],
    },
    {
        "id": "E11",
        "file": "E11_Additional_Configuration_Audit.csv",
        "title": "Configuration Audit & Export Job Logs",
        "category": "Configuration Audit",
        "severity": "critical",
        "heuristic_score": 98,
        "timestamp": "2026-10-12T03:16:35+05:30",
        "source": "Configuration Service Audit",
        "confirmation_status": "CONFIRMED (Direct Audit Observation)",
        "summary": (
            "Event CHG-882 records 'svc_rollcall' from external IP 203.0.113.77 reading integration settings "
            "('credential_config_read') at 03:16:35 IST, immediately preceding API activity. Event CHG-883 records "
            "export job creation at 03:17:30 IST. Log does not show the secret value or the physical person who operated it."
        ),
        "indicators": [
            "Integration settings read from external IP 203.0.113.77 (CHG-882)",
            "Export job created via API (CHG-883)",
            "Direct sequential correlation: Config Read -> API Query -> Export Job -> Download"
        ],
        "related_events": ["CHG-882", "CHG-883", "CHG-884"],
    },
    {
        "id": "E12",
        "file": "E12_Incident_Response_Note.txt",
        "title": "Supplementary Incident Response Note",
        "category": "Incident Response",
        "severity": "high",
        "heuristic_score": 85,
        "timestamp": "2026-10-14T00:00:00+05:30",
        "source": "Incident Response Lead",
        "confirmation_status": "CONFIRMED (Documented IR Status)",
        "summary": (
            "Confirms production integration credential was not scheduled for rotation during October and register shows "
            "no expiry. Affirms that configuration audit log does not show the secret value, the person who obtained it, "
            "or where it may have been copied. Teams must strictly separate confirmed log data from assumptions."
        ),
        "indicators": [
            "Confirmed: no scheduled rotation and no expiry in register",
            "Confirmed: exposure is under review but mechanism remains unproven",
            "Forensic boundary: human operator identity remains unknown"
        ],
        "related_events": ["E12-NOTE"],
    },
]


def get_all_evidence():
    return EVIDENCE_CATALOG


def get_evidence_by_id(eid):
    for item in EVIDENCE_CATALOG:
        if item["id"].lower() == eid.lower() or item.get("file", "").lower() == eid.lower():
            return item
    return None


def get_evidence_summary():
    return {
        "total": len(EVIDENCE_CATALOG),
        "critical": sum(1 for e in EVIDENCE_CATALOG if e["severity"] == "critical"),
        "high": sum(1 for e in EVIDENCE_CATALOG if e["severity"] == "high"),
        "medium": sum(1 for e in EVIDENCE_CATALOG if e["severity"] == "medium"),
    }
