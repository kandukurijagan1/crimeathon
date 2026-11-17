"""
data/evidence.py — Evidence Catalog for Sentrix Shield
======================================================
Official Case NS-26-014 Evidence Dossier Cross-Reference
CRIMEATHON'26 — Team SENTRIX (DEFENSE Track)
"""

EVIDENCE_CATALOG = [
    {
        "id": "E01",
        "file": "E01_Authentication_Logs.csv",
        "title": "Authentication Logs (External IP Access)",
        "category": "Authentication",
        "severity": "critical",
        "timestamp": "2026-10-12T03:16:32+05:30",
        "source": "Northstar Identity Service",
        "summary": (
            "Service account 'svc_rollcall' authenticated via token from external IP 203.0.113.77 "
            "(Events A011, A012, A013). Normal daily logins strictly originate from internal subnet 10.10.4.12. "
            "Also reveals former employee account 'former.ajay' active on 2026-10-09 (A006/A007) despite leaving on 2026-09-30."
        ),
        "indicators": [
            "Token authentication from non-whitelisted external IP (203.0.113.77)",
            "Off-hours access at 03:16 IST",
            "Violation of Policy NS-SEC-04 Rule 7 (former staff account persistence)"
        ],
        "related_events": ["A011", "A012", "A013", "A006", "A007"],
        "risk_score": 95,
    },
    {
        "id": "E02",
        "file": "E02_ClassBridge_Audit_Logs.csv",
        "title": "ClassBridge Learner Portal Audit Logs",
        "category": "Portal Audit",
        "severity": "critical",
        "timestamp": "2026-10-12T03:16:41+05:30",
        "source": "ClassBridge Portal",
        "summary": (
            "Service identity 'svc_rollcall' performed an unauthorized query on 2,300 learner records (P003), "
            "triggered a bulk profile export 'learners/basic-profile' (P004), read 42 courses (P005), and read 2,300 "
            "attendance records (P006) from external IP 203.0.113.77. Normal connector operation reads only 240 records (P001, P002)."
        ),
        "indicators": [
            "Bulk search of 2,300 learner records (P003)",
            "Bulk profile export of 2,300 records (P004)",
            "All actions executed from external IP 203.0.113.77"
        ],
        "related_events": ["P003", "P004", "P005", "P006"],
        "risk_score": 98,
    },
    {
        "id": "E03",
        "file": "E03_API_Gateway_Logs.csv",
        "title": "API Gateway Request Logs",
        "category": "API Gateway",
        "severity": "critical",
        "timestamp": "2026-10-12T03:16:40+05:30",
        "source": "API Gateway",
        "summary": (
            "Client 'rollcall-prod' using API key 'rc-prod-01' from 203.0.113.77 executed requests against "
            "/v1/learners/search (R003) and POST /v1/learners/export (R004), both returning HTTP 200 with 2,300 records. "
            "The gateway lacked rate limiting and endpoint-level authorization restrictions."
        ),
        "indicators": [
            "Attendance client invoking learner export endpoints",
            "HTTP 200 response on sensitive bulk export",
            "No rate limit or IP restriction enforced at gateway"
        ],
        "related_events": ["R003", "R004", "R005", "R006"],
        "risk_score": 96,
    },
    {
        "id": "E04",
        "file": "E04_CampusVault_Audit_Logs.csv",
        "title": "CampusVault Cloud Repository Logs",
        "category": "Data Exfiltration",
        "severity": "critical",
        "timestamp": "2026-10-12T03:20:12+05:30",
        "source": "CampusVault Cloud Storage",
        "summary": (
            "Principal 'rollcall-prod' listed learner-exports/ folder (C002) and downloaded 'learners-20261012.csv' "
            "(486,200 bytes) twice at 03:21:03 (C003) and 03:24:48 (C004) from external IP 203.0.113.77. "
            "Confirms full exfiltration of the generated learner database."
        ),
        "indicators": [
            "Object listing in export directory (C002)",
            "Two full downloads of 486 KB learner database file (C003, C004)",
            "Direct external exfiltration with no DLP controls"
        ],
        "related_events": ["C002", "C003", "C004"],
        "risk_score": 100,
    },
    {
        "id": "E05",
        "file": "E05_Integration_Register.csv",
        "title": "Integration Register (Misconfiguration)",
        "category": "Configuration",
        "severity": "high",
        "timestamp": "2026-03-04T00:00:00+05:30",
        "source": "IT Operations Register",
        "summary": (
            "Integration INT-01 (RollCall Connect) configured with excessive permissions: "
            "'attendance.read; learner.search; learner.export; course.read'. Shows 'expires: never' and "
            "'ip_restriction: not configured'. Violates fundamental least-privilege and lifecycle security standards."
        ),
        "indicators": [
            "Excessive permission scope ('learner.export' granted to attendance sync)",
            "No expiration date ('never') and no rotation schedule",
            "No IP restriction configured ('not configured')"
        ],
        "related_events": ["INT-01"],
        "risk_score": 90,
    },
    {
        "id": "E06",
        "file": "E06_HelpDesk_Tickets.csv",
        "title": "HelpDesk Support Communications",
        "category": "Credential Exposure",
        "severity": "high",
        "timestamp": "2026-10-09T15:42:00+05:30",
        "source": "HelpDesk Lite",
        "summary": (
            "Ticket HD-1058 records IT Analyst Ananya Raman attaching an unredacted screenshot of the configuration page "
            "to a support ticket requested by vendor support. Ticket HD-1069 records Finance discovering the unexpected "
            "export file in CampusVault on 12-Oct at 09:15 IST."
        ),
        "indicators": [
            "Credential/secret exposure via ticket screenshot (HD-1058)",
            "Direct violation of NS-SEC-04 Rule 1",
            "Delayed discovery by Finance rather than automated alert (HD-1069)"
        ],
        "related_events": ["HD-1058", "HD-1069", "HD-1041", "HD-1062"],
        "risk_score": 88,
    },
    {
        "id": "E07",
        "file": "E07_Staff_and_Service_Account_Register.csv",
        "title": "Staff & Service Account Register",
        "category": "Identity Governance",
        "severity": "medium",
        "timestamp": "2026-10-12T00:00:00+05:30",
        "source": "HR & IT IAM Directory",
        "summary": (
            "Maps personnel: Ananya Raman (EMP-001, IT Ops), Rahul Kumar (EMP-002, IT Admin), Meera Shah (EMP-003, Finance), "
            "Ajay Prakash (EMP-004, former support tech, departed 2026-09-30), and SVC-001 (svc_rollcall vendor integration)."
        ),
        "indicators": [
            "Former employee Ajay Prakash's account remained active post-departure",
            "Clear role boundaries between IT Ops, Finance, and vendor service accounts"
        ],
        "related_events": ["EMP-001", "EMP-002", "EMP-004", "SVC-001"],
        "risk_score": 65,
    },
    {
        "id": "E08",
        "file": "E08_Information_Security_Policy_Extract.txt",
        "title": "Information Security Standard (NS-SEC-04 v2.1)",
        "category": "Governance & Policy",
        "severity": "medium",
        "timestamp": "2026-04-01T00:00:00+05:30",
        "source": "Information Security Office",
        "summary": (
            "Seven core security rules violated: (1) Credentials must not be placed in support tickets/screenshots; "
            "(2) Integrations must receive least privilege; (3) Production credentials must have expiry/rotation; "
            "(4) Integrations must be restricted to documented source networks; (5) Bulk exports require approval; "
            "(6) Unusual access must be reviewed; (7) Former staff accounts must be disabled on or before last day."
        ),
        "indicators": [
            "Direct benchmark against which all incident failures are evaluated",
            "Clear baseline proving systemic control failure"
        ],
        "related_events": ["NS-SEC-04-R1", "NS-SEC-04-R2", "NS-SEC-04-R3", "NS-SEC-04-R4", "NS-SEC-04-R5"],
        "risk_score": 75,
    },
    {
        "id": "E09",
        "file": "E09_Network_Observations.csv",
        "title": "Network Perimeter Observations",
        "category": "Network Telemetry",
        "severity": "critical",
        "timestamp": "2026-10-12T03:15:55+05:30",
        "source": "Edge Firewall / Flow Logs",
        "summary": (
            "Event N001 notes first observed inbound connection from unrecognized external IP 203.0.113.77 using RollCall "
            "client ID. Event N002 notes normal scheduled connector resumed attendance-only requests from internal subnet 10.10.4.12 at 03:25:00 IST."
        ),
        "indicators": [
            "Distinct source subnet separation between attacker (203.0.113.77) and legit connector (10.10.4.12)",
            "Strict 10-minute breach window (03:15:55 to 03:25:00 IST)"
        ],
        "related_events": ["N001", "N002"],
        "risk_score": 92,
    },
    {
        "id": "E10",
        "file": "E10_Vendor_And_Internal_Communications.json",
        "title": "Vendor & Internal Communications",
        "category": "Vendor Relations",
        "severity": "medium",
        "timestamp": "2026-10-13T12:30:00+05:30",
        "source": "Email Archive",
        "summary": (
            "Message VND-221 from RollCall Security clarifies: routine connector maintenance occurred 12-Oct, no bulk export "
            "was planned, and no production change originated from Northstar node 10.10.4.12. Vendor confirms investigating credential exposure. "
            "Message INT-REQ-18 shows IT Ops urgently seeking credential review."
        ),
        "indicators": [
            "Vendor refutes initiating bulk learner export",
            "Vendor confirms legitimate connector operates from 10.10.4.12",
            "Points towards credential leak rather than vendor infrastructure breach"
        ],
        "related_events": ["VND-221", "INT-REQ-18"],
        "risk_score": 70,
    },
    {
        "id": "E11",
        "file": "E11_Additional_Configuration_Audit.csv",
        "title": "Configuration Audit & Export Job Logs",
        "category": "Configuration Audit",
        "severity": "critical",
        "timestamp": "2026-10-12T03:16:35+05:30",
        "source": "Configuration Service Audit",
        "summary": (
            "Event CHG-882 records 'svc_rollcall' executing 'credential_config_read' on 'integration-settings/rollcall-prod' "
            "from 203.0.113.77 right before API activity. Event CHG-883 records export job created at 03:17:30. "
            "Event CHG-884 records IT Ops reviewing export job after the fact at 03:26:00 IST."
        ),
        "indicators": [
            "Credential configuration read immediately preceding API abuse (CHG-882)",
            "Export job created directly via API (CHG-883)",
            "Confirms sequential kill-chain: Config Read -> API Query -> Export Job -> Download"
        ],
        "related_events": ["CHG-882", "CHG-883", "CHG-884"],
        "risk_score": 98,
    },
    {
        "id": "E12",
        "file": "E12_Incident_Response_Note.txt",
        "title": "Supplementary Incident Response Note",
        "category": "Incident Response",
        "severity": "high",
        "timestamp": "2026-10-14T00:00:00+05:30",
        "source": "Incident Response Lead",
        "summary": (
            "Confirms production integration credential was not scheduled for rotation during October and register shows no expiry. "
            "Vendor review states credential exposure is under review. Emphasizes separating direct log observations from assumptions, "
            "confirming that config read log does not show secret value or the human operator who copied it."
        ),
        "indicators": [
            "Explicit instruction to separate confirmed observations from unknowns",
            "Confirmed no scheduled rotation and no expiration",
            "Acknowledges forensic limit: human operator identity remains unproven"
        ],
        "related_events": ["E12-NOTE"],
        "risk_score": 85,
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
