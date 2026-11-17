"""
data/logs.py — Authentic Incident Telemetry for Sentrix Shield
==============================================================
Directly derived from Official Case Dossier NS-26-014 (E01–E12).
No invented event IDs, IPs, or timestamps.
All timestamps are India Standard Time (+05:30).
"""

# =============================================================================
# E01: Authentication Logs (Northstar Identity Service)
# =============================================================================
AUTH_LOGS = [
    {
        "event_id": "A001",
        "timestamp": "2026-10-05T08:41:00+05:30",
        "user": "ananya.r",
        "ip": "198.51.100.21",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "low",
        "details": "Routine staff login with MFA from internal IT network.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A002",
        "timestamp": "2026-10-05T09:02:00+05:30",
        "user": "rahul.k",
        "ip": "198.51.100.21",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "low",
        "details": "IT Administrator login with MFA from internal IT network.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A003",
        "timestamp": "2026-10-06T02:01:10+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled attendance sync token auth from approved internal subnet 10.10.4.12.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A004",
        "timestamp": "2026-10-07T02:01:14+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled attendance sync token auth from approved internal subnet 10.10.4.12.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A005",
        "timestamp": "2026-10-08T18:47:02+05:30",
        "user": "ananya.r",
        "ip": "198.51.100.21",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "low",
        "details": "Staff login with MFA from internal IT network.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A006",
        "timestamp": "2026-10-09T09:13:44+05:30",
        "user": "former.ajay",
        "ip": "10.10.8.44",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "high",
        "details": "GOVERNANCE ANOMALY: Authentication by former staff member Ajay Prakash post-departure (left 2026-09-30). Violates NS-SEC-04 Rule 7.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A007",
        "timestamp": "2026-10-09T09:19:02+05:30",
        "user": "former.ajay",
        "ip": "10.10.8.44",
        "result": "DENIED",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "medium",
        "details": "Subsequent login attempt denied for former staff account.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A008",
        "timestamp": "2026-10-10T02:01:08+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled attendance sync token auth from internal subnet 10.10.4.12.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A009",
        "timestamp": "2026-10-11T11:22:00+05:30",
        "user": "meera.s",
        "ip": "203.0.113.18",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "low",
        "details": "Finance Analyst remote login with MFA from registered staff device.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A010",
        "timestamp": "2026-10-12T02:01:06+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled connector token authentication from internal node 10.10.4.12.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A011",
        "timestamp": "2026-10-12T03:16:32+05:30",
        "user": "svc_rollcall",
        "ip": "203.0.113.77",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "critical",
        "details": "CRITICAL ANOMALY: Service identity svc_rollcall authenticated from unrecognized external IP 203.0.113.77 using valid token rc-prod-01.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A012",
        "timestamp": "2026-10-12T03:17:04+05:30",
        "user": "svc_rollcall",
        "ip": "203.0.113.77",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "critical",
        "details": "Second token authentication for svc_rollcall from external host 203.0.113.77.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A013",
        "timestamp": "2026-10-12T03:19:48+05:30",
        "user": "svc_rollcall",
        "ip": "203.0.113.77",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "critical",
        "details": "Third token authentication for svc_rollcall from external host 203.0.113.77.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A014",
        "timestamp": "2026-10-12T10:04:10+05:30",
        "user": "ananya.r",
        "ip": "198.51.100.21",
        "result": "SUCCESS",
        "mfa": "MFA",
        "device": "managed-or-registered",
        "category": "authentication",
        "severity": "low",
        "details": "Normal staff login from IT subnet.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A015",
        "timestamp": "2026-10-13T02:01:09+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled connector token auth from internal node 10.10.4.12.",
        "evidence_id": "E01"
    },
    {
        "event_id": "A016",
        "timestamp": "2026-10-14T02:01:12+05:30",
        "user": "svc_rollcall",
        "ip": "10.10.4.12",
        "result": "TOKEN_AUTH",
        "mfa": "N/A",
        "device": "known-service",
        "category": "authentication",
        "severity": "low",
        "details": "Normal scheduled connector token auth from internal node 10.10.4.12.",
        "evidence_id": "E01"
    },
]

# =============================================================================
# E02: ClassBridge Portal Audit Logs
# =============================================================================
PORTAL_LOGS = [
    {
        "event_id": "P001",
        "timestamp": "2026-10-10T02:01:20+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "attendance.read",
        "object": "attendance/weekly",
        "record_count": 240,
        "records": 240,
        "ip": "10.10.4.12",
        "result": "success",
        "category": "portal_audit",
        "severity": "low",
        "details": "Routine weekly attendance sync query via portal connector.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P002",
        "timestamp": "2026-10-11T02:01:18+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "attendance.read",
        "object": "attendance/daily",
        "record_count": 238,
        "records": 238,
        "ip": "10.10.4.12",
        "result": "success",
        "category": "portal_audit",
        "severity": "low",
        "details": "Routine daily attendance sync query via portal connector.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P003",
        "timestamp": "2026-10-12T03:16:41+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "learner.search",
        "object": "learners",
        "record_count": 2300,
        "records": 2300,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "portal_audit",
        "severity": "critical",
        "details": "ANOMALOUS SEARCH: Mass enumeration query searching across all 2,300 learners from external IP 203.0.113.77.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P004",
        "timestamp": "2026-10-12T03:17:10+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "learner.export",
        "object": "learners/basic-profile",
        "record_count": 2300,
        "records": 2300,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "portal_audit",
        "severity": "critical",
        "details": "UNAUTHORIZED EXPORT: 2,300 learner basic-profile records exported by svc_rollcall from external IP 203.0.113.77.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P005",
        "timestamp": "2026-10-12T03:18:52+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "course.read",
        "object": "courses/current",
        "record_count": 42,
        "records": 42,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "portal_audit",
        "severity": "high",
        "details": "Reconnaissance read on current courses (42 records) from external IP 203.0.113.77.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P006",
        "timestamp": "2026-10-12T03:19:22+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "attendance.read",
        "object": "attendance/all",
        "record_count": 2300,
        "records": 2300,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "portal_audit",
        "severity": "critical",
        "details": "Full attendance dump across 2,300 learners from external IP 203.0.113.77.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P007",
        "timestamp": "2026-10-12T03:22:01+05:30",
        "user": "ananya.r",
        "actor": "ananya.r",
        "action": "learner.search",
        "object": "learners/class-12A",
        "record_count": 32,
        "records": 32,
        "ip": "198.51.100.21",
        "result": "success",
        "category": "portal_audit",
        "severity": "low",
        "details": "Authorized staff portal search for Class 12A learners from internal IT subnet.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P008",
        "timestamp": "2026-10-13T02:01:20+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "attendance.read",
        "object": "attendance/weekly",
        "record_count": 241,
        "records": 241,
        "ip": "10.10.4.12",
        "result": "success",
        "category": "portal_audit",
        "severity": "low",
        "details": "Normal attendance sync resumed from internal connector node 10.10.4.12.",
        "evidence_id": "E02"
    },
    {
        "event_id": "P009",
        "timestamp": "2026-10-14T02:01:20+05:30",
        "user": "svc_rollcall",
        "actor": "svc_rollcall",
        "action": "attendance.read",
        "object": "attendance/weekly",
        "record_count": 239,
        "records": 239,
        "ip": "10.10.4.12",
        "result": "success",
        "category": "portal_audit",
        "severity": "low",
        "details": "Normal attendance sync continued from internal connector node 10.10.4.12.",
        "evidence_id": "E02"
    },
]

# =============================================================================
# E03: API Gateway Logs
# =============================================================================
API_ACCESS_LOGS = [
    {
        "event_id": "R001",
        "timestamp": "2026-10-10T02:01:19+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "10.10.4.12",
        "endpoint": "/v1/attendance",
        "method": "GET",
        "status_code": 200,
        "records_returned": 240,
        "category": "api_gateway",
        "severity": "low",
        "details": "Normal scheduled attendance sync query (240 records returned).",
        "evidence_id": "E03"
    },
    {
        "event_id": "R002",
        "timestamp": "2026-10-11T02:01:17+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "10.10.4.12",
        "endpoint": "/v1/attendance",
        "method": "GET",
        "status_code": 200,
        "records_returned": 238,
        "category": "api_gateway",
        "severity": "low",
        "details": "Normal scheduled daily attendance sync query (238 records returned).",
        "evidence_id": "E03"
    },
    {
        "event_id": "R003",
        "timestamp": "2026-10-12T03:16:40+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "203.0.113.77",
        "endpoint": "/v1/learners/search",
        "method": "GET",
        "status_code": 200,
        "records_returned": 2300,
        "category": "api_gateway",
        "severity": "critical",
        "details": "ANOMALOUS BULK QUERY: Attendance client rollcall-prod executed search on learners, returning 2,300 active profiles from external IP 203.0.113.77.",
        "evidence_id": "E03"
    },
    {
        "event_id": "R004",
        "timestamp": "2026-10-12T03:17:09+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "203.0.113.77",
        "endpoint": "/v1/learners/export",
        "method": "POST",
        "status_code": 200,
        "records_returned": 2300,
        "category": "api_gateway",
        "severity": "critical",
        "details": "UNAUTHORIZED BULK EXPORT: Client invoked POST /v1/learners/export, triggering bulk profile export job for 2,300 records from external IP 203.0.113.77.",
        "evidence_id": "E03"
    },
    {
        "event_id": "R005",
        "timestamp": "2026-10-12T03:18:50+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "203.0.113.77",
        "endpoint": "/v1/courses",
        "method": "GET",
        "status_code": 200,
        "records_returned": 42,
        "category": "api_gateway",
        "severity": "high",
        "details": "Reconnaissance query on current courses (42 records) from external IP 203.0.113.77.",
        "evidence_id": "E03"
    },
    {
        "event_id": "R006",
        "timestamp": "2026-10-12T03:19:20+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "203.0.113.77",
        "endpoint": "/v1/attendance/all",
        "method": "GET",
        "status_code": 200,
        "records_returned": 2300,
        "category": "api_gateway",
        "severity": "critical",
        "details": "Full historical attendance dump (2,300 records) from external IP 203.0.113.77.",
        "evidence_id": "E03"
    },
    {
        "event_id": "R007",
        "timestamp": "2026-10-12T03:22:00+05:30",
        "user": "ananya.r",
        "client_id": "staff-portal",
        "api_key_id": "staff-web",
        "ip": "198.51.100.21",
        "endpoint": "/v1/learners/search",
        "method": "GET",
        "status_code": 200,
        "records_returned": 32,
        "category": "api_gateway",
        "severity": "low",
        "details": "Routine staff portal search for Class 12A learners (32 records) from internal IT subnet.",
        "evidence_id": "E03"
    },
    {
        "event_id": "R008",
        "timestamp": "2026-10-13T02:01:19+05:30",
        "user": "svc_rollcall",
        "client_id": "rollcall-prod",
        "api_key_id": "rc-prod-01",
        "ip": "10.10.4.12",
        "endpoint": "/v1/attendance",
        "method": "GET",
        "status_code": 200,
        "records_returned": 241,
        "category": "api_gateway",
        "severity": "low",
        "details": "Routine scheduled connector attendance sync (241 records) from internal node 10.10.4.12.",
        "evidence_id": "E03"
    },
]

# =============================================================================
# E11: Configuration Audit & Export Job Creation Logs
# =============================================================================
CONFIG_ACCESS_LOGS = [
    {
        "event_id": "CHG-882",
        "timestamp": "2026-10-12T03:16:35+05:30",
        "user": "svc_rollcall",
        "action": "credential_config_read",
        "resource": "integration-settings/rollcall-prod",
        "ip": "203.0.113.77",
        "result": "success",
        "category": "config_access",
        "severity": "critical",
        "details": "CRITICAL AUDIT EVENT: Integration configuration read by svc_rollcall from external host 203.0.113.77 shortly before API burst.",
        "evidence_id": "E11"
    },
    {
        "event_id": "CHG-883",
        "timestamp": "2026-10-12T03:17:30+05:30",
        "user": "svc_rollcall",
        "action": "export_job_created",
        "resource": "learner-exports/learners-20261012.csv",
        "ip": "203.0.113.77",
        "result": "success",
        "category": "config_access",
        "severity": "critical",
        "details": "Export job created via API invocation R004 from external IP 203.0.113.77.",
        "evidence_id": "E11"
    },
    {
        "event_id": "CHG-884",
        "timestamp": "2026-10-12T03:26:00+05:30",
        "user": "it.ops",
        "action": "export_job_reviewed",
        "resource": "learner-exports/learners-20261012.csv",
        "ip": "198.51.100.21",
        "result": "success",
        "category": "config_access",
        "severity": "medium",
        "details": "Post-incident audit review of created export job by IT Operations.",
        "evidence_id": "E11"
    },
]

# =============================================================================
# E04: CampusVault Cloud Repository Audit Logs
# =============================================================================
DATA_EXPORT_LOGS = [
    {
        "event_id": "C001",
        "timestamp": "2026-10-01T09:00:00+05:30",
        "user": "finance.report",
        "principal": "finance.report",
        "action": "object.download",
        "resource": "CampusVault",
        "file": "monthly/attendance-summary-oct.csv",
        "bytes": 18240,
        "record_count": 240,
        "ip": "198.51.100.31",
        "result": "success",
        "category": "data_export",
        "severity": "low",
        "details": "Authorized monthly finance report download from internal finance subnet.",
        "evidence_id": "E04"
    },
    {
        "event_id": "C002",
        "timestamp": "2026-10-12T03:20:12+05:30",
        "user": "rollcall-prod",
        "principal": "rollcall-prod",
        "action": "object.list",
        "resource": "CampusVault",
        "file": "learner-exports/",
        "bytes": 0,
        "record_count": 0,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "data_export",
        "severity": "critical",
        "details": "UNAUTHORIZED ENUMERATION: Client rollcall-prod listed learner-exports folder from external host 203.0.113.77.",
        "evidence_id": "E04"
    },
    {
        "event_id": "C003",
        "timestamp": "2026-10-12T03:21:03+05:30",
        "user": "rollcall-prod",
        "principal": "rollcall-prod",
        "action": "object.download",
        "resource": "CampusVault",
        "file": "learner-exports/learners-20261012.csv",
        "bytes": 486200,
        "record_count": 2300,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "data_export",
        "severity": "critical",
        "details": "DATA EXFILTRATION (1/2): Client downloaded 486,200 bytes containing 2,300 learner basic profiles to external host 203.0.113.77.",
        "evidence_id": "E04"
    },
    {
        "event_id": "C004",
        "timestamp": "2026-10-12T03:24:48+05:30",
        "user": "rollcall-prod",
        "principal": "rollcall-prod",
        "action": "object.download",
        "resource": "CampusVault",
        "file": "learner-exports/learners-20261012.csv",
        "bytes": 486200,
        "record_count": 2300,
        "ip": "203.0.113.77",
        "result": "success",
        "category": "data_export",
        "severity": "critical",
        "details": "DATA EXFILTRATION (2/2): Second redundant download of 486,200 bytes from external host 203.0.113.77.",
        "evidence_id": "E04"
    },
    {
        "event_id": "C005",
        "timestamp": "2026-10-12T10:10:02+05:30",
        "user": "finance.report",
        "principal": "finance.report",
        "action": "object.download",
        "resource": "CampusVault",
        "file": "monthly/attendance-summary-oct.csv",
        "bytes": 18240,
        "record_count": 240,
        "ip": "198.51.100.31",
        "result": "success",
        "category": "data_export",
        "severity": "low",
        "details": "Routine authorized finance download from approved subnet.",
        "evidence_id": "E04"
    },
]

# =============================================================================
# E09: Network Observations (Perimeter Edge)
# =============================================================================
NETWORK_LOGS = [
    {
        "event_id": "N001",
        "timestamp": "2026-10-12T03:15:55+05:30",
        "src_ip": "203.0.113.77",
        "dst_ip": "10.10.2.5",
        "port": 443,
        "protocol": "TCP/TLS",
        "action": "ALLOW",
        "category": "network",
        "severity": "critical",
        "details": "PERIMETER INGRESS: First observed inbound connection using RollCall production client identifier from unrecognized external source 203.0.113.77.",
        "evidence_id": "E09"
    },
    {
        "event_id": "N002",
        "timestamp": "2026-10-12T03:25:00+05:30",
        "src_ip": "10.10.4.12",
        "dst_ip": "10.10.2.5",
        "port": 443,
        "protocol": "TCP/TLS",
        "action": "ALLOW",
        "category": "network",
        "severity": "low",
        "details": "NORMAL CONNECTOR RESUMPTION: Scheduled connector resumed normal attendance-only requests from internal subnet 10.10.4.12.",
        "evidence_id": "E09"
    },
]

# =============================================================================
# E06: HelpDesk Support Communications
# =============================================================================
HELPDESK_LOGS = [
    {
        "event_id": "HD-1041",
        "timestamp": "2026-10-07T11:20:00+05:30",
        "requester": "vendor.support@rollcall.example",
        "subject": "Attendance sync delay",
        "status": "closed",
        "category": "helpdesk",
        "severity": "low",
        "details": "Vendor asked to confirm sync window to review connector logs.",
        "evidence_id": "E06"
    },
    {
        "event_id": "HD-1058",
        "timestamp": "2026-10-09T15:42:00+05:30",
        "requester": "ananya.r",
        "subject": "RollCall API troubleshooting",
        "status": "closed",
        "category": "helpdesk",
        "severity": "high",
        "details": "INVESTIGATED HYPOTHESIS: Vendor requested integration client identifier and a screenshot of configuration page. Screenshot attachment recorded in ticket archive; contents unverified.",
        "evidence_id": "E06"
    },
    {
        "event_id": "HD-1062",
        "timestamp": "2026-10-11T16:08:00+05:30",
        "requester": "vendor.support@rollcall.example",
        "subject": "Planned connector maintenance",
        "status": "closed",
        "category": "helpdesk",
        "severity": "low",
        "details": "Vendor advised routine connector maintenance on 12-Oct. Explicitly confirmed: 'No bulk learner export is planned. Source IP ranges are unchanged.'",
        "evidence_id": "E06"
    },
    {
        "event_id": "HD-1069",
        "timestamp": "2026-10-12T09:15:00+05:30",
        "requester": "finance.team",
        "subject": "Unexpected learner export",
        "status": "open",
        "category": "helpdesk",
        "severity": "critical",
        "details": "INCIDENT DISCOVERY: Finance team noticed unexpected learner export in CampusVault, prompting internal review.",
        "evidence_id": "E06"
    },
]


def get_all_logs():
    """Return all genuine event records sorted chronologically."""
    combined = (
        AUTH_LOGS
        + PORTAL_LOGS
        + API_ACCESS_LOGS
        + CONFIG_ACCESS_LOGS
        + DATA_EXPORT_LOGS
        + NETWORK_LOGS
        + HELPDESK_LOGS
    )
    return sorted(combined, key=lambda x: x.get("timestamp", ""))


def get_logs_by_category():
    """Group genuine logs by category."""
    cats = {}
    for log in get_all_logs():
        c = log.get("category", "other")
        cats.setdefault(c, []).append(log)
    return cats
