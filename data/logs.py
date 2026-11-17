"""
data/logs.py — Synthetic Security Log Data for Sentrix Shield
=============================================================
All data is SYNTHETIC / SIMULATED for the CRIMEATHON'26 hackathon.
Based on the Northstar Skills Academy security-incident case study.
Timestamps centre on 12 October 2026 IST (UTC+5:30).
"""

# ---------------------------------------------------------------------------
# Auth Logs
# ---------------------------------------------------------------------------
AUTH_LOGS = [
    {
        "event_id": "EVT-001",
        "evidence_id": None,
        "timestamp": "2026-10-12T00:05:12+05:30",
        "source": "IAM-Gateway",
        "user": "admin@northstar.edu.in",
        "action": "LOGIN_SUCCESS",
        "ip": "10.0.1.15",
        "mfa": True,
        "details": "Routine admin login from campus network",
        "severity": "info",
    },
    {
        "event_id": "EVT-002",
        "evidence_id": None,
        "timestamp": "2026-10-12T00:32:44+05:30",
        "source": "IAM-Gateway",
        "user": "registrar@northstar.edu.in",
        "action": "LOGIN_SUCCESS",
        "ip": "10.0.1.22",
        "mfa": True,
        "details": "Registrar login — normal hours",
        "severity": "info",
    },
    {
        "event_id": "EVT-003",
        "evidence_id": "EV-001",
        "timestamp": "2026-10-12T01:47:33+05:30",
        "source": "IAM-Gateway",
        "user": "svc-rollcall",
        "action": "LOGIN_SUCCESS",
        "ip": "203.92.45.112",
        "mfa": False,
        "details": "Service account authenticated from UNUSUAL external IP — no MFA",
        "severity": "critical",
    },
    {
        "event_id": "EVT-004",
        "evidence_id": "EV-006",
        "timestamp": "2026-10-12T01:47:33+05:30",
        "source": "IAM-Gateway",
        "user": "svc-rollcall",
        "action": "MFA_BYPASS",
        "ip": "203.92.45.112",
        "mfa": False,
        "details": "No MFA enforced on service accounts — policy gap",
        "severity": "high",
    },
    {
        "event_id": "EVT-005",
        "evidence_id": None,
        "timestamp": "2026-10-12T06:15:00+05:30",
        "source": "IAM-Gateway",
        "user": "faculty01@northstar.edu.in",
        "action": "LOGIN_SUCCESS",
        "ip": "10.0.2.40",
        "mfa": True,
        "details": "Faculty login — normal morning hours",
        "severity": "info",
    },
    {
        "event_id": "EVT-006",
        "evidence_id": None,
        "timestamp": "2026-10-12T07:00:12+05:30",
        "source": "IAM-Gateway",
        "user": "admin@northstar.edu.in",
        "action": "LOGIN_SUCCESS",
        "ip": "10.0.1.15",
        "mfa": True,
        "details": "Admin morning session",
        "severity": "info",
    },
    {
        "event_id": "EVT-007",
        "evidence_id": None,
        "timestamp": "2026-10-12T09:12:34+05:30",
        "source": "IAM-Gateway",
        "user": "svc-rollcall",
        "action": "LOGIN_SUCCESS",
        "ip": "10.0.5.10",
        "mfa": False,
        "details": "Service account routine sync from internal cron server",
        "severity": "info",
    },
    {
        "event_id": "EVT-008",
        "evidence_id": None,
        "timestamp": "2026-10-12T18:45:00+05:30",
        "source": "IAM-Gateway",
        "user": "registrar@northstar.edu.in",
        "action": "LOGOUT",
        "ip": "10.0.1.22",
        "mfa": None,
        "details": "Registrar end-of-day logout",
        "severity": "info",
    },
]

# ---------------------------------------------------------------------------
# API Access Logs (RollCall Connect)
# ---------------------------------------------------------------------------
API_ACCESS_LOGS = [
    {
        "event_id": "EVT-009",
        "evidence_id": None,
        "timestamp": "2026-10-12T01:48:05+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/attendance/sync",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "203.92.45.112",
        "status_code": 200,
        "details": "First attendance sync call from suspicious IP",
        "severity": "medium",
    },
    {
        "event_id": "EVT-010",
        "evidence_id": "EV-003",
        "timestamp": "2026-10-12T01:48:22+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/attendance/sync",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "203.92.45.112",
        "status_code": 200,
        "details": "Bulk attendance sync — 312 calls in ~10 min window (rate anomaly)",
        "severity": "critical",
    },
    {
        "event_id": "EVT-011",
        "evidence_id": None,
        "timestamp": "2026-10-12T01:49:01+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/learners/list",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "203.92.45.112",
        "status_code": 200,
        "details": "Learner enumeration call",
        "severity": "high",
    },
    {
        "event_id": "EVT-012",
        "evidence_id": None,
        "timestamp": "2026-10-12T01:51:30+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/learners/export",
        "method": "POST",
        "user": "svc-rollcall",
        "ip": "203.92.45.112",
        "status_code": 200,
        "details": "Learner data export request initiated",
        "severity": "critical",
    },
    {
        "event_id": "EVT-013",
        "evidence_id": None,
        "timestamp": "2026-10-12T01:55:14+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/attendance/sync",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "203.92.45.112",
        "status_code": 200,
        "details": "Continued bulk sync calls — 300+ total",
        "severity": "critical",
    },
    {
        "event_id": "EVT-014",
        "evidence_id": None,
        "timestamp": "2026-10-12T09:15:00+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/attendance/sync",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "10.0.5.10",
        "status_code": 200,
        "details": "Normal scheduled sync from internal cron",
        "severity": "info",
    },
    {
        "event_id": "EVT-015",
        "evidence_id": None,
        "timestamp": "2026-10-12T09:30:00+05:30",
        "source": "RollCall-API-GW",
        "endpoint": "/api/v2/attendance/sync",
        "method": "GET",
        "user": "svc-rollcall",
        "ip": "10.0.5.10",
        "status_code": 200,
        "details": "Scheduled sync — normal",
        "severity": "info",
    },
]

# ---------------------------------------------------------------------------
# Config Access Logs
# ---------------------------------------------------------------------------
CONFIG_ACCESS_LOGS = [
    {
        "event_id": "EVT-016",
        "evidence_id": "EV-002",
        "timestamp": "2026-10-12T02:14:00+05:30",
        "source": "Config-Service",
        "user": "svc-rollcall",
        "action": "READ_CONFIG",
        "resource": "integration-settings/rollcall-connect",
        "ip": "203.92.45.112",
        "details": "Integration settings (API keys, secrets) read at 02:14 IST — BEFORE suspicious API burst",
        "severity": "critical",
    },
    {
        "event_id": "EVT-017",
        "evidence_id": None,
        "timestamp": "2026-10-12T02:14:18+05:30",
        "source": "Config-Service",
        "user": "svc-rollcall",
        "action": "READ_CONFIG",
        "resource": "integration-settings/campusvault",
        "ip": "203.92.45.112",
        "details": "CampusVault integration config accessed — credentials exposed",
        "severity": "critical",
    },
    {
        "event_id": "EVT-018",
        "evidence_id": None,
        "timestamp": "2026-10-12T02:15:02+05:30",
        "source": "Config-Service",
        "user": "svc-rollcall",
        "action": "READ_CONFIG",
        "resource": "integration-settings/smtp-relay",
        "ip": "203.92.45.112",
        "details": "SMTP relay config read — potential lateral movement prep",
        "severity": "high",
    },
    {
        "event_id": "EVT-019",
        "evidence_id": None,
        "timestamp": "2026-10-12T08:00:00+05:30",
        "source": "Config-Service",
        "user": "admin@northstar.edu.in",
        "action": "READ_CONFIG",
        "resource": "general-settings",
        "ip": "10.0.1.15",
        "details": "Admin routine config check — normal",
        "severity": "info",
    },
]

# ---------------------------------------------------------------------------
# Data Export Logs (CampusVault)
# ---------------------------------------------------------------------------
DATA_EXPORT_LOGS = [
    {
        "event_id": "EVT-020",
        "evidence_id": "EV-004",
        "timestamp": "2026-10-12T02:22:47+05:30",
        "source": "CampusVault",
        "user": "svc-rollcall",
        "action": "BULK_EXPORT",
        "resource": "learner-data",
        "record_count": 2300,
        "ip": "203.92.45.112",
        "file": "export_learner_full_20261012.csv",
        "details": "Unauthorized bulk learner-data export — 2300 records to external endpoint",
        "severity": "critical",
    },
    {
        "event_id": "EVT-021",
        "evidence_id": None,
        "timestamp": "2026-10-12T02:24:10+05:30",
        "source": "CampusVault",
        "user": "svc-rollcall",
        "action": "BULK_EXPORT",
        "resource": "enrollment-data",
        "record_count": 1850,
        "ip": "203.92.45.112",
        "file": "export_enrollment_20261012.csv",
        "details": "Second bulk export — enrollment records",
        "severity": "critical",
    },
    {
        "event_id": "EVT-022",
        "evidence_id": None,
        "timestamp": "2026-10-12T02:26:35+05:30",
        "source": "CampusVault",
        "user": "svc-rollcall",
        "action": "DOWNLOAD",
        "resource": "export_learner_full_20261012.csv",
        "record_count": 2300,
        "ip": "203.92.45.112",
        "file": None,
        "details": "Export file downloaded to external IP",
        "severity": "critical",
    },
    {
        "event_id": "EVT-023",
        "evidence_id": None,
        "timestamp": "2026-10-12T10:00:00+05:30",
        "source": "CampusVault",
        "user": "registrar@northstar.edu.in",
        "action": "VIEW",
        "resource": "learner-data",
        "record_count": 25,
        "ip": "10.0.1.22",
        "file": None,
        "details": "Registrar viewed learner records — routine",
        "severity": "info",
    },
]

# ---------------------------------------------------------------------------
# Network / Firewall Logs
# ---------------------------------------------------------------------------
NETWORK_LOGS = [
    {
        "event_id": "EVT-024",
        "evidence_id": "EV-008",
        "timestamp": "2026-10-12T01:46:58+05:30",
        "source": "Firewall",
        "action": "ALLOW",
        "src_ip": "203.92.45.112",
        "dst_ip": "10.0.5.10",
        "port": 443,
        "protocol": "HTTPS",
        "details": "Inbound connection from non-whitelisted IP allowed — firewall rule too permissive",
        "severity": "high",
    },
    {
        "event_id": "EVT-025",
        "evidence_id": None,
        "timestamp": "2026-10-12T02:27:00+05:30",
        "source": "Firewall",
        "action": "ALLOW",
        "src_ip": "203.92.45.112",
        "dst_ip": "10.0.5.10",
        "port": 443,
        "protocol": "HTTPS",
        "details": "Data exfiltration traffic — large outbound payload",
        "severity": "critical",
    },
    {
        "event_id": "EVT-026",
        "evidence_id": None,
        "timestamp": "2026-10-12T09:12:00+05:30",
        "source": "Firewall",
        "action": "ALLOW",
        "src_ip": "10.0.5.10",
        "dst_ip": "52.66.100.20",
        "port": 443,
        "protocol": "HTTPS",
        "details": "Normal outbound API call to RollCall cloud — routine sync",
        "severity": "info",
    },
]

# ---------------------------------------------------------------------------
# HelpDesk / Ticketing Logs
# ---------------------------------------------------------------------------
HELPDESK_LOGS = [
    {
        "event_id": "EVT-027",
        "evidence_id": "EV-005",
        "timestamp": "2026-10-12T10:30:00+05:30",
        "source": "HelpDesk",
        "user": "vendor-rollcall-support",
        "action": "TICKET_CREATED",
        "ticket_id": "HD-4471",
        "details": "RollCall vendor reported sync failures and duplicate data — triggered internal review",
        "severity": "medium",
    },
    {
        "event_id": "EVT-028",
        "evidence_id": None,
        "timestamp": "2026-10-12T11:00:00+05:30",
        "source": "HelpDesk",
        "user": "admin@northstar.edu.in",
        "action": "TICKET_ESCALATED",
        "ticket_id": "HD-4471",
        "details": "Ticket escalated to IT Security team for investigation",
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# Credential Audit Logs
# ---------------------------------------------------------------------------
CREDENTIAL_AUDIT_LOGS = [
    {
        "event_id": "EVT-029",
        "evidence_id": "EV-007",
        "timestamp": "2026-10-12T12:00:00+05:30",
        "source": "IAM-Audit",
        "user": "svc-rollcall",
        "action": "CREDENTIAL_REVIEW",
        "details": "Credential for svc-rollcall last rotated 14 months ago (Aug 2025) — NO rotation policy in place",
        "severity": "critical",
    },
    {
        "event_id": "EVT-030",
        "evidence_id": None,
        "timestamp": "2026-10-12T12:05:00+05:30",
        "source": "IAM-Audit",
        "user": "svc-campusvault",
        "action": "CREDENTIAL_REVIEW",
        "details": "CampusVault service credential — last rotated 11 months ago",
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# Access Control / Permissions Audit Logs
# ---------------------------------------------------------------------------
ACCESS_CONTROL_LOGS = [
    {
        "event_id": "EVT-031",
        "evidence_id": "EV-009",
        "timestamp": "2026-10-12T12:10:00+05:30",
        "source": "IAM-Audit",
        "user": "svc-rollcall",
        "action": "PERMISSION_REVIEW",
        "details": "Service account has excessive permissions: read + write + export on learner-data, config, enrollment. Violates least-privilege principle.",
        "severity": "critical",
    },
    {
        "event_id": "EVT-032",
        "evidence_id": None,
        "timestamp": "2026-10-12T12:12:00+05:30",
        "source": "IAM-Audit",
        "user": "svc-rollcall",
        "action": "PERMISSION_REVIEW",
        "details": "No scope restrictions on API access — full tenant access granted",
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# Alerting / Monitoring Gaps
# ---------------------------------------------------------------------------
ALERTING_LOGS = [
    {
        "event_id": "EVT-033",
        "evidence_id": "EV-010",
        "timestamp": "2026-10-12T12:30:00+05:30",
        "source": "SIEM-Audit",
        "action": "AUDIT_FINDING",
        "details": "No real-time alerting configured for bulk data exports, off-hours access, or rate-limit breaches",
        "severity": "critical",
    },
    {
        "event_id": "EVT-034",
        "evidence_id": None,
        "timestamp": "2026-10-12T12:32:00+05:30",
        "source": "SIEM-Audit",
        "action": "AUDIT_FINDING",
        "details": "Log retention set to 30 days — insufficient for forensic investigation",
        "severity": "medium",
    },
]

# ---------------------------------------------------------------------------
# Additional filler events (EVT-035 → EVT-050) for realistic volume
# ---------------------------------------------------------------------------
ADDITIONAL_LOGS = [
    {"event_id": f"EVT-{i:03d}", "timestamp": f"2026-10-12T{8 + (i % 10):02d}:{(i * 3) % 60:02d}:00+05:30",
     "source": src, "user": usr, "action": act, "severity": sev, "details": det}
    for i, (src, usr, act, sev, det) in enumerate([
        ("IAM-Gateway", "faculty02@northstar.edu.in", "LOGIN_SUCCESS", "info", "Faculty login — normal"),
        ("IAM-Gateway", "faculty03@northstar.edu.in", "LOGIN_SUCCESS", "info", "Faculty login — normal"),
        ("RollCall-API-GW", "svc-rollcall", "API_CALL", "info", "Routine attendance sync"),
        ("CampusVault", "registrar@northstar.edu.in", "VIEW", "info", "Registrar viewing student records"),
        ("Firewall", "system", "ALLOW", "info", "Normal outbound HTTPS traffic"),
        ("IAM-Gateway", "student01@northstar.edu.in", "LOGIN_SUCCESS", "info", "Student portal login"),
        ("RollCall-API-GW", "svc-rollcall", "API_CALL", "info", "Routine grade push"),
        ("CampusVault", "admin@northstar.edu.in", "VIEW", "info", "Admin dashboard access"),
        ("IAM-Gateway", "faculty01@northstar.edu.in", "LOGOUT", "info", "Faculty logout"),
        ("Firewall", "system", "BLOCK", "info", "Blocked port-scan attempt from internet"),
        ("IAM-Gateway", "admin@northstar.edu.in", "PASSWORD_CHANGE", "info", "Admin password rotation"),
        ("RollCall-API-GW", "svc-rollcall", "API_CALL", "info", "Attendance mark push"),
        ("CampusVault", "registrar@northstar.edu.in", "UPLOAD", "info", "Registrar uploaded transcript"),
        ("IAM-Gateway", "faculty04@northstar.edu.in", "LOGIN_FAIL", "medium", "Failed login — wrong password"),
        ("Firewall", "system", "ALLOW", "info", "VPN tunnel established"),
        ("IAM-Gateway", "student02@northstar.edu.in", "LOGIN_SUCCESS", "info", "Student portal login"),
    ], start=35)
]


def get_all_logs():
    """Return every log category merged into one flat list, sorted by timestamp."""
    combined = (
        AUTH_LOGS
        + API_ACCESS_LOGS
        + CONFIG_ACCESS_LOGS
        + DATA_EXPORT_LOGS
        + NETWORK_LOGS
        + HELPDESK_LOGS
        + CREDENTIAL_AUDIT_LOGS
        + ACCESS_CONTROL_LOGS
        + ALERTING_LOGS
        + ADDITIONAL_LOGS
    )
    return sorted(combined, key=lambda e: e.get("timestamp", ""))


def get_logs_by_category():
    """Return logs grouped by category."""
    return {
        "auth_logs": AUTH_LOGS,
        "api_access_logs": API_ACCESS_LOGS,
        "config_access_logs": CONFIG_ACCESS_LOGS,
        "data_export_logs": DATA_EXPORT_LOGS,
        "network_logs": NETWORK_LOGS,
        "helpdesk_logs": HELPDESK_LOGS,
        "credential_audit_logs": CREDENTIAL_AUDIT_LOGS,
        "access_control_logs": ACCESS_CONTROL_LOGS,
        "alerting_logs": ALERTING_LOGS,
        "additional_logs": ADDITIONAL_LOGS,
    }
