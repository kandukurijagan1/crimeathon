"""
analysis/timeline.py — Chronological Incident Timeline Reconstruction
======================================================================
Official Case NS-26-014 Forensic Reconstruction.
Strictly separates confirmed log observations from hypotheses.
All timestamps are India Standard Time (+05:30).
"""

INCIDENT_TIMELINE = [
    {
        "phase": "Investigated Exposure Opportunity",
        "step": 1,
        "timestamp": "2026-10-09T15:42:00+05:30",
        "title": "Potential Credential Exposure Opportunity (Hypothesis)",
        "description": (
            "IT Operations Analyst Ananya Raman recorded a configuration screenshot attachment "
            "in HelpDesk ticket HD-1058 during RollCall API troubleshooting. Note: The screenshot's actual "
            "contents are not provided in the case dossier. Credential leakage via this ticket is an "
            "investigated hypothesis, not a confirmed observation; contents and exposure mechanism remain unverified."
        ),
        "evidence_ids": ["E06", "E08"],
        "event_ids": ["HD-1058", "NS-SEC-04-R1"],
        "severity": "high",
        "confirmation_status": "HYPOTHESIS (Unverified Contents)",
        "mitre_tactic": "Credential Exposure (CWE-312 / T1552)",
    },
    {
        "phase": "Identity Governance Defect",
        "step": 2,
        "timestamp": "2026-10-09T09:13:44+05:30",
        "title": "Former Staff Member Account Persistence",
        "description": (
            "Former support technician Ajay Prakash (EMP-004) authenticated via MFA from internal IP 10.10.8.44 "
            "(A006, followed by A007 denial) despite departing on 2026-09-30. Violates Policy NS-SEC-04 Rule 7. "
            "Note: This demonstrates an identity offboarding flaw but does NOT establish responsibility for the external incident."
        ),
        "evidence_ids": ["E01", "E07", "E08"],
        "event_ids": ["A006", "A007", "EMP-004", "NS-SEC-04-R7"],
        "severity": "medium",
        "confirmation_status": "CONFIRMED (Separate Governance Defect)",
        "mitre_tactic": "Persistence (TA0003) — Valid Accounts (T1078)",
    },
    {
        "phase": "External Perimeter Ingress",
        "step": 3,
        "timestamp": "2026-10-12T03:15:55+05:30",
        "title": "Inbound Connection from Unrecognized External IP",
        "description": (
            "First observed connection using the RollCall production client identifier (rollcall-prod) "
            "originating from unrecognized external source 203.0.113.77. Ingress was permitted because INT-01 "
            "had 'ip_restriction: not configured' in the integration register."
        ),
        "evidence_ids": ["E09", "E05"],
        "event_ids": ["N001", "INT-01"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Network Log)",
        "mitre_tactic": "Initial Access (TA0001) — Valid Accounts (T1078)",
    },
    {
        "phase": "Token Authentication",
        "step": 4,
        "timestamp": "2026-10-12T03:16:32+05:30",
        "title": "Service Identity Token Authentication",
        "description": (
            "Service identity 'svc_rollcall' authenticated via token from external host 203.0.113.77. "
            "Normal daily connector authentications strictly originate from internal subnet 10.10.4.12 at approximately 02:01 IST."
        ),
        "evidence_ids": ["E01"],
        "event_ids": ["A011", "A012", "A013"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Auth Log)",
        "mitre_tactic": "Defense Evasion (TA0005) — Valid Service Account Usage",
    },
    {
        "phase": "Discovery & Config Read",
        "step": 5,
        "timestamp": "2026-10-12T03:16:35+05:30",
        "title": "Integration Settings Read",
        "description": (
            "Service identity 'svc_rollcall' from external host 203.0.113.77 executed 'credential_config_read' "
            "on 'integration-settings/rollcall-prod'. This audit event occurred immediately prior to API exploitation."
        ),
        "evidence_ids": ["E11"],
        "event_ids": ["CHG-882"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Audit Log)",
        "mitre_tactic": "Discovery (TA0007) — Account / Secret Discovery (T1087)",
    },
    {
        "phase": "Collection: Bulk Search",
        "step": 6,
        "timestamp": "2026-10-12T03:16:40+05:30",
        "title": "Mass Learner Profile Query",
        "description": (
            "Client 'rollcall-prod' with key ID 'rc-prod-01' queried /v1/learners/search, retrieving 2,300 "
            "learner profile records in ClassBridge. Flagged anomalous query volume (normal sync: 238–241 records)."
        ),
        "evidence_ids": ["E02", "E03"],
        "event_ids": ["P003", "R003"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Portal & Gateway Logs)",
        "mitre_tactic": "Collection (TA0009) — Data from Information Repositories (T1213)",
    },
    {
        "phase": "Collection: Bulk Export",
        "step": 7,
        "timestamp": "2026-10-12T03:17:09+05:30",
        "title": "Bulk Profile Export Triggered & Job Created",
        "description": (
            "Client invoked POST /v1/learners/export. ClassBridge logged 'learner.export' for 2,300 records (P004), "
            "and export job 'learner-exports/learners-20261012.csv' was created (CHG-883). INT-01 improperly held 'learner.export' permissions."
        ),
        "evidence_ids": ["E02", "E03", "E11"],
        "event_ids": ["P004", "R004", "CHG-883"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Log & Audit Records)",
        "mitre_tactic": "Collection (TA0009) — Automated Export Generation",
    },
    {
        "phase": "Data Exfiltration",
        "step": 8,
        "timestamp": "2026-10-12T03:20:12+05:30",
        "title": "CampusVault Object Listing & Dual Exfiltration Download",
        "description": (
            "Principal 'rollcall-prod' listed learner-exports/ folder (C002), then downloaded "
            "'learners-20261012.csv' (486,200 bytes) twice at 03:21:03 (C003) and 03:24:48 (C004) to external IP 203.0.113.77."
        ),
        "evidence_ids": ["E04"],
        "event_ids": ["C002", "C003", "C004"],
        "severity": "critical",
        "confirmation_status": "CONFIRMED (Direct Cloud Storage Audit)",
        "mitre_tactic": "Exfiltration (TA0010) — Exfiltration Over Web Service (T1567)",
    },
    {
        "phase": "Connector Resumption",
        "step": 9,
        "timestamp": "2026-10-12T03:25:00+05:30",
        "title": "Legitimate Connector Resumes on Internal Subnet",
        "description": (
            "Normal scheduled connector resumed normal attendance-only requests from internal integration node 10.10.4.12. "
            "External connection from 203.0.113.77 ceased, concluding the 10-minute breach window."
        ),
        "evidence_ids": ["E09"],
        "event_ids": ["N002"],
        "severity": "low",
        "confirmation_status": "CONFIRMED (Direct Network Log)",
        "mitre_tactic": "Perimeter Normalization",
    },
    {
        "phase": "Breach Discovery",
        "step": 10,
        "timestamp": "2026-10-12T09:15:00+05:30",
        "title": "Internal Discovery by Finance Team",
        "description": (
            "Finance analyst discovered the unexpected learner export file in CampusVault (ticket HD-1069). "
            "No automated real-time alert fired during the incident, demonstrating zero real-time detection readiness."
        ),
        "evidence_ids": ["E06"],
        "event_ids": ["HD-1069"],
        "severity": "high",
        "confirmation_status": "CONFIRMED (HelpDesk Ticket Record)",
        "mitre_tactic": "Incident Response Gap — Delayed Human Discovery",
    },
    {
        "phase": "Vendor Clarification",
        "step": 11,
        "timestamp": "2026-10-13T12:30:00+05:30",
        "title": "Vendor Denies Authorizing Bulk Export",
        "description": (
            "RollCall Security confirmed routine maintenance occurred, no bulk export was scheduled, "
            "and legitimate connector node 10.10.4.12 was idle, confirming that credential/configuration exposure was under review."
        ),
        "evidence_ids": ["E10", "E12"],
        "event_ids": ["VND-221", "E12-NOTE"],
        "severity": "medium",
        "confirmation_status": "CONFIRMED (Vendor Communication Record)",
        "mitre_tactic": "Forensic Corroboration — Third-Party Clarification",
    },
]


def get_timeline():
    return INCIDENT_TIMELINE


def get_timeline_summary():
    return [
        {
            "step": item["step"],
            "phase": item["phase"],
            "timestamp": item["timestamp"],
            "title": item["title"],
            "severity": item["severity"],
            "confirmation_status": item.get("confirmation_status", "CONFIRMED"),
        }
        for item in INCIDENT_TIMELINE
    ]
