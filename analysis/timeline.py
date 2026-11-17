"""
analysis/timeline.py — Chronological Incident Timeline Reconstruction
======================================================================
Official Case NS-26-014 Forensic Reconstruction
CRIMEATHON'26 — Team SENTRIX (DEFENSE Track)
"""

INCIDENT_TIMELINE = [
    {
        "phase": "Pre-Incident Exposure",
        "step": 1,
        "timestamp": "2026-10-09T15:42:00+05:30",
        "title": "Secret Exposure in Support Ticket Archive",
        "description": (
            "IT Operations Analyst Ananya Raman attached an unredacted screenshot of the integration "
            "configuration page to HelpDesk ticket HD-1058 during RollCall API troubleshooting. "
            "Direct violation of Policy NS-SEC-04 Rule 1."
        ),
        "evidence_ids": ["E06", "E08"],
        "event_ids": ["HD-1058", "NS-SEC-04-R1"],
        "severity": "high",
        "mitre_tactic": "Credential Exposure (CWE-312 / T1552)",
    },
    {
        "phase": "Initial Connection",
        "step": 2,
        "timestamp": "2026-10-12T03:15:55+05:30",
        "title": "External Inbound Perimeter Connection",
        "description": (
            "First observed connection using the RollCall production client identifier (rollcall-prod) "
            "originating from unrecognized external IP 203.0.113.77. Edge firewall allowed connection due to unconfigured IP restrictions."
        ),
        "evidence_ids": ["E09", "E05"],
        "event_ids": ["N001", "INT-01"],
        "severity": "critical",
        "mitre_tactic": "Initial Access (TA0001) — Valid Accounts (T1078)",
    },
    {
        "phase": "Token Authentication",
        "step": 3,
        "timestamp": "2026-10-12T03:16:32+05:30",
        "title": "Service Identity Authentication",
        "description": (
            "Service identity 'svc_rollcall' authenticated via token from external IP 203.0.113.77. "
            "Normal daily connector authentications strictly originate from internal subnet 10.10.4.12 at ~02:01 IST."
        ),
        "evidence_ids": ["E01"],
        "event_ids": ["A011", "A012", "A013"],
        "severity": "critical",
        "mitre_tactic": "Defense Evasion (TA0005) — Use of Legitimate Service Account",
    },
    {
        "phase": "Discovery & Config Read",
        "step": 4,
        "timestamp": "2026-10-12T03:16:35+05:30",
        "title": "Integration Settings Read",
        "description": (
            "Service identity 'svc_rollcall' from 203.0.113.77 performed credential_config_read on "
            "'integration-settings/rollcall-prod'. Preceded API exploitation by seconds."
        ),
        "evidence_ids": ["E11"],
        "event_ids": ["CHG-882"],
        "severity": "critical",
        "mitre_tactic": "Discovery (TA0007) — Account / Secret Discovery (T1087)",
    },
    {
        "phase": "Collection: Bulk Search",
        "step": 5,
        "timestamp": "2026-10-12T03:16:40+05:30",
        "title": "Mass Learner Profile Query",
        "description": (
            "Client 'rollcall-prod' with key 'rc-prod-01' queried /v1/learners/search, dumping 2,300 "
            "active learner profile records in ClassBridge. Flagged abnormal query volume (baseline: 240 records)."
        ),
        "evidence_ids": ["E02", "E03"],
        "event_ids": ["P003", "R003"],
        "severity": "critical",
        "mitre_tactic": "Collection (TA0009) — Data from Information Repositories (T1213)",
    },
    {
        "phase": "Collection: Export Job Created",
        "step": 6,
        "timestamp": "2026-10-12T03:17:09+05:30",
        "title": "Bulk Profile Export Triggered",
        "description": (
            "Client invoked POST /v1/learners/export. ClassBridge logged action 'learner.export' for 2,300 "
            "records, generating cloud archive 'learners-20261012.csv'. Role held unauthorized export privileges."
        ),
        "evidence_ids": ["E02", "E03", "E11"],
        "event_ids": ["P004", "R004", "CHG-883"],
        "severity": "critical",
        "mitre_tactic": "Collection (TA0009) — Automated Export Generation",
    },
    {
        "phase": "Data Exfiltration (Part 1)",
        "step": 7,
        "timestamp": "2026-10-12T03:20:12+05:30",
        "title": "CampusVault Object Listing & Download",
        "description": (
            "Principal 'rollcall-prod' listed learner-exports/ in CampusVault and downloaded "
            "'learners-20261012.csv' (486,200 bytes) at 03:21:03 IST to external host 203.0.113.77."
        ),
        "evidence_ids": ["E04"],
        "event_ids": ["C002", "C003"],
        "severity": "critical",
        "mitre_tactic": "Exfiltration (TA0010) — Exfiltration Over Web Service (T1567)",
    },
    {
        "phase": "Data Exfiltration (Part 2)",
        "step": 8,
        "timestamp": "2026-10-12T03:24:48+05:30",
        "title": "Second Download & Session Close",
        "description": (
            "Principal downloaded 'learners-20261012.csv' a second time (486,200 bytes) confirming successful "
            "data capture. Connection ceased at 03:25:00 IST."
        ),
        "evidence_ids": ["E04", "E09"],
        "event_ids": ["C004", "N002"],
        "severity": "critical",
        "mitre_tactic": "Exfiltration (TA0010) — Redundant Exfiltration Verification",
    },
    {
        "phase": "Breach Discovery",
        "step": 9,
        "timestamp": "2026-10-12T09:15:00+05:30",
        "title": "Delayed Internal Discovery by Finance",
        "description": (
            "Finance analyst discovered unexpected export file in CampusVault (HD-1069). No automated SIEM "
            "alert fired during the incident, demonstrating zero real-time detection readiness."
        ),
        "evidence_ids": ["E06"],
        "event_ids": ["HD-1069"],
        "severity": "high",
        "mitre_tactic": "Incident Response Gap — Delayed Human Discovery",
    },
    {
        "phase": "Vendor Clarification",
        "step": 10,
        "timestamp": "2026-10-13T12:30:00+05:30",
        "title": "Vendor Denies Authorizing Bulk Export",
        "description": (
            "RollCall Security confirmed routine maintenance occurred, no bulk export was scheduled, "
            "and legitimate connector node 10.10.4.12 was idle, narrowing root cause to exposed credentials."
        ),
        "evidence_ids": ["E10", "E12"],
        "event_ids": ["VND-221", "E12-NOTE"],
        "severity": "medium",
        "mitre_tactic": "Forensic Corroboration — Third-Party Verification",
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
        }
        for item in INCIDENT_TIMELINE
    ]
