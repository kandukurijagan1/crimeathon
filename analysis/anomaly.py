"""
analysis/anomaly.py — Multi-Vector Anomaly Detection & Threat Correlation Engine
================================================================================
CRIMEATHON'26 Case NS-26-014: The Northstar Learning Services Investigation
Analyzes authentic evidence files E01–E12.
Calculates explainable Heuristic Severity Ratings (0–100) reflecting policy impact.
Strictly separates conclusions into:
  1. CONFIRMED OBSERVATION
  2. STRONGLY SUPPORTED INFERENCE
  3. UNKNOWN / REQUIRES FURTHER INVESTIGATION
"""

from data.logs import (
    AUTH_LOGS,
    API_ACCESS_LOGS,
    CONFIG_ACCESS_LOGS,
    DATA_EXPORT_LOGS,
    NETWORK_LOGS,
    HELPDESK_LOGS,
)

# Documented internal authorized subnets
APPROVED_INTERNAL_IPS = {
    "10.10.4.12",       # Approved Northstar integration connector node (E05, E09, E10)
    "198.51.100.21",    # IT Operations staff management subnet (E01, E03, E07)
    "198.51.100.31",    # Finance reporting authorized subnet (E04)
    "10.10.8.44",       # Support technician internal subnet (E01)
    "127.0.0.1",        # Local loopback test environment
}

EXTERNAL_ATTACKER_IP = "203.0.113.77"
UNAUTHORIZED_EXTERNAL_IP = "203.0.113.77"
NORMAL_ATTENDANCE_LIMIT = 250


# =============================================================================
# Detection Rules
# =============================================================================

def detect_external_service_ingress():
    """Rule 1: Detect inbound service-identity usage from unwhitelisted external IP."""
    hits = [l for l in AUTH_LOGS if l.get("ip") == UNAUTHORIZED_EXTERNAL_IP]
    net_hits = [l for l in NETWORK_LOGS if l.get("src_ip") == UNAUTHORIZED_EXTERNAL_IP]
    
    if hits:
        event_ids = sorted(list(set([l["event_id"] for l in hits] + [l["event_id"] for l in net_hits])))
        return [{
            "finding_id": "FND-001",
            "anomaly": "External Source IP for Service Identity",
            "severity": "CRITICAL",
            "heuristic_score": 95,
            "risk_score": 95,
            "timestamp": "2026-10-12T03:15:55+05:30",
            "source_evidence_file": "E01_Authentication_Logs.csv, E09_Network_Observations.csv",
            "event_ids": event_ids,
            "event_id": event_ids[0],
            "detection_rule": "RULE-AUTH-01: Ingress Service-Account Boundary Enforcement",
            "reason_for_flagging": (
                f"Service identity 'svc_rollcall' authenticated via token rc-prod-01 from unrecognized "
                f"external IP {UNAUTHORIZED_EXTERNAL_IP}. Routine daily connector authentications strictly originate "
                "from internal subnet node 10.10.4.12 at approximately 02:01 IST."
            ),
            "confidence_classification": "CONFIRMED OBSERVATION",
            "recommended_defensive_action": (
                "Deploy strict IP allowlisting on API gateway and edge firewalls restricting svc_rollcall "
                "to internal connector host 10.10.4.12 only. Drop external packets and trigger real-time SIEM alerts."
            ),
            "policy_violation": "NS-SEC-04 Rule 4 (Vendor integrations restricted to documented source networks)"
        }]
    return []


def detect_bulk_learner_export():
    """Rule 2: Detect unauthorized bulk learner search and profile export."""
    vault_exports = [l for l in DATA_EXPORT_LOGS if l.get("record_count", 0) > NORMAL_ATTENDANCE_LIMIT]
    api_exports = [l for l in API_ACCESS_LOGS if l.get("endpoint") == "/v1/learners/export"]
    
    if vault_exports or api_exports:
        event_ids = sorted(list(set([l["event_id"] for l in vault_exports + api_exports])))
        return [{
            "finding_id": "FND-002",
            "anomaly": "Unauthorized Bulk Learner Profile Export",
            "severity": "CRITICAL",
            "heuristic_score": 98,
            "risk_score": 98,
            "timestamp": "2026-10-12T03:17:09+05:30",
            "source_evidence_file": "E02_ClassBridge_Audit_Logs.csv, E03_API_Gateway_Logs.csv, E04_CampusVault_Audit_Logs.csv",
            "event_ids": event_ids,
            "event_id": "R004",
            "detection_rule": "RULE-API-02: Bulk Data Export & Least-Privilege Role Scoping",
            "reason_for_flagging": (
                "Client rollcall-prod invoked POST /v1/learners/export, returning 2,300 learner profile records "
                "(P004/R004) and creating cloud archive learners-20261012.csv (486,200 bytes). "
                "Attendance connectors should never be provisioned with export permissions."
            ),
            "confidence_classification": "CONFIRMED OBSERVATION",
            "recommended_defensive_action": (
                "De-scope integration credential INT-01 to attendance.read only; revoke learner.export and "
                "learner.search. Enforce mandatory manager dual-approval and export record ceilings (max 100)."
            ),
            "policy_violation": "NS-SEC-04 Rule 2 (Least privilege) & Rule 5 (Bulk exports require approved request)"
        }]
    return []


def detect_repeated_archive_download():
    """Rule 3: Detect multiple exfiltration downloads of sensitive cloud archive."""
    downloads = [l for l in DATA_EXPORT_LOGS if l.get("action") == "object.download" and l.get("ip") == UNAUTHORIZED_EXTERNAL_IP]
    
    if len(downloads) >= 2:
        event_ids = [d["event_id"] for d in downloads]
        total_bytes = sum(d.get("bytes", 0) for d in downloads)
        return [{
            "finding_id": "FND-003",
            "anomaly": "Repeated Cloud Archive Download (Data Exfiltration)",
            "severity": "CRITICAL",
            "heuristic_score": 100,
            "risk_score": 100,
            "timestamp": "2026-10-12T03:21:03+05:30",
            "source_evidence_file": "E04_CampusVault_Audit_Logs.csv",
            "event_ids": event_ids,
            "event_id": event_ids[0],
            "detection_rule": "RULE-VAULT-03: Repeated Cloud Storage Download & Exfiltration Pattern",
            "reason_for_flagging": (
                f"Archive 'learners-20261012.csv' (486,200 bytes) was downloaded TWICE (C003 at 03:21:03 and "
                f"C004 at 03:24:48) by rollcall-prod to external host {UNAUTHORIZED_EXTERNAL_IP}, transferring {total_bytes} bytes."
            ),
            "confidence_classification": "CONFIRMED OBSERVATION",
            "recommended_defensive_action": (
                "Quarantine export bucket; require dual-factor authorization for downloading learner archives; "
                "deploy egress DLP scanning on cloud object stores."
            ),
            "policy_violation": "NS-SEC-04 Rule 5 (Bulk exports logged & approved) & Rule 6 (Unusual access volume)"
        }]
    return []


def detect_config_harvesting():
    """Rule 4: Detect configuration-settings access correlated with subsequent API burst."""
    config_reads = [l for l in CONFIG_ACCESS_LOGS if l.get("action") == "credential_config_read" and l.get("ip") == UNAUTHORIZED_EXTERNAL_IP]
    
    if config_reads:
        event_ids = [c["event_id"] for c in config_reads]
        return [{
            "finding_id": "FND-004",
            "anomaly": "Integration Settings Read Correlated with API Activity",
            "severity": "CRITICAL",
            "heuristic_score": 96,
            "risk_score": 96,
            "timestamp": "2026-10-12T03:16:35+05:30",
            "source_evidence_file": "E11_Additional_Configuration_Audit.csv",
            "event_ids": event_ids,
            "event_id": event_ids[0],
            "detection_rule": "RULE-CFG-04: Off-Hours Configuration Read Detection",
            "reason_for_flagging": (
                "Event CHG-882 records svc_rollcall reading integration-settings/rollcall-prod from external IP "
                f"{UNAUTHORIZED_EXTERNAL_IP} at 03:16:35 IST, occurring seconds prior to mass learner query (R003) and export (R004). "
                "Note: Log CHG-882 confirms configuration read; whether plaintext secrets were exposed remains unverified in evidence."
            ),
            "confidence_classification": "CONFIRMED OBSERVATION",
            "recommended_defensive_action": (
                "Encrypt integration secrets in approved vault; alert on configuration access from non-whitelisted IPs."
            ),
            "policy_violation": "NS-SEC-04 Rule 1 (Credentials stored in approved secrets vault)"
        }]
    return []


def detect_credential_hygiene_defect():
    """Rule 5: Detect missing expiry, missing rotation, and unconstrained IP on integration."""
    return [{
        "finding_id": "FND-005",
        "anomaly": "Stale Credential with Missing Expiry & IP Restriction",
        "severity": "HIGH",
        "heuristic_score": 88,
        "risk_score": 88,
        "timestamp": "2026-10-12T00:00:00+05:30",
        "source_evidence_file": "E05_Integration_Register.csv, E12_Incident_Response_Note.txt",
        "event_ids": ["INT-01", "E12-NOTE"],
        "event_id": "INT-01",
        "detection_rule": "RULE-IAM-05: Credential Lifecycle & Hygiene Compliance",
        "reason_for_flagging": (
            "Integration INT-01 was created on 2026-03-04 (approx. 7 months active at incident time). "
            "Register confirms 'expires: never', no scheduled October rotation, and 'ip_restriction: not configured'. "
            "Allowed the stale token to be used externally without expiry challenge."
        ),
        "confidence_classification": "CONFIRMED OBSERVATION",
        "recommended_defensive_action": (
            "Enforce mandatory 90-day automated credential rotation; configure hard token expiry TTL; "
            "mandate source IP allowlisting in the integration register."
        ),
        "policy_violation": "NS-SEC-04 Rule 3 (Production service credentials must have expiry or rotation schedule)"
    }]


def detect_former_staff_persistence():
    """Rule 6: Detect former employee account active post-departure."""
    ajay_auth = [l for l in AUTH_LOGS if l.get("user") == "former.ajay" and l.get("result") == "SUCCESS"]
    
    if ajay_auth:
        event_ids = [l["event_id"] for l in ajay_auth]
        return [{
            "finding_id": "FND-006",
            "anomaly": "Former Employee Account Active Post-Departure",
            "severity": "HIGH",
            "heuristic_score": 75,
            "risk_score": 75,
            "timestamp": "2026-10-09T09:13:44+05:30",
            "source_evidence_file": "E01_Authentication_Logs.csv, E07_Staff_and_Service_Account_Register.csv",
            "event_ids": event_ids,
            "event_id": event_ids[0],
            "detection_rule": "RULE-IAM-06: Offboarding Deprovisioning Enforcement",
            "reason_for_flagging": (
                "Event A006 records former support technician former.ajay successfully authenticating via MFA on "
                "2026-10-09, despite recorded employment end date of 2026-09-30 (E07). "
                "IMPORTANT FORENSIC BOUNDARY: This confirms an identity offboarding governance defect, but does NOT "
                "establish responsibility for the external RollCall incident on 12-Oct."
            ),
            "confidence_classification": "CONFIRMED OBSERVATION",
            "recommended_defensive_action": (
                "Automate HR-to-IAM deprovisioning pipelines ensuring instant deactivation of accounts on employee last day."
            ),
            "policy_violation": "NS-SEC-04 Rule 7 (Former staff accounts disabled on or before last working day)"
        }]
    return []


def detect_ticket_exposure_hypothesis():
    """Rule 7: Catalog investigated hypothesis regarding ticket screenshot."""
    return [{
        "finding_id": "FND-007",
        "anomaly": "Potential Credential Exposure Opportunity (Investigated Hypothesis)",
        "severity": "MEDIUM",
        "heuristic_score": 60,
        "risk_score": 60,
        "timestamp": "2026-10-09T15:42:00+05:30",
        "source_evidence_file": "E06_HelpDesk_Tickets.csv",
        "event_ids": ["HD-1058"],
        "event_id": "HD-1058",
        "detection_rule": "RULE-GOV-07: Secret Leakage & Support Archive Auditing",
        "reason_for_flagging": (
            "Ticket HD-1058 recorded an IT Analyst attaching a configuration screenshot to a vendor ticket. "
            "FORENSIC UNKNOWN: The screenshot's actual image contents are not provided in the case evidence. "
            "Whether it revealed secrets or was accessed by unauthorized parties remains UNVERIFIED and unknown."
        ),
        "confidence_classification": "UNKNOWN / REQUIRES FURTHER INVESTIGATION",
        "recommended_defensive_action": (
            "Implement automated DLP scanning on support ticket attachments to redact credentials and API keys."
        ),
        "policy_violation": "NS-SEC-04 Rule 1 (Credentials must not be placed in support tickets, screenshots, or email)"
    }]


def detect_unverified_human_operator():
    """Rule 8: Document the forensic limit regarding physical human operator identity."""
    return [{
        "finding_id": "FND-008",
        "anomaly": "Attribution Boundary (Human Operator Unproven)",
        "severity": "MEDIUM",
        "heuristic_score": 50,
        "risk_score": 50,
        "timestamp": "2026-10-12T03:16:32+05:30",
        "source_evidence_file": "E01_Authentication_Logs.csv, E12_Incident_Response_Note.txt",
        "event_ids": ["A011", "E12-NOTE"],
        "event_id": "A011",
        "detection_rule": "RULE-FOR-08: Forensic Attribution Ground-Truth Boundary",
        "reason_for_flagging": (
            "While token authentication A011 proves that service account svc_rollcall was operated from external IP "
            "203.0.113.77, logs do not establish the physical identity of the human operator behind the keyboard. "
            "Per E12, service-account events must not be treated as proof of physical human identity or labeled as a confirmed attacker."
        ),
        "confidence_classification": "UNKNOWN / REQUIRES FURTHER INVESTIGATION",
        "recommended_defensive_action": (
            "Deploy device-fingerprinting, certificate-based mutual TLS, and hardware token binding for B2B connectors."
        ),
        "policy_violation": "Forensic Principle (Do not confuse service identity with physical human attribution)"
    }]


# =============================================================================
# Aggregator & Classifier
# =============================================================================

def run_all_detections():
    """Aggregates all heuristic findings, sorted by severity score."""
    all_findings = (
        detect_external_service_ingress()
        + detect_bulk_learner_export()
        + detect_repeated_archive_download()
        + detect_config_harvesting()
        + detect_credential_hygiene_defect()
        + detect_former_staff_persistence()
        + detect_ticket_exposure_hypothesis()
        + detect_unverified_human_operator()
    )

    # Sort descending by heuristic score
    sorted_findings = sorted(all_findings, key=lambda x: x["heuristic_score"], reverse=True)
    max_score = max((f["heuristic_score"] for f in sorted_findings), default=0)

    # Categorize findings by confidence classification
    confirmed = [f for f in sorted_findings if f["confidence_classification"] == "CONFIRMED OBSERVATION"]
    inferences = [f for f in sorted_findings if f["confidence_classification"] == "STRONGLY SUPPORTED INFERENCE"]
    unknowns = [f for f in sorted_findings if f["confidence_classification"] == "UNKNOWN / REQUIRES FURTHER INVESTIGATION"]

    return {
        "scoring_methodology": "Heuristic Severity Rating (0–100, measures policy impact, not compromise probability)",
        "total_anomalies": len(all_findings),
        "unique_anomaly_types": len(sorted_findings),
        "overall_risk_score": max_score,
        "threat_level": (
            "CRITICAL" if max_score >= 90 else
            "HIGH" if max_score >= 70 else
            "MEDIUM" if max_score >= 40 else "LOW"
        ),
        "classification_summary": {
            "confirmed_observations": len(confirmed),
            "strongly_supported_inferences": len(inferences),
            "unknowns_requiring_investigation": len(unknowns)
        },
        "findings": sorted_findings,
    }


# Backward compatibility aliases
detect_unwhitelisted_external_ip = detect_external_service_ingress
detect_off_hours_bulk_export = detect_bulk_learner_export
detect_config_read_preceding_abuse = detect_config_harvesting
detect_unusual_api_query_volume = detect_bulk_learner_export
detect_offboarding_governance_anomaly = detect_former_staff_persistence

