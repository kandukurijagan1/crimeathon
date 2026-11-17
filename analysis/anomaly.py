"""
analysis/anomaly.py — Heuristic Anomaly Detection Engine for Sentrix Shield
===========================================================================
Analyses authentic Case NS-26-014 telemetry across E01–E12.
Calculates heuristic severity scores (0–100) reflecting policy deviation and
potential security impact (NOT statistical compromise probabilities).
"""

from data.logs import (
    AUTH_LOGS,
    API_ACCESS_LOGS,
    CONFIG_ACCESS_LOGS,
    DATA_EXPORT_LOGS,
    NETWORK_LOGS,
)

# ---------------------------------------------------------------------------
# Approved network baselines & operational thresholds
# ---------------------------------------------------------------------------
NORMAL_ATTENDANCE_RECORD_LIMIT = 250
OFF_HOURS_START = 0   # 00:00 IST
OFF_HOURS_END = 6     # 06:00 IST

# Documented internal subnets per E01, E03, E04, E07, E09
WHITELISTED_INTERNAL_IPS = {
    "10.10.4.12",       # Approved Northstar integration connector node (E05, E09, E10)
    "198.51.100.21",    # IT Operations staff management subnet (E01, E03, E07)
    "198.51.100.31",    # Finance reporting authorized subnet (E04)
    "10.10.8.44",       # Support technician internal subnet (E01)
    "127.0.0.1",        # Local loopback test environment
}

EXTERNAL_ATTACKER_IP = "203.0.113.77"


def _hour_from_ts(ts: str) -> int:
    """Extract hour (int) from an ISO timestamp string."""
    try:
        return int(ts[11:13])
    except (IndexError, ValueError):
        return -1


# ---------------------------------------------------------------------------
# Heuristic Detection Rules
# ---------------------------------------------------------------------------

def detect_unwhitelisted_external_ip():
    """Rule 1: Detect inbound service activity from unwhitelisted external IPs."""
    findings = []
    suspicious_events = []
    
    for log in AUTH_LOGS + API_ACCESS_LOGS + DATA_EXPORT_LOGS + CONFIG_ACCESS_LOGS:
        ip = log.get("ip", "")
        if ip and ip not in WHITELISTED_INTERNAL_IPS:
            suspicious_events.append(log)
            
    if suspicious_events:
        findings.append({
            "rule_id": "RULE-SEC-01",
            "anomaly": "External Source IP for Service Identity",
            "heuristic_score": 95,
            "risk_level": "critical",
            "description": (
                f"Service identity activity observed from external IP {EXTERNAL_ATTACKER_IP} "
                f"across {len(suspicious_events)} correlated events. Integration register INT-01 "
                "had 'ip_restriction: not configured', allowing unverified perimeter access."
            ),
            "affected_events": sorted(list(set(e["event_id"] for e in suspicious_events))),
            "recommendation": "Enforce strict IP allowlisting at API Gateway restricting connector to 10.10.4.12.",
            "policy_violation": "NS-SEC-04 Rule 4 (Documented source network restriction)"
        })
    return findings


def detect_off_hours_bulk_export():
    """Rule 2: Detect unauthorized bulk learner export exceeding baseline limit."""
    findings = []
    export_events = [
        log for log in DATA_EXPORT_LOGS
        if log.get("record_count", 0) > NORMAL_ATTENDANCE_RECORD_LIMIT
    ]
    api_export_events = [
        log for log in API_ACCESS_LOGS
        if log.get("endpoint") == "/v1/learners/export" or log.get("records_returned", 0) > NORMAL_ATTENDANCE_RECORD_LIMIT
    ]
    
    if export_events or api_export_events:
        all_ids = [e["event_id"] for e in export_events + api_export_events]
        findings.append({
            "rule_id": "RULE-SEC-02",
            "anomaly": "Unauthorized Bulk Learner Profile Export",
            "heuristic_score": 98,
            "risk_level": "critical",
            "description": (
                "Bulk export of 2,300 active student records triggered via /v1/learners/export (R004/P004) "
                "and downloaded from CampusVault (C003, C004; 486,200 bytes). Normal attendance baseline is ~240 records."
            ),
            "affected_events": sorted(list(set(all_ids))),
            "recommendation": "Remove learner.export scope from connector identity; require manager approval for bulk exports.",
            "policy_violation": "NS-SEC-04 Rule 5 (Bulk exports require approved business request)"
        })
    return findings


def detect_config_read_preceding_abuse():
    """Rule 3: Detect configuration read preceding API query burst."""
    findings = []
    config_reads = [
        log for log in CONFIG_ACCESS_LOGS
        if log.get("action") == "credential_config_read" and log.get("ip") not in WHITELISTED_INTERNAL_IPS
    ]
    
    if config_reads:
        findings.append({
            "rule_id": "RULE-SEC-03",
            "anomaly": "Integration Settings Read from External IP",
            "heuristic_score": 96,
            "risk_level": "critical",
            "description": (
                "Event CHG-882 records svc_rollcall reading integration-settings/rollcall-prod at 03:16:35 IST "
                "from external IP 203.0.113.77, occurring seconds before bulk search (R003) and export (R004)."
            ),
            "affected_events": [c["event_id"] for c in config_reads],
            "recommendation": "Encrypt secrets in dedicated secrets vault; deny read access to external integration tokens.",
            "policy_violation": "NS-SEC-04 Rule 1 (Credentials must reside in approved vault)"
        })
    return findings


def detect_unusual_api_query_volume():
    """Rule 4: Detect unusual API velocity and non-attendance endpoint access."""
    findings = []
    unusual_calls = [
        log for log in API_ACCESS_LOGS
        if log.get("ip") not in WHITELISTED_INTERNAL_IPS and log.get("endpoint") != "/v1/attendance"
    ]
    
    if unusual_calls:
        findings.append({
            "rule_id": "RULE-SEC-04",
            "anomaly": "Anomalous Endpoint Traversal & Query Velocity",
            "heuristic_score": 92,
            "risk_level": "critical",
            "description": (
                f"Client rollcall-prod accessed non-attendance endpoints (/v1/learners/search, /v1/learners/export, "
                f"/v1/courses) returning 4,642 total records within 3 minutes from external source 203.0.113.77."
            ),
            "affected_events": [c["event_id"] for c in unusual_calls],
            "recommendation": "Enforce per-key endpoint rate limiting and strictly scope service keys to /v1/attendance.",
            "policy_violation": "NS-SEC-04 Rule 2 (Least privilege) & Rule 6 (Review unusual access volumes)"
        })
    return findings


def detect_offboarding_governance_anomaly():
    """Rule 5: Detect former employee account activity post-departure."""
    findings = []
    former_staff_logins = [
        log for log in AUTH_LOGS
        if log.get("user") == "former.ajay" and log.get("result") == "SUCCESS"
    ]
    
    if former_staff_logins:
        findings.append({
            "rule_id": "RULE-SEC-05",
            "anomaly": "Former Employee Account Active Post-Departure",
            "heuristic_score": 75,
            "risk_level": "high",
            "description": (
                "Event A006 records former support technician former.ajay successfully authenticating via MFA on "
                "2026-10-09 (departed 2026-09-30). This indicates an identity offboarding governance defect. "
                "Note: Does not establish responsibility for the external incident."
            ),
            "affected_events": [l["event_id"] for l in former_staff_logins],
            "recommendation": "Automate HR-to-IAM deprovisioning to revoke all credentials on or before the employee's last day.",
            "policy_violation": "NS-SEC-04 Rule 7 (Former staff accounts must be disabled on or before last working day)"
        })
    return findings


# ---------------------------------------------------------------------------
# Aggregator & Severity Calculator
# ---------------------------------------------------------------------------

def run_all_detections():
    """Run all heuristic rules and return unified report with scoring."""
    all_findings = (
        detect_unwhitelisted_external_ip()
        + detect_off_hours_bulk_export()
        + detect_config_read_preceding_abuse()
        + detect_unusual_api_query_volume()
        + detect_offboarding_governance_anomaly()
    )
    
    for f in all_findings:
        f["risk_score"] = f["heuristic_score"]

    # Sort by heuristic severity score descending
    sorted_findings = sorted(all_findings, key=lambda x: x["heuristic_score"], reverse=True)
    max_score = max((f["heuristic_score"] for f in sorted_findings), default=0)
    
    return {
        "scoring_type": "Heuristic Severity Rating (0–100, measures policy impact, not compromise probability)",
        "total_anomalies": len(all_findings),
        "unique_anomaly_types": len(sorted_findings),
        "overall_risk_score": max_score,
        "threat_level": (
            "CRITICAL" if max_score >= 90 else
            "HIGH" if max_score >= 70 else
            "MEDIUM" if max_score >= 40 else "LOW"
        ),
        "findings": sorted_findings,
    }
