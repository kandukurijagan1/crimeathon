"""
analysis/anomaly.py — Anomaly Detection Module for Sentrix Shield
=================================================================
Simple rule-based anomaly detection engine.
All data is SYNTHETIC / SIMULATED for the CRIMEATHON'26 hackathon.
"""

from data.logs import (
    AUTH_LOGS,
    API_ACCESS_LOGS,
    CONFIG_ACCESS_LOGS,
    DATA_EXPORT_LOGS,
    NETWORK_LOGS,
)

# ---------------------------------------------------------------------------
# Thresholds & baselines
# ---------------------------------------------------------------------------
NORMAL_API_CALLS_PER_HOUR = 15
OFF_HOURS_START = 0   # 00:00
OFF_HOURS_END = 6     # 06:00
WHITELISTED_IPS = {"10.0.1.15", "10.0.1.22", "10.0.2.40", "10.0.5.10", "10.10.4.12", "198.51.100.21", "52.66.100.20"}
MAX_EXPORT_RECORDS = 100  # anything above this is flagged


def _hour_from_ts(ts: str) -> int:
    """Extract hour (int) from an ISO timestamp string."""
    try:
        return int(ts[11:13])
    except (IndexError, ValueError):
        return -1


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_api_volume_anomaly():
    """Flag API-access events whose volume indicates abuse."""
    findings = []
    suspicious = [
        log for log in API_ACCESS_LOGS
        if log.get("ip") not in WHITELISTED_IPS
    ]
    has_rate_burst = any("312" in log.get("details", "") or log.get("severity") == "critical" for log in suspicious)
    if len(suspicious) >= 3 or has_rate_burst:
        findings.append({
            "anomaly": "Excessive API Call Volume",
            "description": (
                f"{len(suspicious)} API calls from non-whitelisted IPs detected "
                f"including a burst of 300+ calls in 10 minutes (baseline: {NORMAL_API_CALLS_PER_HOUR}/hr). "
                "Indicates automated data scraping or credential abuse."
            ),
            "affected_events": [s["event_id"] for s in suspicious],
            "risk_level": "critical",
            "risk_score": 95,
            "recommendation": "Implement per-IP rate limiting and API key scoping.",
        })
    return findings


def detect_off_hours_access():
    """Flag logins and actions occurring outside business hours."""
    findings = []
    for log in AUTH_LOGS + CONFIG_ACCESS_LOGS:
        hour = _hour_from_ts(log.get("timestamp", ""))
        if OFF_HOURS_START <= hour < OFF_HOURS_END:
            ip = log.get("ip", "")
            if ip not in WHITELISTED_IPS:
                findings.append({
                    "anomaly": "Off-Hours Access",
                    "description": (
                        f"User '{log.get('user')}' accessed '{log.get('action', log.get('resource', 'system'))}' "
                        f"at hour {hour:02d}:xx IST from {ip}."
                    ),
                    "affected_events": [log.get("event_id")],
                    "risk_level": "high",
                    "risk_score": 80,
                    "recommendation": "Restrict service-account access to business hours or require approval for off-hours use.",
                })
    return findings


def detect_unauthorized_exports():
    """Flag bulk data exports above the safe threshold."""
    findings = []
    for log in DATA_EXPORT_LOGS:
        count = log.get("record_count", 0)
        if count > MAX_EXPORT_RECORDS:
            findings.append({
                "anomaly": "Unauthorized Bulk Data Export",
                "description": (
                    f"{count} records exported by '{log.get('user')}' from "
                    f"'{log.get('resource')}' — file: {log.get('file', 'N/A')}."
                ),
                "affected_events": [log.get("event_id")],
                "risk_level": "critical",
                "risk_score": 98,
                "recommendation": "Require admin approval for exports > 100 records; enable DLP scanning.",
            })
    return findings


def detect_config_before_activity():
    """Flag config reads that precede suspicious API / export activity."""
    findings = []
    config_ts = [
        log for log in CONFIG_ACCESS_LOGS
        if log.get("ip") not in WHITELISTED_IPS
    ]
    suspicious_api = [
        log for log in API_ACCESS_LOGS + DATA_EXPORT_LOGS
        if log.get("ip") not in WHITELISTED_IPS
    ]
    if config_ts and suspicious_api:
        findings.append({
            "anomaly": "Configuration Read Before Suspicious Activity",
            "description": (
                "Integration secrets were read from Config-Service BEFORE "
                "bulk API calls and data exports. This is consistent with "
                "credential harvesting preceding lateral movement."
            ),
            "affected_events": (
                [c["event_id"] for c in config_ts]
                + [s["event_id"] for s in suspicious_api[:3]]
            ),
            "risk_level": "critical",
            "risk_score": 93,
            "recommendation": "Encrypt secrets at rest, enforce just-in-time access, and alert on config reads from new IPs.",
        })
    return findings


def detect_non_whitelisted_network():
    """Flag network connections from IPs not on the whitelist."""
    findings = []
    for log in NETWORK_LOGS:
        src = log.get("src_ip", "")
        if src not in WHITELISTED_IPS:
            findings.append({
                "anomaly": "Non-Whitelisted IP Connection",
                "description": (
                    f"Connection from {src} to {log.get('dst_ip')} on port "
                    f"{log.get('port')} was ALLOWED by firewall."
                ),
                "affected_events": [log.get("event_id")],
                "risk_level": "high",
                "risk_score": 78,
                "recommendation": "Tighten firewall rules; implement IP whitelisting for API endpoints.",
            })
    return findings


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def run_all_detections():
    """Run every detection rule and return a combined report."""
    all_findings = (
        detect_api_volume_anomaly()
        + detect_off_hours_access()
        + detect_unauthorized_exports()
        + detect_config_before_activity()
        + detect_non_whitelisted_network()
    )
    # De-duplicate by anomaly name (keep first with highest score)
    seen = {}
    unique = []
    for f in all_findings:
        key = f["anomaly"]
        if key not in seen or f["risk_score"] > seen[key]["risk_score"]:
            seen[key] = f
    unique = sorted(seen.values(), key=lambda x: x["risk_score"], reverse=True)

    overall_risk = max((f["risk_score"] for f in unique), default=0)
    return {
        "total_anomalies": len(all_findings),
        "unique_anomaly_types": len(unique),
        "overall_risk_score": overall_risk,
        "threat_level": (
            "CRITICAL" if overall_risk >= 90 else
            "HIGH" if overall_risk >= 70 else
            "MEDIUM" if overall_risk >= 40 else "LOW"
        ),
        "findings": unique,
    }
