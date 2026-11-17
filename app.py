"""
app.py — Sentrix Shield: Security Monitoring & Incident Response Platform
=========================================================================
Flask backend for the CRIMEATHON'26 hackathon.
All data is SYNTHETIC / SIMULATED — clearly labelled.
Run:  python app.py
"""

import os
import uuid
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# --- internal modules -------------------------------------------------------
from data.logs import get_all_logs, get_logs_by_category
from data.evidence import EVIDENCE_CATALOG, get_evidence_by_id, get_evidence_summary
from analysis.anomaly import run_all_detections
from analysis.timeline import get_timeline, get_timeline_summary

# --- Flask app ---------------------------------------------------------------
app = Flask(__name__, static_folder="static")
CORS(app)

IST = timezone(timedelta(hours=5, minutes=30))

# =============================================================================
# Routes
# =============================================================================

# ----- Serve frontend --------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# ----- Dashboard summary -----------------------------------------------------
@app.route("/api/dashboard")
def dashboard():
    logs = get_all_logs()
    anomaly_report = run_all_detections()
    critical_count = sum(1 for l in logs if l.get("severity") == "critical")
    high_count = sum(1 for l in logs if l.get("severity") == "high")

    return jsonify({
        "status": "simulated",
        "generated_at": datetime.now(IST).isoformat(),
        "total_events": len(logs),
        "critical_events": critical_count,
        "high_events": high_count,
        "total_alerts": anomaly_report["total_anomalies"],
        "unique_anomaly_types": anomaly_report["unique_anomaly_types"],
        "overall_risk_score": anomaly_report["overall_risk_score"],
        "threat_level": anomaly_report["threat_level"],
        "evidence_items": len(EVIDENCE_CATALOG),
        "data_records_exposed": 2300,
        "credential_age_months": 14,
        "summary": (
            "Northstar Skills Academy experienced a credential-abuse incident "
            "on 12 Oct 2026. The 'svc-rollcall' service account was used from "
            "an external IP to harvest config secrets, make 300+ API calls, "
            "and export 2,300 learner records from CampusVault."
        ),
    })


# ----- Security Logs ---------------------------------------------------------
@app.route("/api/logs")
def logs():
    category = request.args.get("category")
    severity = request.args.get("severity")

    if category:
        by_cat = get_logs_by_category()
        data = by_cat.get(category, [])
    else:
        data = get_all_logs()

    if severity:
        data = [l for l in data if l.get("severity") == severity]

    return jsonify({
        "status": "simulated",
        "total": len(data),
        "logs": data,
    })


# ----- Alerts (derived from anomaly detection) --------------------------------
@app.route("/api/alerts")
def alerts():
    report = run_all_detections()
    alert_list = []
    for i, f in enumerate(report["findings"], start=1):
        alert_list.append({
            "alert_id": f"ALT-{i:03d}",
            "type": f["anomaly"],
            "risk_level": f["risk_level"],
            "risk_score": f["risk_score"],
            "description": f["description"],
            "recommendation": f["recommendation"],
            "affected_events": f["affected_events"],
        })
    return jsonify({
        "status": "simulated",
        "total_alerts": len(alert_list),
        "threat_level": report["threat_level"],
        "alerts": alert_list,
    })


# ----- Incident Timeline -----------------------------------------------------
@app.route("/api/timeline")
def timeline():
    detail = request.args.get("detail", "full")
    data = get_timeline() if detail == "full" else get_timeline_summary()
    return jsonify({
        "status": "simulated",
        "total_phases": len(data),
        "timeline": data,
    })


# ----- Security Policies / Recommendations -----------------------------------
@app.route("/api/policies")
def policies():
    policy_list = [
        {
            "id": "POL-001",
            "title": "Credential Rotation Policy",
            "priority": "critical",
            "description": "Enforce automatic credential rotation every 90 days for all service accounts.",
            "current_state": "No rotation policy — svc-rollcall credential was 14 months old.",
            "recommendation": "Deploy automated secret manager (e.g., HashiCorp Vault) with 90-day max lifetime.",
            "evidence_refs": ["EV-007"],
        },
        {
            "id": "POL-002",
            "title": "MFA for Service Accounts",
            "priority": "critical",
            "description": "Require multi-factor or certificate-based authentication for all non-human identities.",
            "current_state": "No MFA on service accounts.",
            "recommendation": "Implement mutual TLS or OAuth2 client-credentials with short-lived tokens.",
            "evidence_refs": ["EV-006"],
        },
        {
            "id": "POL-003",
            "title": "Least-Privilege Access Control",
            "priority": "critical",
            "description": "Service accounts must have only the minimum permissions required.",
            "current_state": "svc-rollcall had read+write+export — only read-only sync was needed.",
            "recommendation": "Scope down to read-only attendance sync; remove export and config-write permissions.",
            "evidence_refs": ["EV-009"],
        },
        {
            "id": "POL-004",
            "title": "API Rate Limiting",
            "priority": "high",
            "description": "Enforce per-identity, per-IP rate limits on all public and internal APIs.",
            "current_state": "No rate limiting — 300+ calls in 10 minutes went unchallenged.",
            "recommendation": "Set 20 req/min per service account with progressive back-off and alerting.",
            "evidence_refs": ["EV-003"],
        },
        {
            "id": "POL-005",
            "title": "IP Whitelisting & Geo-Fencing",
            "priority": "high",
            "description": "Restrict API and admin access to known IP ranges.",
            "current_state": "Firewall allowed traffic from non-whitelisted 203.92.45.112.",
            "recommendation": "Implement strict allowlisting for service-account source IPs.",
            "evidence_refs": ["EV-008"],
        },
        {
            "id": "POL-006",
            "title": "Real-Time SIEM Alerting",
            "priority": "critical",
            "description": "Configure real-time alerts for bulk exports, off-hours access, and rate-limit breaches.",
            "current_state": "No real-time alerting — breach undetected for ~8 hours.",
            "recommendation": "Deploy SIEM rules with <5 min detection SLA for critical events.",
            "evidence_refs": ["EV-010"],
        },
        {
            "id": "POL-007",
            "title": "Data Export Approval Workflow",
            "priority": "high",
            "description": "Require admin approval for any bulk data export exceeding 100 records.",
            "current_state": "No approval workflow — 2,300 records exported without authorisation.",
            "recommendation": "Implement DLP policy requiring manager sign-off for large exports.",
            "evidence_refs": ["EV-004"],
        },
        {
            "id": "POL-008",
            "title": "Configuration Access Monitoring",
            "priority": "high",
            "description": "Alert on any read of integration secrets from non-standard sources.",
            "current_state": "Config reads from external IP were not flagged.",
            "recommendation": "Encrypt secrets at rest; log and alert on every access; use JIT secret delivery.",
            "evidence_refs": ["EV-002"],
        },
    ]
    return jsonify({
        "status": "simulated",
        "total_policies": len(policy_list),
        "policies": policy_list,
    })


# ----- Attack Simulation -----------------------------------------------------
@app.route("/api/simulate", methods=["POST"])
def simulate():
    sim_id = str(uuid.uuid4())[:8]
    body = request.get_json(silent=True) or {}
    scenario = body.get("scenario", "credential-exposure")

    steps = [
        {
            "step": 1,
            "action": "Authenticate with stale service credential",
            "result": "SUCCESS — no MFA, credential accepted",
            "risk": "critical",
        },
        {
            "step": 2,
            "action": "Read integration config (API keys & secrets)",
            "result": "SUCCESS — secrets exposed in plaintext",
            "risk": "critical",
        },
        {
            "step": 3,
            "action": "Burst 300+ attendance-sync API calls",
            "result": "SUCCESS — no rate limiting triggered",
            "risk": "critical",
        },
        {
            "step": 4,
            "action": "Bulk-export 2,300 learner records from CampusVault",
            "result": "SUCCESS — no approval workflow, no DLP alert",
            "risk": "critical",
        },
        {
            "step": 5,
            "action": "Download export file to external endpoint",
            "result": "SUCCESS — firewall allowed outbound transfer",
            "risk": "critical",
        },
    ]

    controls_tested = [
        {"control": "MFA on service accounts", "status": "FAIL"},
        {"control": "Credential rotation policy", "status": "FAIL"},
        {"control": "API rate limiting", "status": "FAIL"},
        {"control": "IP whitelisting", "status": "FAIL"},
        {"control": "Data export approval", "status": "FAIL"},
        {"control": "Real-time alerting", "status": "FAIL"},
        {"control": "Least-privilege access", "status": "FAIL"},
        {"control": "Config encryption at rest", "status": "FAIL"},
    ]

    return jsonify({
        "status": "simulated",
        "simulation_id": sim_id,
        "scenario": scenario,
        "timestamp": datetime.now(IST).isoformat(),
        "result": "BREACH_SUCCESSFUL",
        "steps": steps,
        "controls_tested": controls_tested,
        "controls_passed": 0,
        "controls_failed": len(controls_tested),
        "overall_verdict": (
            "All 8 security controls FAILED. The simulated attack replicated "
            "the full kill chain from credential abuse to data exfiltration "
            "without triggering any defensive alert."
        ),
    })


# ----- Evidence Catalog -------------------------------------------------------
@app.route("/api/evidence")
def evidence():
    eid = request.args.get("id")
    if eid:
        item = get_evidence_by_id(eid)
        if item:
            return jsonify({"status": "simulated", "evidence": item})
        return jsonify({"error": f"Evidence '{eid}' not found"}), 404
    return jsonify({
        "status": "simulated",
        "total": len(EVIDENCE_CATALOG),
        "evidence": EVIDENCE_CATALOG,
    })


# ----- Credential Audit -------------------------------------------------------
@app.route("/api/credential-audit")
def credential_audit():
    audit_data = {
        "status": "simulated",
        "audit_date": "2026-10-12T12:00:00+05:30",
        "accounts_reviewed": 5,
        "accounts": [
            {
                "account": "svc-rollcall",
                "type": "service",
                "created": "2025-02-10",
                "last_rotated": "2025-08-15",
                "age_months": 14,
                "mfa_enabled": False,
                "permissions": ["read", "write", "export"],
                "compliant": False,
                "issues": [
                    "Credential not rotated in 14 months",
                    "No MFA enforced",
                    "Excessive permissions (read+write+export)",
                    "No IP restriction on usage",
                ],
                "risk_score": 95,
            },
            {
                "account": "svc-campusvault",
                "type": "service",
                "created": "2025-05-20",
                "last_rotated": "2025-11-01",
                "age_months": 11,
                "mfa_enabled": False,
                "permissions": ["read", "write"],
                "compliant": False,
                "issues": [
                    "Credential not rotated in 11 months",
                    "No MFA enforced",
                ],
                "risk_score": 70,
            },
            {
                "account": "admin@northstar.edu.in",
                "type": "human",
                "created": "2024-01-15",
                "last_rotated": "2026-09-20",
                "age_months": 1,
                "mfa_enabled": True,
                "permissions": ["admin"],
                "compliant": True,
                "issues": [],
                "risk_score": 10,
            },
            {
                "account": "registrar@northstar.edu.in",
                "type": "human",
                "created": "2024-03-01",
                "last_rotated": "2026-08-10",
                "age_months": 2,
                "mfa_enabled": True,
                "permissions": ["read", "write"],
                "compliant": True,
                "issues": [],
                "risk_score": 15,
            },
            {
                "account": "svc-smtp-relay",
                "type": "service",
                "created": "2025-07-01",
                "last_rotated": "2026-01-15",
                "age_months": 9,
                "mfa_enabled": False,
                "permissions": ["send"],
                "compliant": False,
                "issues": [
                    "Credential not rotated in 9 months",
                    "No MFA enforced",
                ],
                "risk_score": 55,
            },
        ],
        "summary": {
            "compliant": 2,
            "non_compliant": 3,
            "critical_risk": 1,
            "high_risk": 1,
            "medium_risk": 1,
            "recommendation": (
                "Immediately rotate all service-account credentials. "
                "Enforce 90-day rotation policy and MFA / mTLS for non-human identities."
            ),
        },
    }
    return jsonify(audit_data)


# ----- Credential Rotation (Simulated) ----------------------------------------
@app.route("/api/rotate-credential", methods=["POST"])
def rotate_credential():
    body = request.get_json(silent=True) or {}
    account = body.get("account", "svc-rollcall")
    new_id = str(uuid.uuid4())[:12]
    return jsonify({
        "status": "simulated",
        "account": account,
        "action": "CREDENTIAL_ROTATED",
        "new_credential_id": f"cred-{new_id}",
        "rotated_at": datetime.now(IST).isoformat(),
        "next_rotation_due": "90 days",
        "message": (
            f"Credential for '{account}' has been rotated (simulated). "
            "Old credential revoked. New credential issued with 90-day expiry."
        ),
    })


# ----- Anomaly Detection Results ----------------------------------------------
@app.route("/api/anomaly-detection")
def anomaly_detection():
    report = run_all_detections()
    report["status"] = "simulated"
    return jsonify(report)


# =============================================================================
# Main
# =============================================================================
if __name__ == "__main__":
    # Ensure static folder exists (frontend will go here)
    os.makedirs("static", exist_ok=True)
    print("=" * 60)
    print("  SENTRIX SHIELD — Security Monitoring & Incident Response")
    print("  CRIMEATHON'26 Hackathon | Northstar Skills Academy")
    print("  All data is SYNTHETIC / SIMULATED")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
