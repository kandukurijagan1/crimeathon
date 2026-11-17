"""
app.py — Sentrix Shield: Security Monitoring & Incident Response Platform
=========================================================================
Flask backend for the CRIMEATHON'26 hackathon.
All data is SYNTHETIC / SIMULATED — clearly labelled.
Run:  python app.py
"""

import os
import uuid
import io
import csv
import ipaddress
from functools import wraps
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS

# --- internal modules -------------------------------------------------------
from data.logs import get_all_logs, get_logs_by_category
from data.evidence import EVIDENCE_CATALOG, get_evidence_by_id, get_evidence_summary
from data.loader import get_evidence_inventory, load_raw_evidence_file
from analysis.anomaly import run_all_detections
from analysis.timeline import get_timeline, get_timeline_summary

# --- Flask app ---------------------------------------------------------------
app = Flask(__name__, static_folder="static")

# Explicit CORS origin configuration — no wildcards
TRUSTED_ORIGINS = [
    "http://127.0.0.1:5000",
    "http://localhost:5000"
]
CORS(app, resources={r"/api/*": {"origins": TRUSTED_ORIGINS}})

IST = timezone(timedelta(hours=5, minutes=30))

# --- Security Configuration & Role-Based Access Control (RBAC) ---------------
VALID_API_TOKENS = {
    os.environ.get("SENTRIX_ADMIN_TOKEN", "sentrix-admin-token-2026-auth"): {
        "role": "admin",
        "username": "soc_admin",
        "description": "Full SOC Administrator Access"
    },
    os.environ.get("SENTRIX_ANALYST_TOKEN", "sentrix-analyst-token-2026-auth"): {
        "role": "analyst",
        "username": "soc_analyst",
        "description": "SOC Security Analyst Access"
    }
}

# Documented Internal Networks from Case Dossier E01, E05, E07, E08, E09
CONFIGURED_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.10.4.0/24"),      # Vendor integration connector subnet (E05, E09)
    ipaddress.ip_network("198.51.100.0/24"),   # Staff & Finance management subnet (E01, E04, E07)
    ipaddress.ip_network("10.10.8.0/24"),      # Support technician internal subnet (E01)
    ipaddress.ip_network("127.0.0.0/8")        # Local loopback interface
]
APPROVED_CONNECTOR_HOST = ipaddress.ip_address("10.10.4.12")

# Server-Side Role-Based Endpoint Access Matrix
SERVER_RBAC_RULES = {
    "attendance.read": {
        "allowed_endpoints": ["/v1/attendance"],
        "description": "Hardened connector role: restricted solely to reading attendance records"
    },
    "learner.search": {
        "allowed_endpoints": ["/v1/attendance", "/v1/learners/search", "/v1/courses"],
        "description": "Standard staff portal role: attendance, learner queries, courses"
    },
    "learner.export": {
        "allowed_endpoints": ["/v1/attendance", "/v1/learners/search", "/v1/learners/export", "/v1/courses"],
        "description": "Elevated export role: requires dual approval for records > 100"
    },
    "admin": {
        "allowed_endpoints": ["/v1/attendance", "/v1/learners/search", "/v1/learners/export", "/v1/courses", "/v1/config"],
        "description": "System administrator: full endpoint access"
    }
}


def get_authenticated_user():
    """Extract and validate bearer token or X-API-Key from request headers."""
    auth_header = request.headers.get("Authorization", "").strip()
    api_key_header = request.headers.get("X-API-Key", "").strip()
    
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif api_key_header:
        token = api_key_header
        
    if not token:
        return None
        
    return VALID_API_TOKENS.get(token)


def require_auth(f):
    """Decorator requiring a valid authentication token for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_authenticated_user()
        if not user:
            return jsonify({
                "status": "error",
                "error": "UNAUTHORIZED",
                "message": "Authentication required: Provide a valid Bearer token in the 'Authorization' header or 'X-API-Key'.",
                "http_code": 401
            }), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function


def require_role(*required_roles):
    """Decorator requiring specific role membership (e.g. 'admin')."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_authenticated_user()
            if not user:
                return jsonify({
                    "status": "error",
                    "error": "UNAUTHORIZED",
                    "message": "Authentication required: Provide a valid Bearer token in the 'Authorization' header or 'X-API-Key'.",
                    "http_code": 401
                }), 401
            if user.get("role") not in required_roles:
                return jsonify({
                    "status": "error",
                    "error": "FORBIDDEN",
                    "message": f"Insufficient privileges: Required role(s): {', '.join(required_roles)}, but authenticated as '{user.get('role')}'.",
                    "http_code": 403
                }), 403
            request.current_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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
        "scoring_methodology": "Heuristic Severity Rating (0–100, measures policy impact, not compromise probability)",
        "evidence_items": len(EVIDENCE_CATALOG),
        "data_records_exposed": 2300,
        "credential_created_date": "2026-03-04",
        "credential_age_months": 7,
        "compromised_key_id": "rc-prod-01",
        "compromised_identity": "svc_rollcall",
        "external_ip": "203.0.113.77",
        "summary": (
            "Northstar Skills Academy experienced an unauthorized data exfiltration incident "
            "on 12 Oct 2026. The 'svc_rollcall' integration credential (rc-prod-01) was active "
            "for approx. 7 months (created 2026-03-04) with no expiry date, no rotation schedule, "
            "and no IP restriction. It was used from external IP 203.0.113.77 to read config (CHG-882), "
            "execute bulk queries (R003/P003), trigger an export job (R004/P004), and download 2,300 "
            "learner records twice from CampusVault (C003/C004)."
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
            "alert_id": f.get("finding_id", f"ALT-{i:03d}"),
            "type": f.get("anomaly", ""),
            "risk_level": f.get("severity", f.get("risk_level", "HIGH")),
            "risk_score": f.get("heuristic_score", f.get("risk_score", 80)),
            "heuristic_score": f.get("heuristic_score", f.get("risk_score", 80)),
            "description": f.get("reason_for_flagging", f.get("description", "")),
            "recommendation": f.get("recommended_defensive_action", f.get("recommendation", "")),
            "affected_events": f.get("event_ids", f.get("affected_events", [])),
            "confidence_classification": f.get("confidence_classification", "CONFIRMED OBSERVATION"),
            "source_evidence_file": f.get("source_evidence_file", ""),
            "timestamp": f.get("timestamp", ""),
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
            "title": "Credential Rotation & Lifetime Policy",
            "priority": "critical",
            "description": "Enforce automatic credential rotation every 90 days for all service accounts.",
            "current_state": "No rotation schedule — svc_rollcall (rc-prod-01) active approx. 7 months with 'expires: never' (E05 INT-01).",
            "recommendation": "Deploy automated secret manager (e.g., HashiCorp Vault) with 90-day max TTL.",
            "evidence_refs": ["E05", "E08", "E12"],
        },
        {
            "id": "POL-002",
            "title": "Certificate & Token Authentication Security",
            "priority": "critical",
            "description": "Require mutual TLS or short-lived signed tokens for non-human identities.",
            "current_state": "Static unexpiring API token used over public internet without mTLS or certificate pinning.",
            "recommendation": "Implement mTLS or OAuth2 client-credentials with short-lived tokens and device binding.",
            "evidence_refs": ["E01", "E05"],
        },
        {
            "id": "POL-003",
            "title": "Least-Privilege Role Authorization",
            "priority": "critical",
            "description": "Service accounts must have only the minimal permissions required for their operational purpose.",
            "current_state": "svc_rollcall assigned 'learner.export' and 'learner.search' — only 'attendance.read' was required.",
            "recommendation": "De-scope integration credentials strictly to attendance.read; revoke learner.export and learner.search.",
            "evidence_refs": ["E02", "E05", "E08"],
        },
        {
            "id": "POL-004",
            "title": "API Gateway Rate Limiting & Velocity Controls",
            "priority": "high",
            "description": "Enforce per-identity, per-IP rate limits on all public and internal APIs.",
            "current_state": "No rate limiting — 4,642 total records traversed in under 3 minutes (R003, R004, R006).",
            "recommendation": "Set 20 req/min per service account with progressive back-off and SIEM alerting.",
            "evidence_refs": ["E03", "E08"],
        },
        {
            "id": "POL-005",
            "title": "Source IP Allowlisting & Network Isolation",
            "priority": "critical",
            "description": "Restrict API and connector ingress strictly to documented internal subnets.",
            "current_state": "Register INT-01 had 'ip_restriction: not configured', allowing requests from external IP 203.0.113.77.",
            "recommendation": "Implement strict firewall and gateway allowlisting restricted to internal connector node 10.10.4.12.",
            "evidence_refs": ["E05", "E09"],
        },
        {
            "id": "POL-006",
            "title": "Real-Time SIEM Anomaly Correlation",
            "priority": "critical",
            "description": "Configure real-time alerts for bulk exports, off-hours access, and off-subnet requests.",
            "current_state": "No real-time alerting — incident discovered hours later by Finance (HD-1069).",
            "recommendation": "Deploy SIEM correlation rules with sub-second alerting for off-subnet service token usage.",
            "evidence_refs": ["E06", "E08", "E11"],
        },
        {
            "id": "POL-007",
            "title": "Bulk Export Approval & DLP Screening",
            "priority": "critical",
            "description": "Require dual-authorization and DLP screening for bulk exports exceeding 100 records.",
            "current_state": "No approval workflow — 2,300 learner profiles exported and downloaded twice from CampusVault (C003, C004).",
            "recommendation": "Enforce record-count ceiling (max 100) and dual-manager approval workflow for bulk exports.",
            "evidence_refs": ["E04", "E08"],
        },
        {
            "id": "POL-008",
            "title": "Configuration Protection & Secret Segregation",
            "priority": "high",
            "description": "Prevent exposure of credentials in tickets or configuration read events.",
            "current_state": "Screenshot listed in ticket archive (HD-1058); integration settings read from external IP (CHG-882).",
            "recommendation": "Encrypt secrets at rest; redact sensitive keys in tickets; alert on configuration reads from non-standard IPs.",
            "evidence_refs": ["E06", "E08", "E11"],
        },
    ]
    return jsonify({
        "status": "simulated",
        "total_policies": len(policy_list),
        "policies": policy_list,
    })


# ----- Attack Simulation -----------------------------------------------------
@app.route("/api/simulate", methods=["POST"])
@require_auth
def simulate():
    sim_id = str(uuid.uuid4())[:8]
    body = request.get_json(silent=True) or {}
    scenario = body.get("scenario", "credential-exposure")

    # Observed events strictly mapped to authentic E01-E12 telemetry vs hypothetical simulation
    steps = [
        {
            "step": 1,
            "type": "CONFIRMED_OBSERVATION",
            "event_ids": ["A011", "N001"],
            "evidence_refs": ["E01", "E09"],
            "action": "External service token authentication (Event A011 from 203.0.113.77)",
            "result": "ACCEPTED — Static token rc-prod-01 accepted; INT-01 lacked IP restriction",
            "risk": "critical",
            "notes": "Direct observation: Service identity svc_rollcall authenticated from unwhitelisted external IP."
        },
        {
            "step": 2,
            "type": "CONFIRMED_OBSERVATION",
            "event_ids": ["CHG-882"],
            "evidence_refs": ["E11"],
            "action": "Integration settings read from external IP (Event CHG-882 at 03:16:35 IST)",
            "result": "CONFIG ACCESSED — Resource read logged; plaintext secret exposure unverified in evidence",
            "risk": "critical",
            "notes": "Direct observation: Settings resource read logged. Visual secret exposure remains unproven."
        },
        {
            "step": 3,
            "type": "CONFIRMED_OBSERVATION",
            "event_ids": ["P003", "R003"],
            "evidence_refs": ["E02", "E03"],
            "action": "Mass learner query via API gateway (Events P003/R003 returning 2,300 records)",
            "result": "QUERY COMPLETED — 2,300 records returned; no gateway rate limits triggered",
            "risk": "critical",
            "notes": "Direct observation: Broad enumeration query executed without velocity or threshold controls."
        },
        {
            "step": 4,
            "type": "CONFIRMED_OBSERVATION",
            "event_ids": ["P004", "R004", "CHG-883"],
            "evidence_refs": ["E02", "E03", "E11"],
            "action": "API export job creation (Events R004/P004 generating learners-20261012.csv)",
            "result": "EXPORT JOB CREATED — Generated 486,200-byte archive in CampusVault (Event CHG-883)",
            "risk": "critical",
            "notes": "Direct observation: Distinguishes API export job creation from subsequent storage download."
        },
        {
            "step": 5,
            "type": "CONFIRMED_OBSERVATION",
            "event_ids": ["C003", "C004"],
            "evidence_refs": ["E04"],
            "action": "CampusVault archive downloads (Events C003 at 03:21:03 & C004 at 03:24:48)",
            "result": "DOWNLOADED TWICE — 486,200 bytes transferred per event to external host 203.0.113.77",
            "risk": "critical",
            "notes": "Direct observation: Repeated file exfiltration to external destination without egress DLP."
        },
        {
            "step": 6,
            "type": "HYPOTHETICAL_SIMULATION",
            "event_ids": ["HD-1058", "SIM-HYP"],
            "evidence_refs": ["E06", "E12"],
            "action": "[HYPOTHETICAL] Pre-incident credential exposure opportunity",
            "result": "UNVERIFIED MECHANISM — Screenshot attached in ticket HD-1058; actual leak vector unknown",
            "risk": "medium",
            "notes": "Hypothetical reconstruction only: Case dossier does not provide screenshot contents."
        }
    ]

    controls_tested = [
        {"control": "Source IP Allowlisting (Rule 4: Restrict to 10.10.4.12)", "baseline_status": "FAIL", "hardened_status": "PASS"},
        {"control": "Least-Privilege Scoping (Rule 2: Restrict to attendance.read)", "baseline_status": "FAIL", "hardened_status": "PASS"},
        {"control": "Bulk Export Record Ceiling (Rule 5: Cap at 100 records + approval)", "baseline_status": "FAIL", "hardened_status": "PASS"},
        {"control": "Credential Rotation & TTL (Rule 3: 90-day Vault TTL)", "baseline_status": "FAIL", "hardened_status": "PASS"},
        {"control": "API Velocity Controls (Rule 6: 20 req/min limit)", "baseline_status": "FAIL", "hardened_status": "PASS"},
        {"control": "Real-Time SIEM Alerting (Sub-second off-subnet alert)", "baseline_status": "FAIL", "hardened_status": "PASS"},
    ]

    return jsonify({
        "status": "simulated",
        "simulation_id": sim_id,
        "scenario": scenario,
        "operator": request.current_user["username"],
        "timestamp": datetime.now(IST).isoformat(),
        "result": "VULNERABLE_BASELINE_BREACH_REPLICATED",
        "simulation_label": "HYPOTHETICAL ATTACK RECONSTRUCTION & DEFENSE TEST",
        "steps": steps,
        "controls_tested": controls_tested,
        "controls_passed_under_hardened": len(controls_tested),
        "controls_failed_under_vulnerable": len(controls_tested),
        "overall_verdict": (
            "Under the vulnerable baseline, all security controls failed to prevent unauthorized access. "
            "Under SENTRIX SHIELD's Zero-Trust controls, the attack is intercepted at Step 1 (IP Allowlist drop) "
            "and Step 4 (Export Role Boundary / Record Limit Ceiling)."
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


# ----- Evidence Integrity & Hashes (Dynamic Loader) --------------------------
@app.route("/api/evidence/integrity")
def evidence_integrity():
    """Returns SHA-256 integrity hashes, file sizes, and verification status for E01-E12."""
    inv = get_evidence_inventory()
    all_verified = all(item["exists"] and item["status"] == "VERIFIED_INTACT" for item in inv)
    return jsonify({
        "status": "verified" if all_verified else "degraded",
        "verified_intact": all_verified,
        "total_files": len(inv),
        "inventory": inv
    })


@app.route("/api/evidence/raw/<eid>")
def evidence_raw(eid):
    """Safely retrieves raw contents of an evidence file for forensic inspection."""
    data, err = load_raw_evidence_file(eid)
    if err:
        return jsonify({"error": err}), 404
    return jsonify({
        "status": "success",
        "evidence_id": data["evidence_id"],
        "filename": data["filename"],
        "sha256": data["sha256"],
        "size_bytes": data["size_bytes"],
        "content": data["content"]
    })


# ----- Credential Audit -------------------------------------------------------
@app.route("/api/credential-audit")
def credential_audit():
    audit_data = {
        "status": "simulated",
        "audit_date": "2026-10-12T12:00:00+05:30",
        "scoring_methodology": "Heuristic Severity Rating (0–100, measures policy impact, not compromise probability)",
        "accounts_reviewed": 5,
        "accounts": [
            {
                "account": "svc_rollcall",
                "client_id": "rollcall-prod",
                "api_key_id": "rc-prod-01",
                "type": "service",
                "created": "2026-03-04",
                "age_months": 7,
                "expires": "never",
                "ip_restriction": "not configured",
                "mfa_enabled": False,
                "permissions": ["attendance.read", "learner.search", "learner.export", "course.read"],
                "compliant": False,
                "issues": [
                    "Created 2026-03-04 (~7 months active) with no scheduled rotation (E05 INT-01)",
                    "No expiration configured (expires: never)",
                    "Excessive permissions: 'learner.export' granted to an attendance sync connector",
                    "No source IP restriction configured (allowed connection from 203.0.113.77)",
                ],
                "heuristic_score": 95,
            },
            {
                "account": "former.ajay",
                "person_id": "EMP-004",
                "role": "Former Support Technician",
                "type": "former-staff",
                "departure_date": "2026-09-30",
                "last_auth": "2026-10-09T09:13:44+05:30",
                "compliant": False,
                "issues": [
                    "Account remained active post-departure (authenticated on 2026-10-09)",
                    "Direct violation of NS-SEC-04 Rule 7 (former staff deprovisioning)",
                    "Note: Demonstrates identity offboarding flaw; does not establish responsibility for external RollCall incident",
                ],
                "heuristic_score": 75,
            },
            {
                "account": "ananya.r",
                "person_id": "EMP-001",
                "role": "IT Operations Analyst",
                "type": "human",
                "created": "2025-01-15",
                "mfa_enabled": True,
                "compliant": True,
                "issues": [],
                "heuristic_score": 15,
            },
            {
                "account": "rahul.k",
                "person_id": "EMP-002",
                "role": "IT Administrator",
                "type": "human",
                "created": "2024-06-01",
                "mfa_enabled": True,
                "compliant": True,
                "issues": [],
                "heuristic_score": 10,
            },
            {
                "account": "meera.s",
                "person_id": "EMP-003",
                "role": "Finance Analyst",
                "type": "human",
                "created": "2025-04-10",
                "mfa_enabled": True,
                "compliant": True,
                "issues": [],
                "heuristic_score": 10,
            },
        ],
        "summary": {
            "compliant": 3,
            "non_compliant": 2,
            "critical_risk": 1,
            "high_risk": 1,
            "recommendation": (
                "Immediately rotate svc_rollcall credential (INT-01), enforce strict 90-day TTL, "
                "restrict source IP to 10.10.4.12, de-scope permissions to attendance.read, "
                "and audit HR offboarding hooks to prevent former employee accounts from persisting."
            ),
        },
    }
    return jsonify(audit_data)


# ----- Credential Rotation (Simulated Demonstration) -------------------------
@app.route("/api/rotate-credential", methods=["POST"])
@require_role("admin")
def rotate_credential():
    if not request.is_json:
        return jsonify({"error": "BAD_REQUEST", "message": "Request body must be valid JSON"}), 400

    body = request.get_json(silent=True) or {}
    account = body.get("account", "svc_rollcall")
    if not isinstance(account, str) or not account.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "BAD_REQUEST", "message": "Field 'account' must be a valid alphanumeric identifier"}), 400

    new_id = str(uuid.uuid4())[:12]
    return jsonify({
        "status": "SIMULATED_DEMONSTRATION",
        "simulation_mode": True,
        "account": account,
        "action": "SIMULATED_CREDENTIAL_ROTATION",
        "mock_new_credential_id": f"cred-sim-{new_id}",
        "rotated_at": datetime.now(IST).isoformat(),
        "policy_rotation_interval": "90 days",
        "authenticated_operator": request.current_user["username"],
        "notice": (
            "SIMULATION ONLY: No live HashiCorp Vault or production secrets manager is connected. "
            "This response demonstrates the SOP workflow and parameter specification required for automated credential rotation."
        )
    })


# ----- Anomaly Detection Results ----------------------------------------------
@app.route("/api/anomaly-detection")
def anomaly_detection():
    report = run_all_detections()
    report["status"] = "simulated"
    return jsonify(report)


# ----- Advanced Interactive Defense Tools ------------------------------------
@app.route("/api/test-ip", methods=["POST"])
def test_ip():
    if not request.is_json:
        return jsonify({"error": "BAD_REQUEST", "message": "Request body must be valid JSON"}), 400

    body = request.get_json(silent=True) or {}
    ip_raw = body.get("ip")
    if not ip_raw or not isinstance(ip_raw, str):
        return jsonify({"error": "BAD_REQUEST", "message": "Field 'ip' is required and must be a valid IP string"}), 400
        
    ip_str = ip_raw.strip()
    try:
        target_ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return jsonify({
            "error": "INVALID_IP_FORMAT",
            "message": f"'{ip_str}' is not a valid IPv4 or IPv6 address per RFC standards.",
            "http_code": 400
        }), 400
        
    # Rigorous check against configured internal subnets
    matched_network = next((net for net in CONFIGURED_INTERNAL_NETWORKS if target_ip in net), None)
    
    if matched_network:
        return jsonify({
            "ip": str(target_ip),
            "status": "ALLOWED",
            "action": "PERMIT_INGRESS",
            "rule": "RULE-FW-ALLOW-INTERNAL",
            "matched_network": str(matched_network),
            "reason": f"IP {target_ip} falls within configured authorized network {matched_network}.",
            "risk_score": 0
        })
    else:
        return jsonify({
            "ip": str(target_ip),
            "status": "BLOCKED",
            "action": "DROP_AND_SIEM_ALERT",
            "rule": "RULE-FW-DROP-EXTERNAL",
            "reason": f"IP {target_ip} does not match any configured authorized internal network. Zero-Trust perimeter drops inbound traffic.",
            "risk_score": 95,
            "siem_alert": "ALT-NET-09: Unauthorized ingress attempt from unwhitelisted source address"
        })


@app.route("/api/test-role", methods=["POST"])
def test_role():
    if not request.is_json:
        return jsonify({"error": "BAD_REQUEST", "message": "Request body must be valid JSON"}), 400

    body = request.get_json(silent=True) or {}
    role = body.get("role")
    endpoint = body.get("endpoint")
    
    if not role or not isinstance(role, str):
        return jsonify({"error": "BAD_REQUEST", "message": "Field 'role' is required"}), 400
    if not endpoint or not isinstance(endpoint, str):
        return jsonify({"error": "BAD_REQUEST", "message": "Field 'endpoint' is required"}), 400

    role = role.strip()
    endpoint = endpoint.strip()

    if role not in SERVER_RBAC_RULES:
        return jsonify({
            "error": "INVALID_ROLE",
            "message": f"Role '{role}' is unrecognized. Valid roles: {list(SERVER_RBAC_RULES.keys())}"
        }), 400
        
    rule_info = SERVER_RBAC_RULES[role]
    permitted = endpoint in rule_info["allowed_endpoints"]
    
    return jsonify({
        "role": role,
        "endpoint": endpoint,
        "status": "PERMITTED" if permitted else "DENIED_403",
        "http_code": 200 if permitted else 403,
        "role_description": rule_info["description"],
        "reason": (
            f"Role '{role}' is authorized to access '{endpoint}'."
            if permitted else
            f"Access denied: Endpoint '{endpoint}' requires elevated privileges beyond '{role}'. Principle of least privilege enforced."
        ),
        "hardened_enforced": True
    })


@app.route("/api/run-tests", methods=["POST"])
@require_role("admin", "analyst")
def run_tests_api():
    """Runs test assertions and returns structured JSON results for the frontend lab."""
    import subprocess, sys, re
    try:
        proc = subprocess.run([sys.executable, "run_tests.py"], capture_output=True, text=True, timeout=25)
        output = proc.stdout + proc.stderr
        
        # Strip ANSI escape sequences for accurate string counts
        clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
        passes = clean_output.count("[PASS]")
        fails = clean_output.count("[FAIL]")
        total = passes + fails
        
        return jsonify({
            "status": "completed",
            "exit_code": proc.returncode,
            "operator": request.current_user["username"],
            "total": total,
            "passed": passes,
            "failed": fails,
            "success_rate": f"{(passes / total * 100):.1f}%" if total > 0 else "100%",
            "raw_output": clean_output
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/export-report")
@require_auth
def export_report():
    """Generates complete forensic case report in JSON format."""
    anomaly_data = run_all_detections()
    timeline_data = get_timeline()
    
    report = {
        "report_id": f"REP-SENTRIX-{datetime.now(IST).strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.now(IST).isoformat(),
        "case_file": "NS-26-014 — The Northstar Learning Services Investigation",
        "institution": "Northstar Skills Academy Pvt. Ltd. (Chennai)",
        "track": "DEFENSE",
        "team": "SENTRIX (SIMATS)",
        "incident_date": "2026-10-12",
        "threat_level": anomaly_data["threat_level"],
        "overall_risk_score": anomaly_data["overall_risk_score"],
        "records_logged_in_export": 2300,
        "records_compromised": 2300,
        "records_logged_note": "2,300 learner records logged in export telemetry (P004/R004); exact unique individual count is not proven beyond the logged record count.",
        "exfiltration_size_bytes": 486200,
        "compromised_identity": "svc_rollcall (rc-prod-01)",
        "unauthorized_external_ip": "203.0.113.77",
        "external_attacker_ip": "203.0.113.77",
        "root_cause_summary": (
            "Service identity 'svc_rollcall' operated with unexpiring, unrotated credentials (~7 months active, "
            "created 2026-03-04 with expires: never), excessive permissions ('learner.export'), and unrestricted "
            "network ingress, enabling unauthorized external access and download from 203.0.113.77. API export job "
            "creation (R004/P004/CHG-883) produced a 486,200-byte archive in CampusVault, which was subsequently downloaded "
            "twice (C003, C004). Support ticket HD-1058 recorded a screenshot attachment, but its visual contents and "
            "the initial credential exposure mechanism remain unverified and unknown in the case evidence."
        ),
        "evidence_inventory": EVIDENCE_CATALOG,
        "incident_timeline": timeline_data,
        "anomaly_findings": anomaly_data["findings"],
        "defense_recommendations": [
            "Enforce mandatory 90-day automated credential rotation using HashiCorp Vault.",
            "Enforce zero-trust IP allowlisting restricting integration APIs to 10.10.4.12.",
            "De-scope service credentials to read-only attendance synchronization.",
            "Require dual-authorization and DLP screening on bulk data exports.",
            "Enforce immediate real-time SIEM alerting on off-subnet logins and off-hours config reads."
        ]
    }
    return jsonify(report)


@app.route("/api/export-report/csv")
@require_auth
def export_report_csv():
    """Generates complete forensic case findings and timeline as a downloadable CSV."""
    anomaly_data = run_all_detections()
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header section
    writer.writerow(["# SENTRIX SHIELD FORENSIC INVESTIGATION REPORT"])
    writer.writerow(["# Case", "NS-26-014 — The Northstar Learning Services Investigation"])
    writer.writerow(["# Track", "DEFENSE"])
    writer.writerow(["# Team", "SENTRIX (SIMATS)"])
    writer.writerow(["# Generated", datetime.now(IST).isoformat()])
    writer.writerow([])
    
    # Findings Table
    writer.writerow(["FINDING_ID", "ANOMALY", "SEVERITY", "HEURISTIC_SCORE", "CONFIDENCE_CLASSIFICATION", "TIMESTAMP_IST", "SOURCE_EVIDENCE", "EVENT_IDS", "RECOMMENDED_DEFENSE"])
    for f in anomaly_data["findings"]:
        writer.writerow([
            f.get("finding_id", ""),
            f.get("anomaly", ""),
            f.get("severity", ""),
            f.get("heuristic_score", 0),
            f.get("confidence_classification", ""),
            f.get("timestamp", ""),
            f.get("source_evidence_file", ""),
            "; ".join(f.get("event_ids", [])),
            f.get("recommended_defensive_action", "")
        ])
    
    writer.writerow([])
    # Timeline Table
    writer.writerow(["STEP", "TIMESTAMP_IST", "PHASE_TITLE", "CONFIRMATION_STATUS", "EVENT_IDS", "EVIDENCE_FILES", "MITRE_TECHNIQUE"])
    for s in get_timeline():
        writer.writerow([
            s.get("step", ""),
            s.get("timestamp", ""),
            s.get("title", ""),
            s.get("confirmation_status", ""),
            "; ".join(s.get("event_ids", [])),
            "; ".join(s.get("evidence_ids", [])),
            s.get("mitre_tactic", "")
        ])

    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentrix_shield_forensic_report.csv"}
    )


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
    app.run(host="0.0.0.0", port=5000, debug=False)
