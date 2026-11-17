#!/usr/bin/env python3
"""
run_tests.py — SENTRIX SHIELD Automated Verification Test Suite
==============================================================
CRIMEATHON'26 — Team SENTRIX (DEFENSE Track)
Case NS-26-014: The Northstar Learning Services Investigation

Runs comprehensive verification across:
1. Evidence Consistency & Ground-Truth Alignment (E01–E12)
2. Anomaly Detection Heuristic Engine
3. Timeline Correlation & Hypothesis Separation
4. Credential Lifecycle & Identity Governance (Audit & 7-Month Age Check)
5. Local Safe Simulation with ISOLATED Security Control Tests (Role, IP, Token & Export Record Limit)
6. Flask REST API Integration Endpoints
"""

import sys
import json
import time
import subprocess
from pathlib import Path

# Color styling for terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed_tests = 0
failed_tests = 0


def log_test(name: str, passed: bool, detail: str = ""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"  [{GREEN}PASS{RESET}] {name} {CYAN}{detail}{RESET}")
    else:
        failed_tests += 1
        print(f"  [{RED}FAIL{RESET}] {name} {YELLOW}{detail}{RESET}")


def run_evidence_consistency_tests():
    print(f"\n{BOLD}=== 1. EVIDENCE CONSISTENCY & GROUND-TRUTH ALIGNMENT ==={RESET}")
    from data.logs import (
        AUTH_LOGS,
        API_ACCESS_LOGS,
        CONFIG_ACCESS_LOGS,
        DATA_EXPORT_LOGS,
        NETWORK_LOGS,
        get_all_logs,
    )
    from data.evidence import get_all_evidence, get_evidence_by_id

    # 1. Verify authentic IP usage
    attacker_ips = {l.get("ip") for l in get_all_logs() if l.get("severity") == "critical" and "ip" in l}
    log_test("Official External IP Used (203.0.113.77)", "203.0.113.77" in attacker_ips)
    log_test("Invented IP (203.92.45.112) Excluded", not any("203.92.45.112" in str(l) for l in get_all_logs()))

    # 2. Verify authentic Service Account name
    identities = {l.get("user") for l in get_all_logs()}
    log_test("Service Account Identity 'svc_rollcall' Used", "svc_rollcall" in identities)
    log_test("Invented Identity 'svc-rollcall' Excluded", "svc-rollcall" not in identities)

    # 3. Verify authentic Event IDs
    event_ids = {l.get("event_id") for l in get_all_logs()}
    required_ids = {"A011", "R003", "R004", "CHG-882", "C003", "C004", "N001", "HD-1058", "A006"}
    log_test("Official Case Event IDs Mapped (A011, R004, C003, CHG-882, etc.)", required_ids.issubset(event_ids))
    log_test("Invented Prefix 'EVT-' Excluded", not any(eid.startswith("EVT-") for eid in event_ids if eid))

    # 4. Verify Former Staff offboarding anomaly
    ajay_events = [l for l in AUTH_LOGS if l.get("user") == "former.ajay"]
    log_test("Former Staff Governance Anomaly (A006 former.ajay) Included", len(ajay_events) > 0)

    # 5. Verify Evidence Dossier separation of confirmed vs hypothesis
    e06 = get_evidence_by_id("E06")
    log_test("E06 Classifies Screenshot Exposure as Hypothesis/Unverified", e06 is not None and "HYPOTHESIS" in e06.get("confirmation_status", ""))


def run_unit_tests():
    print(f"\n{BOLD}=== 2. HEURISTIC ANOMALY DETECTION ENGINE TESTS ==={RESET}")
    from analysis.anomaly import (
        run_all_detections,
        detect_unwhitelisted_external_ip,
        detect_off_hours_bulk_export,
        detect_config_read_preceding_abuse,
        detect_unusual_api_query_volume,
        detect_offboarding_governance_anomaly
    )

    report = run_all_detections()
    log_test("Heuristic Scoring Methodology Specified", "Heuristic Severity Rating" in report.get("scoring_type", ""))
    log_test("Threat Level Calculation", report["threat_level"] in ("HIGH", "CRITICAL"), f"(Threat Level: {report['threat_level']})")
    log_test("Overall Heuristic Score >= 90", report["overall_risk_score"] >= 90, f"(Score: {report['overall_risk_score']}/100)")
    
    rule1 = detect_unwhitelisted_external_ip()
    log_test("Rule 1: External Source IP for Service Identity", len(rule1) > 0, f"(Heuristic Score: {rule1[0]['heuristic_score']})")

    rule2 = detect_off_hours_bulk_export()
    log_test("Rule 2: Unauthorized Bulk Learner Profile Export", len(rule2) > 0, f"(Heuristic Score: {rule2[0]['heuristic_score']})")

    rule3 = detect_config_read_preceding_abuse()
    log_test("Rule 3: Integration Settings Read Prior to API Burst", len(rule3) > 0, f"(Heuristic Score: {rule3[0]['heuristic_score']})")

    rule4 = detect_unusual_api_query_volume()
    log_test("Rule 4: Anomalous Endpoint Traversal & Query Velocity", len(rule4) > 0, f"(Heuristic Score: {rule4[0]['heuristic_score']})")

    rule5 = detect_offboarding_governance_anomaly()
    log_test("Rule 5: Former Employee Account Active Post-Departure", len(rule5) > 0, f"(Heuristic Score: {rule5[0]['heuristic_score']})")


def run_timeline_tests():
    print(f"\n{BOLD}=== 3. TIMELINE CORRELATION & HYPOTHESIS SEPARATION TESTS ==={RESET}")
    from analysis.timeline import get_timeline, get_timeline_summary

    tl = get_timeline()
    log_test("Timeline Phase Count >= 10", len(tl) >= 10, f"({len(tl)} phases correlated)")
    log_test("Chronological Step Continuity", all(tl[i]["step"] == i + 1 for i in range(len(tl))))
    
    # Verify Phase 1 is labeled as hypothesis / unverified
    step1 = tl[0]
    log_test("Phase 1 Accurately Labeled as Hypothesis / Exposure Opportunity", "Hypothesis" in step1["title"] or "Opportunity" in step1["title"])
    log_test("Phase 1 Documents Unverified Screenshot Contents", "unverified" in step1["description"].lower())

    # Verify A006 former staff inclusion
    ajay_step = next((s for s in tl if "A006" in s.get("event_ids", [])), None)
    log_test("Timeline Identifies Former Staff Governance Defect (A006)", ajay_step is not None and "ajay" in ajay_step["description"].lower())

    # Verify Exfiltration phase
    exfil_step = next((s for s in tl if "Exfiltration" in s["title"] or "CampusVault" in s["title"]), None)
    log_test("Data Exfiltration Phase Correlated (C002-C004)", exfil_step is not None and "E04" in exfil_step["evidence_ids"])


def run_credential_audit_tests():
    print(f"\n{BOLD}=== 4. CREDENTIAL LIFECYCLE & IDENTITY AUDIT TESTS ==={RESET}")
    import urllib.request
    try:
        res = urllib.request.urlopen("http://127.0.0.1:5000/api/credential-audit", timeout=2)
        data = json.loads(res.read())
        accounts = {a["account"]: a for a in data.get("accounts", [])}
        
        rollcall = accounts.get("svc_rollcall")
        log_test("svc_rollcall Account Audited", rollcall is not None)
        log_test("Credential Age Approx. 7 Months (Created 2026-03-04)", rollcall is not None and rollcall.get("age_months") == 7)
        log_test("Identifies 'expires: never' Defect", rollcall is not None and rollcall.get("expires") == "never")
        log_test("Identifies 'ip_restriction: not configured' Defect", rollcall is not None and "not configured" in rollcall.get("ip_restriction", ""))
        
        ajay = accounts.get("former.ajay")
        log_test("Former Staff Offboarding Defect Audited (former.ajay)", ajay is not None and not ajay.get("compliant"))
    except Exception as e:
        log_test("Credential Audit API Available", False, str(e))


def run_hardened_mock_api_tests():
    print(f"\n{BOLD}=== 5. LOCAL SAFE SIMULATION (ISOLATED DEFENSE CONTROL TESTS) ==={RESET}")
    sim_dir = Path(__file__).resolve().parent / "FULL PACK" / "SAFE_SIMULATION"
    if not (sim_dir / "mock_api_server.py").exists():
        log_test("Mock API Server File Exists", False, "Missing mock_api_server.py")
        return

    # Start mock server in background on port 8798
    proc = subprocess.Popen(
        [sys.executable, "mock_api_server.py", "--mode", "hardened", "--port", "8798"],
        cwd=str(sim_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)

    try:
        import urllib.request, urllib.error
        base = "http://127.0.0.1:8798"
        token = "demo-rollcall-token"

        def call(path, method="GET", source="10.10.4.12", body=None, auth_token=token, role=None):
            data = None if body is None else json.dumps(body).encode()
            headers = {
                "Authorization": "Bearer " + auth_token,
                "X-Simulated-Source-IP": source,
                "Content-Type": "application/json"
            }
            if role:
                headers["X-Simulated-Role"] = role
            req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        # Test 1: Attendance allowed
        status, _ = call("/v1/attendance")
        log_test("Control 1: Authorized Attendance Allowed from 10.10.4.12 (HTTP 200)", status == 200, f"Got HTTP {status}")

        # Test 2: Role boundary - learner search
        status, _ = call("/v1/learners/search")
        log_test("Control 2 (Role Boundary): Learner Search Denied to Attendance Role (HTTP 403)", status == 403, f"Got HTTP {status}")

        # Test 3: Role boundary - bulk export
        status, _ = call("/v1/learners/export", "POST", body={"record_count": 2300})
        log_test("Control 3 (Role Boundary): Bulk Export Denied to Attendance Role (HTTP 403)", status == 403, f"Got HTTP {status}")

        # Test 4: Source IP allowlist
        status, _ = call("/v1/attendance", source="203.0.113.77")
        log_test("Control 4 (IP Whitelisting): Unapproved External IP 203.0.113.77 Denied (HTTP 403)", status == 403, f"Got HTTP {status}")

        # Test 5: Token authentication
        status, _ = call("/v1/attendance", auth_token="invalid-token")
        log_test("Control 5 (Authentication): Invalid Token Rejected (HTTP 403)", status == 403, f"Got HTTP {status}")

        # Test 6: ISOLATED EXPORT LIMIT TEST
        # Client has simulated authorized role 'learner.export', but requests 2,300 records exceeding limit of 100
        status, body = call("/v1/learners/export", "POST", body={"record_count": 2300}, role="learner.export")
        log_test("Control 6 (ISOLATED RECORD LIMIT): Export > 100 records blocked by record ceiling (HTTP 400)", status == 400, f"Got HTTP {status} ({body.get('error')})")

        # Test 7: ISOLATED EXPORT LIMIT TEST - Small authorized export permitted
        status, body = call("/v1/learners/export", "POST", body={"record_count": 50}, role="learner.export")
        log_test("Control 7 (ISOLATED RECORD LIMIT): Small export <= 100 records permitted for authorized role (HTTP 200)", status == 200, f"Got HTTP {status}")

    finally:
        proc.terminate()
        proc.wait()


def run_flask_api_tests():
    print(f"\n{BOLD}=== 6. SENTRIX SHIELD FLASK REST API INTEGRATION TESTS ==={RESET}")
    import urllib.request
    
    endpoints = [
        ("/", "Frontend SPA HTML"),
        ("/api/dashboard", "Dashboard Telemetry"),
        ("/api/logs", "Security Logs Stream"),
        ("/api/alerts", "SIEM Real-Time Alerts"),
        ("/api/timeline", "Incident Chronology"),
        ("/api/policies", "Security Hardening Policies"),
        ("/api/evidence", "Forensic Evidence Catalog"),
        ("/api/credential-audit", "Credential Lifecycle Audit"),
        ("/api/anomaly-detection", "Anomaly Engine Results"),
    ]

    for ep, desc in endpoints:
        try:
            res = urllib.request.urlopen(f"http://127.0.0.1:5000{ep}", timeout=2)
            log_test(f"GET {ep} ({desc})", res.status == 200, f"HTTP {res.status}")
        except Exception as e:
            log_test(f"GET {ep} ({desc})", False, str(e))

    # Test POST simulation
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:5000/api/simulate",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        res = urllib.request.urlopen(req, timeout=2)
        log_test("POST /api/simulate (Attack Simulation)", res.status == 200, f"HTTP {res.status}")
    except Exception as e:
        log_test("POST /api/simulate", False, str(e))

    # Test POST rotation
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:5000/api/rotate-credential",
            data=b"{\"account\": \"svc_rollcall\"}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        res = urllib.request.urlopen(req, timeout=2)
        log_test("POST /api/rotate-credential (Simulated Vault Rotation)", res.status == 200, f"HTTP {res.status}")
    except Exception as e:
        log_test("POST /api/rotate-credential", False, str(e))


def main():
    print(f"{BOLD}======================================================================{RESET}")
    print(f"{BOLD}   SENTRIX SHIELD — AUTOMATED VERIFICATION TEST RUNNER{RESET}")
    print(f"{BOLD}   CRIMEATHON'26 Selection Round | Track: DEFENSE | Team: SENTRIX{RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    
    run_evidence_consistency_tests()
    run_unit_tests()
    run_timeline_tests()
    run_credential_audit_tests()
    run_hardened_mock_api_tests()
    run_flask_api_tests()

    total = passed_tests + failed_tests
    print(f"\n{BOLD}======================================================================{RESET}")
    print(f"{BOLD}TEST RESULTS: {GREEN}{passed_tests} PASSED{RESET}, {RED if failed_tests else GREEN}{failed_tests} FAILED{RESET} (Total: {total}){RESET}")
    print(f"{BOLD}SUCCESS RATE: {GREEN}{100.0 * passed_tests / total:.1f}%{RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    sys.exit(0 if failed_tests == 0 else 1)


if __name__ == "__main__":
    main()
