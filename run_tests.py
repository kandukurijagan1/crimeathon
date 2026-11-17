#!/usr/bin/env python3
"""
run_tests.py — SENTRIX SHIELD Automated Verification Test Suite
==============================================================
CRIMEATHON'26 — Team SENTRIX (DEFENSE Track)
Case NS-26-014: The Northstar Learning Services Investigation

Runs complete verification across:
1. Local Mock API Hardened Gateway (5/5 security controls)
2. Anomaly Detection Engine (Heuristics & SIEM rules)
3. Incident Timeline Correlation Engine
4. Credential Lifecycle & Vault Management Engine
5. Flask REST API Integration Endpoints
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


def run_unit_tests():
    print(f"\n{BOLD}=== 1. ANOMALY DETECTION ENGINE TESTS ==={RESET}")
    from analysis.anomaly import (
        run_all_detections,
        detect_api_volume_anomaly,
        detect_off_hours_access,
        detect_unauthorized_exports,
        detect_config_before_activity,
        detect_non_whitelisted_network
    )

    report = run_all_detections()
    log_test("Total Anomalies Detected > 0", report["total_anomalies"] > 0, f"({report['total_anomalies']} found)")
    log_test("Threat Level Calculation", report["threat_level"] in ("HIGH", "CRITICAL"), f"(Threat Level: {report['threat_level']})")
    log_test("Overall Risk Score >= 80", report["overall_risk_score"] >= 80, f"(Score: {report['overall_risk_score']})")
    
    vol = detect_api_volume_anomaly()
    log_test("Rule: Excessive API Velocity", len(vol) > 0, f"({len(vol)} rule triggers)")

    off = detect_off_hours_access()
    log_test("Rule: Off-Hours Inbound Access", len(off) > 0, f"({len(off)} triggers)")

    exp = detect_unauthorized_exports()
    log_test("Rule: Unauthorized Bulk Data Export", len(exp) > 0, f"({len(exp)} triggers)")

    cfg = detect_config_before_activity()
    log_test("Rule: Config Read Preceding API Spike", len(cfg) > 0, f"({len(cfg)} triggers)")

    net = detect_non_whitelisted_network()
    log_test("Rule: Non-Whitelisted Perimeter Ingress", len(net) > 0, f"({len(net)} triggers)")


def run_timeline_tests():
    print(f"\n{BOLD}=== 2. TIMELINE CORRELATION ENGINE TESTS ==={RESET}")
    from analysis.timeline import get_timeline, get_timeline_summary

    tl = get_timeline()
    log_test("Timeline Event Count >= 8", len(tl) >= 8, f"({len(tl)} phases correlated)")
    log_test("Chronological Step Continuity", all(tl[i]["step"] == i + 1 for i in range(len(tl))))
    
    phases = [item["phase"] for item in tl]
    log_test("Pre-Incident Exposure Phase Present", "Pre-Incident Exposure" in phases)
    log_test("Exfiltration Phase Present", any("Exfiltration" in p for p in phases))
    
    summary = get_timeline_summary()
    log_test("Timeline Summary Serialization", len(summary) == len(tl))


def run_evidence_tests():
    print(f"\n{BOLD}=== 3. EVIDENCE DOSSIER CATALOG TESTS ==={RESET}")
    from data.evidence import get_all_evidence, get_evidence_by_id, get_evidence_summary

    ev = get_all_evidence()
    log_test("Official Evidence Count == 12", len(ev) == 12, f"({len(ev)} files mapped E01-E12)")
    
    e01 = get_evidence_by_id("E01")
    log_test("Evidence E01 Lookup", e01 is not None and "Authentication" in e01["title"])

    e04 = get_evidence_by_id("E04")
    log_test("Evidence E04 (CampusVault Exfiltration) Lookup", e04 is not None and e04["severity"] == "critical")

    summary = get_evidence_summary()
    log_test("Evidence Summary Counts", summary["critical"] >= 5, f"({summary['critical']} Critical, {summary['high']} High)")


def run_hardened_mock_api_tests():
    print(f"\n{BOLD}=== 4. LOCAL SAFE SIMULATION (HARDENED GATEWAY) TESTS ==={RESET}")
    sim_dir = Path(__file__).resolve().parent / "FULL PACK" / "SAFE_SIMULATION"
    if not (sim_dir / "mock_api_server.py").exists():
        log_test("Mock API Server File Exists", False, "Missing mock_api_server.py")
        return

    # Start mock server in background
    proc = subprocess.Popen(
        [sys.executable, "mock_api_server.py", "--mode", "hardened", "--port", "8799"],
        cwd=str(sim_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)

    try:
        import urllib.request, urllib.error
        base = "http://127.0.0.1:8799"
        token = "demo-rollcall-token"

        def call(path, method="GET", source="10.10.4.12", body=None, auth_token=token):
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(
                base + path,
                data=data,
                method=method,
                headers={
                    "Authorization": "Bearer " + auth_token,
                    "X-Simulated-Source-IP": source,
                    "Content-Type": "application/json"
                }
            )
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        status, _ = call("/v1/attendance")
        log_test("Rule 1: Authorized Attendance Allowed (200 OK)", status == 200, f"Got HTTP {status}")

        status, _ = call("/v1/learners/search")
        log_test("Rule 2: Learner Search Denied to Connector (403)", status == 403, f"Got HTTP {status}")

        status, _ = call("/v1/learners/export", "POST", body={"record_count": 2300})
        log_test("Rule 3: Bulk Export Exceeding Limit Denied (403)", status == 403, f"Got HTTP {status}")

        status, _ = call("/v1/attendance", source="203.0.113.77")
        log_test("Rule 4: Unapproved Source IP Blocked (403)", status == 403, f"Got HTTP {status}")

        status, _ = call("/v1/attendance", auth_token="revoked-token")
        log_test("Rule 5: Invalid/Revoked Token Denied (403)", status == 403, f"Got HTTP {status}")

    finally:
        proc.terminate()
        proc.wait()


def run_flask_api_tests():
    print(f"\n{BOLD}=== 5. SENTRIX SHIELD FLASK REST API TESTS ==={RESET}")
    import urllib.request
    
    endpoints = [
        ("/", "Frontend SPA HTML"),
        ("/api/dashboard", "Dashboard Telemetry"),
        ("/api/logs", "Security Logs Stream"),
        ("/api/alerts", "SIEM Real-Time Alerts"),
        ("/api/timeline", "Incident Chronology"),
        ("/api/policies", "Security Hardening Controls"),
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
    
    run_unit_tests()
    run_timeline_tests()
    run_evidence_tests()
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
