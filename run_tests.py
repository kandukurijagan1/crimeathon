#!/usr/bin/env python3
"""
run_tests.py — SENTRIX SHIELD Comprehensive Automated Security Test Suite
========================================================================
CRIMEATHON'26 Selection Round | Track: DEFENSE | Team: SENTRIX (SIMATS)
Case NS-26-014: The Northstar Learning Services Investigation

Strictly tests:
 1. Loading all 12 evidence files E01–E12 and verifying file presence
 2. Event ID preservation and format validation
 3. Accurate timestamp chronological sorting (IST +05:30)
 4. External source IP detection (203.0.113.77) with no unsubstantiated human attribution
 5. Unusual API record-count detection (distinguishing export job from file downloads)
 6. Bulk learner export detection (P004/R004 -> learners-20261012.csv)
 7. Repeated cloud repository downloads detection (C003, C004)
 8. Missing credential expiration policy detection (INT-01 expires: never, ~7 months)
 9. Missing source IP restriction detection (INT-01 ip_restriction: not configured)
10. Former employee offboarding violation warning (A006 former.ajay on 09-Oct)
11. Evidence SHA-256 hash generation & integrity verification
12. Vulnerable API vs. Hardened API behavior comparison
13. Export approval enforcement (isolated record limit ceiling <= 100)
14. Unauthorized request rejection (IP drop, role restriction)
15. Incident investigation report generation (JSON and CSV)
16. Flask API Authentication Middleware (HTTP 401 Unauthenticated Rejection)
17. Server-Side Role-Based Access Control (HTTP 403 Forbidden on Privilege Violation)
18. Input Validation & Defense Verification (HTTP 400 on Invalid IP / Malformed Data)
19. Attack Simulation Ground Truth Alignment (No Unsupported Claims / Labeled Hypotheses)
20. Explicit CORS Origin Protection (No Unrestricted Wildcards)
"""

import sys
import json
import time
import subprocess
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path

# Terminal styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed_tests = 0
failed_tests = 0

ADMIN_TOKEN = "sentrix-admin-token-2026-auth"
ANALYST_TOKEN = "sentrix-analyst-token-2026-auth"


def log_test(name: str, passed: bool, detail: str = ""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"  [{GREEN}PASS{RESET}] {name} {CYAN}{detail}{RESET}")
    else:
        failed_tests += 1
        print(f"  [{RED}FAIL{RESET}] {name} {YELLOW}{detail}{RESET}")


def api_call(url, method="GET", headers=None, body=None, auth=True):
    """Helper to make HTTP calls to local Flask server."""
    req_headers = headers.copy() if headers else {}
    if auth and "Authorization" not in req_headers:
        req_headers["Authorization"] = f"Bearer {ADMIN_TOKEN}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=req_headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            content_type = r.headers.get("Content-Type", "")
            raw = r.read()
            if "application/json" in content_type:
                return r.status, json.loads(raw), r.headers
            return r.status, raw.decode("utf-8", errors="replace"), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), e.headers
        except Exception:
            return e.code, raw.decode("utf-8", errors="replace"), e.headers


# =============================================================================
# 1. Loading all 12 evidence files E01–E12
# =============================================================================
def test_cat1_loading_evidence_files():
    print(f"\n{BOLD}=== 1. LOADING ALL 12 EVIDENCE FILES E01–E12 ==={RESET}")
    from data.loader import get_evidence_inventory, OFFICIAL_FILES
    inv = get_evidence_inventory()
    log_test("All 12 Official Evidence Files Defined in Manifest", len(OFFICIAL_FILES) == 12)
    log_test("All 12 Evidence Files Present On Disk", len(inv) == 12 and all(f["exists"] for f in inv))
    log_test("All 12 Evidence Files Non-Empty", all(f["size_bytes"] > 0 for f in inv))


# =============================================================================
# 2. Event ID preservation and format validation
# =============================================================================
def test_cat2_event_id_preservation():
    print(f"\n{BOLD}=== 2. EVENT ID PRESERVATION & FORMAT VALIDATION ==={RESET}")
    from data.logs import get_all_logs
    logs = get_all_logs()
    event_ids = {l.get("event_id") for l in logs if l.get("event_id")}
    
    required_ids = {"A011", "A012", "R003", "R004", "P003", "P004", "C003", "C004", "CHG-882", "CHG-883", "HD-1058", "A006", "N001"}
    log_test("Preserves Case Dossier Event IDs (A011, R004, C003, CHG-882, etc.)", required_ids.issubset(event_ids))
    log_test("No Invented Prefix 'EVT-' Present", not any(eid.startswith("EVT-") for eid in event_ids))
    log_test("Preserves Ticket Identifiers (HD-1058, HD-1069)", "HD-1058" in event_ids and "HD-1069" in event_ids)


# =============================================================================
# 3. Accurate timestamp chronological sorting (IST)
# =============================================================================
def test_cat3_chronological_sorting():
    print(f"\n{BOLD}=== 3. ACCURATE TIMESTAMP CHRONOLOGICAL SORTING (IST) ==={RESET}")
    from analysis.timeline import get_timeline
    tl = get_timeline()
    log_test("Timeline Phases Count >= 10", len(tl) >= 10, f"({len(tl)} phases correlated)")
    
    timestamps = [step["timestamp"] for step in tl if step.get("timestamp")]
    is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
    log_test("Strict Chronological Ordering Across Correlated Steps", is_sorted)
    
    has_ist = all("+05:30" in ts for ts in timestamps)
    log_test("Timestamps Retain Authentic IST Timezone (+05:30)", has_ist)


# =============================================================================
# 4. External source IP detection (203.0.113.77) with no human attribution
# =============================================================================
def test_cat4_external_source_ip():
    print(f"\n{BOLD}=== 4. EXTERNAL SOURCE IP DETECTION & ATTRIBUTION BOUNDARY ==={RESET}")
    from analysis.anomaly import detect_external_service_ingress, UNAUTHORIZED_EXTERNAL_IP
    log_test("Target External IP is Authentic 203.0.113.77", UNAUTHORIZED_EXTERNAL_IP == "203.0.113.77")
    findings = detect_external_service_ingress()
    log_test("Rule 1 Flags External Service Ingress from 203.0.113.77", len(findings) > 0)
    if findings:
        log_test("Rule 1 Heuristic Severity Score is 95/100", findings[0]["heuristic_score"] == 95)
        log_test("Rule 1 Confidence Classified as 'CONFIRMED OBSERVATION'", findings[0]["confidence_classification"] == "CONFIRMED OBSERVATION")


# =============================================================================
# 5. Unusual API record-count detection
# =============================================================================
def test_cat5_unusual_api_record_count():
    print(f"\n{BOLD}=== 5. UNUSUAL API RECORD-COUNT DETECTION ==={RESET}")
    from data.logs import API_ACCESS_LOGS, PORTAL_LOGS
    r004 = next((l for l in API_ACCESS_LOGS if l.get("event_id") == "R004"), None)
    log_test("API Log R004 Records Export Job Triggered", r004 is not None and r004.get("endpoint") == "/v1/learners/export")
    
    p004 = next((l for l in PORTAL_LOGS if l.get("event_id") == "P004"), None)
    log_test("Portal Log P004 Confirms 2,300 Records Exported", p004 is not None and p004.get("record_count") == 2300)
    
    from analysis.anomaly import detect_bulk_learner_export
    fnd = detect_bulk_learner_export()
    log_test("Bulk Export Anomaly Rule Detects 2,300 Record Volume", len(fnd) > 0 and fnd[0]["heuristic_score"] == 98)


# =============================================================================
# 6. Bulk learner export detection
# =============================================================================
def test_cat6_bulk_learner_export():
    print(f"\n{BOLD}=== 6. BULK LEARNER EXPORT DETECTION ==={RESET}")
    from data.logs import DATA_EXPORT_LOGS
    bulk_events = [l for l in DATA_EXPORT_LOGS if l.get("record_count", 0) > 250]
    log_test("Detects Bulk Export Exceeding Normal Limit (> 250)", len(bulk_events) > 0)
    log_test("Identifies Target Filename 'learners-20261012.csv'", any("learners-20261012.csv" in str(l) for l in bulk_events))


# =============================================================================
# 7. Repeated cloud repository downloads detection (C003, C004)
# =============================================================================
def test_cat7_repeated_cloud_downloads():
    print(f"\n{BOLD}=== 7. REPEATED CLOUD REPOSITORY DOWNLOADS DETECTION (C003, C004) ==={RESET}")
    from analysis.anomaly import detect_repeated_archive_download
    findings = detect_repeated_archive_download()
    log_test("Rule 3 Flags Repeated Object Downloads from CampusVault", len(findings) > 0)
    if findings:
        f = findings[0]
        log_test("Correlates Events C003 and C004", "C003" in f["event_ids"] and "C004" in f["event_ids"])
        log_test("Rule 3 Severity Score is 100/100 (Critical)", f["heuristic_score"] == 100)


# =============================================================================
# 8. Missing credential expiration policy detection (INT-01 expires: never)
# =============================================================================
def test_cat8_missing_credential_expiry():
    print(f"\n{BOLD}=== 8. MISSING CREDENTIAL EXPIRATION & AGE DETECTION ==={RESET}")
    from analysis.anomaly import detect_credential_hygiene_defect
    findings = detect_credential_hygiene_defect()
    log_test("Flags INT-01 Credential Hygiene Defect", len(findings) > 0)
    if findings:
        reason = findings[0]["reason_for_flagging"]
        log_test("Accurately Identifies ~7 Months Credential Age (Created 2026-03-04)", "7 months" in reason.lower())
        log_test("Identifies 'expires: never' Defect", "expires: never" in reason)


# =============================================================================
# 9. Missing source IP restriction detection (INT-01 ip_restriction: not configured)
# =============================================================================
def test_cat9_missing_ip_restriction():
    print(f"\n{BOLD}=== 9. MISSING SOURCE IP RESTRICTION DETECTION ==={RESET}")
    from analysis.anomaly import detect_credential_hygiene_defect
    findings = detect_credential_hygiene_defect()
    if findings:
        reason = findings[0]["reason_for_flagging"]
        log_test("Identifies Missing Source IP Restriction in INT-01", "ip_restriction: not configured" in reason)
        log_test("Links Violation to NS-SEC-04 Rule 3", "Rule 3" in findings[0]["policy_violation"])


# =============================================================================
# 10. Former employee offboarding violation warning (A006 former.ajay on 09-Oct)
# =============================================================================
def test_cat10_former_employee_offboarding():
    print(f"\n{BOLD}=== 10. FORMER EMPLOYEE OFFBOARDING VIOLATION WARNING (A006) ==={RESET}")
    from analysis.anomaly import detect_former_staff_persistence
    findings = detect_former_staff_persistence()
    log_test("Rule 6 Detects Post-Departure Authentication (Event A006)", len(findings) > 0)
    if findings:
        f = findings[0]
        log_test("Identifies Account 'former.ajay'", "former.ajay" in f["reason_for_flagging"])
        log_test("Explicitly Disclaims Attribution for 12-Oct Incident", "does not establish responsibility" in f["reason_for_flagging"].lower())


# =============================================================================
# 11. Evidence SHA-256 hash generation & integrity verification
# =============================================================================
def test_cat11_evidence_integrity_hashes():
    print(f"\n{BOLD}=== 11. EVIDENCE SHA-256 HASH GENERATION & INTEGRITY VERIFICATION ==={RESET}")
    from data.loader import get_evidence_inventory
    inv = get_evidence_inventory()
    hashes = [item["sha256"] for item in inv]
    log_test("Generated SHA-256 Hashes for All 12 Files", len(hashes) == 12 and all(len(h) == 64 for h in hashes))
    
    e01_hash = next(item["sha256"] for item in inv if item["evidence_id"] == "E01")
    log_test("E01 SHA-256 Hash Computed Accurately", len(e01_hash) == 64 and e01_hash.startswith("fd67af"))
    
    e04_hash = next(item["sha256"] for item in inv if item["evidence_id"] == "E04")
    log_test("E04 SHA-256 Hash Computed Accurately", len(e04_hash) == 64 and e04_hash.startswith("2cc66d"))


# =============================================================================
# 12. Vulnerable API vs. Hardened API behavior comparison
# =============================================================================
def test_cat12_vulnerable_vs_hardened_api():
    print(f"\n{BOLD}=== 12. VULNERABLE API VS HARDENED API BEHAVIOR COMPARISON ==={RESET}")
    sim_dir = Path(__file__).resolve().parent / "FULL PACK" / "SAFE_SIMULATION"
    if not (sim_dir / "mock_api_server.py").exists():
        log_test("Mock API Server Available for Simulation", False)
        return

    proc_vuln = subprocess.Popen([sys.executable, "mock_api_server.py", "--mode", "vulnerable", "--port", "8790"], cwd=str(sim_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc_hard = subprocess.Popen([sys.executable, "mock_api_server.py", "--mode", "hardened", "--port", "8791"], cwd=str(sim_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    try:
        def request_api(port, path, method="GET", source="203.0.113.77"):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, headers={"X-Simulated-Source-IP": source, "Authorization": "Bearer demo-rollcall-token", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        vuln_status = request_api(8790, "/v1/attendance", source="203.0.113.77")
        log_test("Vulnerable API Allows External Untrusted IP 203.0.113.77 (HTTP 200)", vuln_status == 200)

        hard_status = request_api(8791, "/v1/attendance", source="203.0.113.77")
        log_test("Hardened API Blocks External Untrusted IP 203.0.113.77 (HTTP 403)", hard_status == 403)

    finally:
        proc_vuln.terminate()
        proc_hard.terminate()
        proc_vuln.wait()
        proc_hard.wait()


# =============================================================================
# 13. Export approval enforcement (isolated record limit ceiling <= 100)
# =============================================================================
def test_cat13_export_approval_enforcement():
    print(f"\n{BOLD}=== 13. EXPORT APPROVAL & RECORD LIMIT ENFORCEMENT (ISOLATED) ==={RESET}")
    sim_dir = Path(__file__).resolve().parent / "FULL PACK" / "SAFE_SIMULATION"
    proc = subprocess.Popen([sys.executable, "mock_api_server.py", "--mode", "hardened", "--port", "8792"], cwd=str(sim_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

    try:
        def export_call(record_count, role="learner.export"):
            data = json.dumps({"record_count": record_count}).encode()
            headers = {
                "Authorization": "Bearer demo-rollcall-token",
                "X-Simulated-Source-IP": "10.10.4.12",
                "X-Simulated-Role": role,
                "Content-Type": "application/json"
            }
            req = urllib.request.Request("http://127.0.0.1:8792/v1/learners/export", data=data, method="POST", headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        code_large, body_large = export_call(2300)
        log_test("Export > 100 Records Rejected by Record Limit Ceiling (HTTP 400)", code_large == 400, f"Error: {body_large.get('error')}")

        code_small, body_small = export_call(50)
        log_test("Export <= 100 Records Approved and Dispatched (HTTP 200)", code_small == 200)

    finally:
        proc.terminate()
        proc.wait()


# =============================================================================
# 14. Unauthorized request rejection (IP drop, role restriction)
# =============================================================================
def test_cat14_unauthorized_request_rejection():
    print(f"\n{BOLD}=== 14. UNAUTHORIZED REQUEST REJECTION (IP DROP & ROLE RESTRICTION) ==={RESET}")
    status, d, _ = api_call("http://127.0.0.1:5000/api/test-ip", method="POST", body={"ip": "203.0.113.77"})
    log_test("Perimeter Filter Rejects Untrusted External IP (BLOCKED)", status == 200 and d.get("status") == "BLOCKED" and d.get("action") == "DROP_AND_SIEM_ALERT")

    status, d, _ = api_call("http://127.0.0.1:5000/api/test-role", method="POST", body={"role": "attendance.read", "endpoint": "/v1/learners/export"})
    log_test("Least Privilege Boundary Rejects Export for Attendance Role (DENIED_403)", status == 200 and d.get("status") == "DENIED_403")


# =============================================================================
# 15. Incident investigation report generation (JSON and CSV)
# =============================================================================
def test_cat15_report_generation():
    print(f"\n{BOLD}=== 15. INCIDENT INVESTIGATION REPORT GENERATION (JSON & CSV) ==={RESET}")
    # JSON Report (authenticated)
    status, d, _ = api_call("http://127.0.0.1:5000/api/export-report", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    log_test("Forensic Report Generated in Structured JSON", status == 200 and "report_id" in d)
    log_test("JSON Report Records 2,300 Logged Exported Records", d.get("records_logged_in_export") == 2300 or d.get("records_compromised") == 2300)
    log_test("JSON Report Explains Logged Count vs Individual Proof", "unique individual count is not proven" in d.get("records_logged_note", "").lower())
    log_test("JSON Report Separates Screenshot Hypothesis", "screenshot attachment" in d.get("root_cause_summary", "").lower() and "unverified and unknown" in d.get("root_cause_summary", "").lower())

    # CSV Report (authenticated)
    status, csv_text, _ = api_call("http://127.0.0.1:5000/api/export-report/csv", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    lines = csv_text.splitlines() if isinstance(csv_text, str) else []
    log_test("Forensic Report Generated in Downloadable CSV Format", status == 200 and len(lines) > 10)
    log_test("CSV Report Headers Include Finding and Timeline Tables", any("FINDING_ID" in l for l in lines) and any("PHASE_TITLE" in l for l in lines))


# =============================================================================
# 16. Real Flask API Authentication Middleware (401 Negative Tests)
# =============================================================================
def test_cat16_authentication_middleware():
    print(f"\n{BOLD}=== 16. REAL FLASK API AUTHENTICATION MIDDLEWARE (NEGATIVE TESTS) ==={RESET}")
    # A. Unauthenticated call to /api/dashboard
    status, body, _ = api_call("http://127.0.0.1:5000/api/dashboard", auth=False)
    log_test("Missing Token to /api/dashboard Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # B. Unauthenticated call to /api/logs
    status, body, _ = api_call("http://127.0.0.1:5000/api/logs", auth=False)
    log_test("Missing Token to /api/logs Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # C. Unauthenticated call to /api/credential-audit
    status, body, _ = api_call("http://127.0.0.1:5000/api/credential-audit", auth=False)
    log_test("Missing Token to /api/credential-audit Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # D. Unauthenticated call to /api/export-report
    status, body, _ = api_call("http://127.0.0.1:5000/api/export-report", auth=False)
    log_test("Missing Token to /api/export-report Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # E. Invalid token call to /api/export-report
    status, body, _ = api_call("http://127.0.0.1:5000/api/export-report", headers={"Authorization": "Bearer invalid-token-xyz"})
    log_test("Invalid Token to /api/export-report Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # F. Unauthenticated call to /api/rotate-credential
    status, body, _ = api_call("http://127.0.0.1:5000/api/rotate-credential", method="POST", body={"account": "svc_rollcall"}, auth=False)
    log_test("Unauthenticated Credential Rotation Rejected (HTTP 401)", status == 401, f"Status: {status}")

    # G. Valid Bearer Token Authenticated Successfully
    status, body, _ = api_call("http://127.0.0.1:5000/api/export-report", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    log_test("Valid Bearer Token Authenticated Successfully (HTTP 200)", status == 200, f"Status: {status}")


# =============================================================================
# 17. Server-Side Role-Based Access Control (403 Privilege Tests)
# =============================================================================
def test_cat17_role_based_access_control():
    print(f"\n{BOLD}=== 17. ROLE-BASED ACCESS CONTROL (403 PRIVILEGE TESTS) ==={RESET}")
    # A. Analyst token attempting admin-only credential rotation -> 403 Forbidden
    status, body, _ = api_call(
        "http://127.0.0.1:5000/api/rotate-credential",
        method="POST",
        headers={"Authorization": f"Bearer {ANALYST_TOKEN}"},
        body={"account": "svc_rollcall"}
    )
    log_test("Analyst Role Denied Admin Rotation Route (HTTP 403 Forbidden)", status == 403, f"Status: {status} ({body.get('error')})")

    # B. Admin token executing credential rotation -> 200 OK
    status, body, _ = api_call(
        "http://127.0.0.1:5000/api/rotate-credential",
        method="POST",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        body={"account": "svc_rollcall"}
    )
    log_test("Admin Role Permitted to Rotate Credentials (HTTP 200 OK)", status == 200, f"Status: {status}")
    log_test("Rotation Explicitly Labeled as Simulated Demonstration", body.get("status") == "SIMULATED_DEMONSTRATION" and body.get("simulation_mode") is True)


# =============================================================================
# 18. Input Validation & Strict Typing (400 Input Tests)
# =============================================================================
def test_cat18_input_validation():
    print(f"\n{BOLD}=== 18. INPUT VALIDATION & STRICT TYPING (400 TESTS) ==={RESET}")
    # A. Non-IP string to test-ip
    status, body, _ = api_call("http://127.0.0.1:5000/api/test-ip", method="POST", body={"ip": "not-an-ip-address"})
    log_test("Invalid IP String Rejected by ipaddress Parser (HTTP 400)", status == 400, f"Error: {body.get('error')}")

    # B. Missing IP field to test-ip
    status, body, _ = api_call("http://127.0.0.1:5000/api/test-ip", method="POST", body={})
    log_test("Missing 'ip' Parameter Rejected (HTTP 400)", status == 400, f"Error: {body.get('error')}")

    # C. Unrecognized role to test-role
    status, body, _ = api_call("http://127.0.0.1:5000/api/test-role", method="POST", body={"role": "super_hacker_role", "endpoint": "/v1/attendance"})
    log_test("Unrecognized Role Rejected by Server-Side RBAC (HTTP 400)", status == 400, f"Error: {body.get('error')}")


# =============================================================================
# 19. Attack Simulation Ground Truth Alignment
# =============================================================================
def test_cat19_attack_simulation_alignment():
    print(f"\n{BOLD}=== 19. ATTACK SIMULATION GROUND TRUTH ALIGNMENT ==={RESET}")
    status, body, _ = api_call(
        "http://127.0.0.1:5000/api/simulate",
        method="POST",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        body={"scenario": "credential-exposure"}
    )
    log_test("Simulation Endpoint Successfully Authenticated (HTTP 200)", status == 200)
    
    steps = body.get("steps", [])
    raw_str = json.dumps(steps)
    
    log_test("No Unsupported Claim of Plaintext Secret Exposure", "secrets exposed in plaintext" not in raw_str.lower() and "plaintext" not in raw_str.lower())
    log_test("No Unsupported Claim of 300+ API Calls", "300+" not in raw_str and "312" not in raw_str)
    log_test("Distinguishes Confirmed Events from Hypothetical Simulation", any(s.get("type") == "CONFIRMED_OBSERVATION" for s in steps) and any(s.get("type") == "HYPOTHETICAL_SIMULATION" for s in steps))
    log_test("Distinguishes API Export Job Creation from Cloud Download", any("export job" in s.get("action", "").lower() for s in steps) and any("download" in s.get("action", "").lower() for s in steps))


# =============================================================================
# 20. Explicit CORS Origin Protection
# =============================================================================
def test_cat20_cors_protection():
    print(f"\n{BOLD}=== 20. EXPLICIT CORS ORIGIN PROTECTION ==={RESET}")
    # Request with trusted origin
    status, _, headers = api_call("http://127.0.0.1:5000/api/dashboard", headers={"Origin": "http://localhost:5000"})
    allow_origin = headers.get("Access-Control-Allow-Origin")
    log_test("CORS Returns Trusted Origin for Localhost (No Wildcard '*')", allow_origin == "http://localhost:5000" or allow_origin in ("http://localhost:5000", "http://127.0.0.1:5000"))


# =============================================================================
# Main Test Coordinator
# =============================================================================
def main():
    print(f"{BOLD}======================================================================{RESET}")
    print(f"{BOLD}   SENTRIX SHIELD — COMPREHENSIVE AUTOMATED SECURITY TEST RUNNER{RESET}")
    print(f"{BOLD}   CRIMEATHON'26 Selection Round | Track: DEFENSE | Team: SENTRIX{RESET}")
    print(f"{BOLD}======================================================================{RESET}")

    test_cat1_loading_evidence_files()
    test_cat2_event_id_preservation()
    test_cat3_chronological_sorting()
    test_cat4_external_source_ip()
    test_cat5_unusual_api_record_count()
    test_cat6_bulk_learner_export()
    test_cat7_repeated_cloud_downloads()
    test_cat8_missing_credential_expiry()
    test_cat9_missing_ip_restriction()
    test_cat10_former_employee_offboarding()
    test_cat11_evidence_integrity_hashes()
    test_cat12_vulnerable_vs_hardened_api()
    test_cat13_export_approval_enforcement()
    test_cat14_unauthorized_request_rejection()
    test_cat15_report_generation()
    test_cat16_authentication_middleware()
    test_cat17_role_based_access_control()
    test_cat18_input_validation()
    test_cat19_attack_simulation_alignment()
    test_cat20_cors_protection()

    total = passed_tests + failed_tests
    print(f"\n{BOLD}======================================================================{RESET}")
    print(f"{BOLD}FINAL SUMMARY: {GREEN}{passed_tests} PASSED{RESET}, {RED if failed_tests else GREEN}{failed_tests} FAILED{RESET} (Total: {total}){RESET}")
    print(f"{BOLD}SECURITY TEST SUCCESS RATE: {GREEN}{100.0 * passed_tests / total:.1f}%{RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    sys.exit(0 if failed_tests == 0 else 1)


if __name__ == "__main__":
    main()
