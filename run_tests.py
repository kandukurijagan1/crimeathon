#!/usr/bin/env python3
"""
run_tests.py — SENTRIX SHIELD Comprehensive 15-Category Automated Test Suite
============================================================================
CRIMEATHON'26 Selection Round | Track: DEFENSE | Team: SENTRIX (SIMATS)
Case NS-26-014: The Northstar Learning Services Investigation

Strictly tests all 15 Verification Categories required by Master Prompt Section 11:
 1. Loading all 12 evidence files E01–E12 and verifying file presence
 2. Event ID preservation and format validation
 3. Accurate timestamp chronological sorting (IST +05:30)
 4. External attacker IP detection (203.0.113.77)
 5. Unusual API record-count detection (350 records in R004, 2,300 across P003-P004)
 6. Bulk learner export detection
 7. Repeated cloud repository downloads detection (C003, C004)
 8. Missing credential expiration policy detection (INT-01 expires: never, ~7 months)
 9. Missing source IP restriction detection (INT-01 ip_restriction: not configured)
10. Former employee offboarding violation warning (A006 former.ajay on 09-Oct)
11. Evidence SHA-256 hash generation & integrity verification
12. Vulnerable API vs. Hardened API behavior comparison
13. Export approval enforcement (isolated record limit ceiling <= 100)
14. Unauthorized request rejection (IP drop, role restriction)
15. Incident investigation report generation (JSON and CSV)
"""

import sys
import json
import time
import subprocess
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


def log_test(name: str, passed: bool, detail: str = ""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"  [{GREEN}PASS{RESET}] {name} {CYAN}{detail}{RESET}")
    else:
        failed_tests += 1
        print(f"  [{RED}FAIL{RESET}] {name} {YELLOW}{detail}{RESET}")


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
    
    # Authentic IDs from Case Dossier
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
    
    # Verify strict ascending timestamp order
    timestamps = [step["timestamp"] for step in tl if step.get("timestamp")]
    is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
    log_test("Strict Chronological Ordering Across Correlated Steps", is_sorted)
    
    # Verify IST timezone indicator (+05:30)
    has_ist = all("+05:30" in ts for ts in timestamps)
    log_test("Timestamps Retain Authentic IST Timezone (+05:30)", has_ist)


# =============================================================================
# 4. External attacker IP detection (203.0.113.77)
# =============================================================================
def test_cat4_external_attacker_ip():
    print(f"\n{BOLD}=== 4. EXTERNAL ATTACKER IP DETECTION (203.0.113.77) ==={RESET}")
    from analysis.anomaly import detect_external_service_ingress, EXTERNAL_ATTACKER_IP
    log_test("Target Attacker IP is Authentic 203.0.113.77", EXTERNAL_ATTACKER_IP == "203.0.113.77")
    findings = detect_external_service_ingress()
    log_test("Rule 1 Flags External Service Ingress from 203.0.113.77", len(findings) > 0)
    if findings:
        log_test("Rule 1 Heuristic Severity Score is 95/100", findings[0]["heuristic_score"] == 95)
        log_test("Rule 1 Confidence Classified as 'CONFIRMED OBSERVATION'", findings[0]["confidence_classification"] == "CONFIRMED OBSERVATION")


# =============================================================================
# 5. Unusual API record-count detection (350 records in R004, 2,300 across P003-P004)
# =============================================================================
def test_cat5_unusual_api_record_count():
    print(f"\n{BOLD}=== 5. UNUSUAL API RECORD-COUNT DETECTION ==={RESET}")
    from data.logs import API_ACCESS_LOGS, DATA_EXPORT_LOGS, PORTAL_LOGS
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
    
    # Verify specific known file hashes
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

    # Start vulnerable server on 8790
    proc_vuln = subprocess.Popen([sys.executable, "mock_api_server.py", "--mode", "vulnerable", "--port", "8790"], cwd=str(sim_dir), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Start hardened server on 8791
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

        # Vulnerable mode allows external IP
        vuln_status = request_api(8790, "/v1/attendance", source="203.0.113.77")
        log_test("Vulnerable API Allows External Untrusted IP 203.0.113.77 (HTTP 200)", vuln_status == 200)

        # Hardened mode blocks external IP
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

        # Sub-test A: Authorized role requesting 2,300 records (> 100 ceiling)
        code_large, body_large = export_call(2300)
        log_test("Export > 100 Records Rejected by Record Limit Ceiling (HTTP 400)", code_large == 400, f"Error: {body_large.get('error')}")

        # Sub-test B: Authorized role requesting 50 records (<= 100 ceiling)
        code_small, body_small = export_call(50)
        log_test("Export <= 100 Records Approved and Dispatched (HTTP 200)", code_small == 200, f"Records returned: {body_small.get('records_returned')}")

    finally:
        proc.terminate()
        proc.wait()


# =============================================================================
# 14. Unauthorized request rejection (IP drop, role restriction)
# =============================================================================
def test_cat14_unauthorized_request_rejection():
    print(f"\n{BOLD}=== 14. UNAUTHORIZED REQUEST REJECTION (IP DROP & ROLE RESTRICTION) ==={RESET}")
    # Test IP rejection API endpoint
    req_ip = urllib.request.Request("http://127.0.0.1:5000/api/test-ip", data=json.dumps({"ip": "203.0.113.77"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req_ip, timeout=3) as r:
        d = json.loads(r.read())
        log_test("Perimeter Filter Rejects Untrusted External IP (BLOCKED)", d.get("status") == "BLOCKED" and d.get("action") == "DROP_AND_SIEM_ALERT")

    # Test Role boundary API endpoint
    req_role = urllib.request.Request("http://127.0.0.1:5000/api/test-role", data=json.dumps({"role": "attendance.read", "endpoint": "/v1/learners/export"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req_role, timeout=3) as r:
        d = json.loads(r.read())
        log_test("Least Privilege Boundary Rejects Export for Attendance Role (DENIED_403)", d.get("status") == "DENIED_403")


# =============================================================================
# 15. Incident investigation report generation (JSON and CSV)
# =============================================================================
def test_cat15_report_generation():
    print(f"\n{BOLD}=== 15. INCIDENT INVESTIGATION REPORT GENERATION (JSON & CSV) ==={RESET}")
    # JSON Report
    with urllib.request.urlopen("http://127.0.0.1:5000/api/export-report", timeout=3) as r:
        d = json.loads(r.read())
        log_test("Forensic Report Generated in Structured JSON", r.status == 200 and "report_id" in d)
        log_test("JSON Report Includes Accurate 2,300 Compromised Records Count", d.get("records_compromised") == 2300)
        log_test("JSON Report Documents 5 Specific Defense Recommendations", len(d.get("defense_recommendations", [])) >= 5)

    # CSV Report
    with urllib.request.urlopen("http://127.0.0.1:5000/api/export-report/csv", timeout=3) as r:
        csv_bytes = r.read()
        lines = csv_bytes.decode("utf-8").splitlines()
        log_test("Forensic Report Generated in Downloadable CSV Format", r.status == 200 and len(lines) > 10)
        log_test("CSV Report Headers Include Finding and Timeline Tables", any("FINDING_ID" in l for l in lines) and any("PHASE_TITLE" in l for l in lines))


# =============================================================================
# Main Test Coordinator
# =============================================================================
def main():
    print(f"{BOLD}======================================================================{RESET}")
    print(f"{BOLD}   SENTRIX SHIELD — 15-CATEGORY MASTER VERIFICATION TEST RUNNER{RESET}")
    print(f"{BOLD}   CRIMEATHON'26 Selection Round | Track: DEFENSE | Team: SENTRIX{RESET}")
    print(f"{BOLD}======================================================================{RESET}")

    test_cat1_loading_evidence_files()
    test_cat2_event_id_preservation()
    test_cat3_chronological_sorting()
    test_cat4_external_attacker_ip()
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

    total = passed_tests + failed_tests
    print(f"\n{BOLD}======================================================================{RESET}")
    print(f"{BOLD}FINAL SUMMARY: {GREEN}{passed_tests} PASSED{RESET}, {RED if failed_tests else GREEN}{failed_tests} FAILED{RESET} (Total: {total}){RESET}")
    print(f"{BOLD}VERIFICATION SUCCESS RATE: {GREEN}{100.0 * passed_tests / total:.1f}%{RESET}")
    print(f"{BOLD}======================================================================{RESET}")
    sys.exit(0 if failed_tests == 0 else 1)


if __name__ == "__main__":
    main()
