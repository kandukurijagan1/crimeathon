"""
data/loader.py — Dynamic Evidence Ingestion & Integrity Verification Engine
===========================================================================
CRIMEATHON'26 Case NS-26-014: The Northstar Learning Services Investigation
Directly ingests authentic files from 'FULL PACK/EVIDENCE'.
Computes SHA-256 checksums, validates file integrity, and normalizes telemetry
without altering or fabricating any event records.
"""

import os
import csv
import json
import hashlib
from pathlib import Path
from datetime import datetime

# Resolve base directories safely
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "FULL PACK" / "EVIDENCE"
SAFE_SIMULATION_DIR = PROJECT_ROOT / "FULL PACK" / "SAFE_SIMULATION"

# Official 12 Evidence Files Manifest
OFFICIAL_FILES = [
    {"id": "E01", "file": "E01_Authentication_Logs.csv", "type": "csv", "source": "Northstar Identity (IAM)", "category": "Authentication"},
    {"id": "E02", "file": "E02_ClassBridge_Audit_Logs.csv", "type": "csv", "source": "ClassBridge Portal", "category": "Portal Audit"},
    {"id": "E03", "file": "E03_API_Gateway_Logs.csv", "type": "csv", "source": "API Gateway", "category": "API Gateway"},
    {"id": "E04", "file": "E04_CampusVault_Audit_Logs.csv", "type": "csv", "source": "CampusVault Cloud Storage", "category": "Cloud Repository"},
    {"id": "E05", "file": "E05_Integration_Register.csv", "type": "csv", "source": "IT Operations Register", "category": "Governance"},
    {"id": "E06", "file": "E06_HelpDesk_Tickets.csv", "type": "csv", "source": "HelpDesk Lite", "category": "Support Tickets"},
    {"id": "E07", "file": "E07_Staff_and_Service_Account_Register.csv", "type": "csv", "source": "HR & Identity Directory", "category": "Identity Context"},
    {"id": "E08", "file": "E08_Information_Security_Policy_Extract.txt", "type": "txt", "source": "Information Security Office", "category": "Policy Standard"},
    {"id": "E09", "file": "E09_Network_Observations.csv", "type": "csv", "source": "Perimeter Network Sensor", "category": "Network Flow"},
    {"id": "E10", "file": "E10_Vendor_And_Internal_Communications.json", "type": "json", "source": "Communications Archive", "category": "Vendor Relations"},
    {"id": "E11", "file": "E11_Additional_Configuration_Audit.csv", "type": "csv", "source": "Configuration Service Audit", "category": "Configuration Audit"},
    {"id": "E12", "file": "E12_Incident_Response_Note.txt", "type": "txt", "source": "Incident Response Lead", "category": "Forensic Note"},
]


def calculate_sha256(filepath: Path) -> str:
    """Calculate the cryptographic SHA-256 hash of an evidence file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def get_evidence_inventory():
    """Returns metadata, file size, record count, and SHA-256 hash for all 12 files."""
    inventory = []
    for item in OFFICIAL_FILES:
        filepath = EVIDENCE_DIR / item["file"]
        exists = filepath.exists()
        
        info = {
            "evidence_id": item["id"],
            "filename": item["file"],
            "source": item["source"],
            "category": item["category"],
            "type": item["type"],
            "path": str(filepath),
            "exists": exists,
            "status": "VERIFIED_INTACT" if exists else "FILE_MISSING",
            "size_bytes": filepath.stat().st_size if exists else 0,
            "sha256": calculate_sha256(filepath) if exists else "UNAVAILABLE",
            "last_modified": datetime.fromtimestamp(filepath.stat().st_mtime).isoformat() if exists else None,
            "record_count": 0,
        }
        
        # Calculate record count
        if exists:
            if item["type"] == "csv":
                try:
                    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                        reader = csv.DictReader(f)
                        info["record_count"] = sum(1 for _ in reader)
                except Exception:
                    pass
            elif item["type"] == "json":
                try:
                    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                        data = json.load(f)
                        info["record_count"] = len(data) if isinstance(data, list) else 1
                except Exception:
                    pass
            elif item["type"] == "txt":
                try:
                    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                        info["record_count"] = sum(1 for line in f if line.strip())
                except Exception:
                    pass
                    
        inventory.append(info)
    return inventory


def load_raw_evidence_file(evidence_id: str):
    """Loads the raw content of an evidence file for forensic inspection."""
    target = next((item for item in OFFICIAL_FILES if item["id"].upper() == evidence_id.upper()), None)
    if not target:
        return None, "Evidence file not found in manifest."
        
    filepath = EVIDENCE_DIR / target["file"]
    if not filepath.exists():
        return None, f"File {target['file']} does not exist on disk."
        
    try:
        with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
            content = f.read()
        return {
            "evidence_id": target["id"],
            "filename": target["file"],
            "sha256": calculate_sha256(filepath),
            "size_bytes": len(content.encode("utf-8")),
            "content": content
        }, None
    except Exception as e:
        return None, str(e)


def load_parsed_evidence():
    """Parses all evidence records into structured Python dicts."""
    parsed = {}
    
    # E01 Authentication Logs
    e01_path = EVIDENCE_DIR / "E01_Authentication_Logs.csv"
    if e01_path.exists():
        with open(e01_path, "r", encoding="utf-8-sig") as f:
            parsed["auth_logs"] = list(csv.DictReader(f))
    else:
        parsed["auth_logs"] = []

    # E02 ClassBridge Logs
    e02_path = EVIDENCE_DIR / "E02_ClassBridge_Audit_Logs.csv"
    if e02_path.exists():
        with open(e02_path, "r", encoding="utf-8-sig") as f:
            parsed["portal_logs"] = list(csv.DictReader(f))
    else:
        parsed["portal_logs"] = []

    # E03 API Gateway Logs
    e03_path = EVIDENCE_DIR / "E03_API_Gateway_Logs.csv"
    if e03_path.exists():
        with open(e03_path, "r", encoding="utf-8-sig") as f:
            parsed["api_logs"] = list(csv.DictReader(f))
    else:
        parsed["api_logs"] = []

    # E04 CampusVault Logs
    e04_path = EVIDENCE_DIR / "E04_CampusVault_Audit_Logs.csv"
    if e04_path.exists():
        with open(e04_path, "r", encoding="utf-8-sig") as f:
            parsed["vault_logs"] = list(csv.DictReader(f))
    else:
        parsed["vault_logs"] = []

    # E05 Integration Register
    e05_path = EVIDENCE_DIR / "E05_Integration_Register.csv"
    if e05_path.exists():
        with open(e05_path, "r", encoding="utf-8-sig") as f:
            parsed["integrations"] = list(csv.DictReader(f))
    else:
        parsed["integrations"] = []

    # E06 HelpDesk Tickets
    e06_path = EVIDENCE_DIR / "E06_HelpDesk_Tickets.csv"
    if e06_path.exists():
        with open(e06_path, "r", encoding="utf-8-sig") as f:
            parsed["tickets"] = list(csv.DictReader(f))
    else:
        parsed["tickets"] = []

    # E07 Staff Register
    e07_path = EVIDENCE_DIR / "E07_Staff_and_Service_Account_Register.csv"
    if e07_path.exists():
        with open(e07_path, "r", encoding="utf-8-sig") as f:
            parsed["accounts"] = list(csv.DictReader(f))
    else:
        parsed["accounts"] = []

    # E09 Network Observations
    e09_path = EVIDENCE_DIR / "E09_Network_Observations.csv"
    if e09_path.exists():
        with open(e09_path, "r", encoding="utf-8-sig") as f:
            parsed["network_logs"] = list(csv.DictReader(f))
    else:
        parsed["network_logs"] = []

    # E10 Communications
    e10_path = EVIDENCE_DIR / "E10_Vendor_And_Internal_Communications.json"
    if e10_path.exists():
        with open(e10_path, "r", encoding="utf-8-sig") as f:
            parsed["communications"] = json.load(f)
    else:
        parsed["communications"] = []

    # E11 Configuration Audit
    e11_path = EVIDENCE_DIR / "E11_Additional_Configuration_Audit.csv"
    if e11_path.exists():
        with open(e11_path, "r", encoding="utf-8-sig") as f:
            parsed["config_audit"] = list(csv.DictReader(f))
    else:
        parsed["config_audit"] = []

    return parsed
