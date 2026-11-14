"""
Tests for Section 63 BSA / 65B IEA Electronic Evidence Affidavit Compiler.
"""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
from fastapi import HTTPException

from app.models import (
    EvidenceIngestRequest,
    Section63AffidavitRequest,
)
from app import security
from app.routers import evidence as evidence_router
from app.routers import evidence_affidavit as affidavit_router
from app.services import incidents
from app.services import evidence as evidence_service
from app.services import evidence_affidavit as affidavit_service

TOKEN = "evidence-affidavit-test-token-1234567890"


@pytest.fixture(autouse=True)
def clean_vault_state():
    """Reset evidence vault state before each test."""
    evidence_service.reset()
    incidents.reset()
    incidents.seed_sample_evidence_incidents()
    yield
    evidence_service.reset()
    incidents.reset()


@pytest.fixture
def principal(monkeypatch):
    from fastapi.security import HTTPAuthorizationCredentials

    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        f'{{"{TOKEN}": "OFF-SUP-DELHI"}}',
    )
    return security.get_current_principal(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials=TOKEN)
    )


def test_get_ntp_status():
    """Verify CSIR-NPL Stratum 1 NTP synchronization record meets BSA § 63(2)(a) requirements."""
    ntp = affidavit_service.get_server_ntp_status()
    assert ntp["is_synchronized"] is True
    assert ntp["ntp_server_host"] == "time.nplindia.org"
    assert ntp["stratum_level"] == 1
    assert ntp["clock_offset_ms"] < 5.0  # Forensic tolerance limit
    assert ntp["jitter_ms"] < 1.0
    assert ntp["leap_indicator"] == 0
    assert "Section 63(2)(a) BSA" in ntp["statutory_compliance"]


def test_compile_section63_affidavit_success():
    """Verify compilation of court-ready Section 63 BSA / 65B IEA affidavit with valid exhibits."""
    case_id = "CASE-2026-DELHI-01"
    req = Section63AffidavitRequest(
        case_id=case_id,
        court_name="Court of Chief Metropolitan Magistrate, Rouse Avenue, New Delhi",
        fir_crime_number="FIR No. 142/2026 PS Cyber Crime u/s 318(4) BNS",
        investigating_officer={
            "officer_name": "Inspector Rajesh Kumar",
            "designation": "Inspector of Police (Cyber Crime Branch)",
            "badge_id": "IO-DEL-4412",
            "police_station": "Cyber Crime PS, Central District",
        },
        system_incharge={
            "officer_name": "Dr. Neha Sharma",
            "designation": "Scientist / System In-Charge",
            "badge_id": "SYS-CFSL-8819",
            "organization": "State Cyber Forensic Laboratory",
        },
    )

    res = affidavit_router.compile_section63_affidavit_endpoint(req)

    assert res["status"] == "SEALED_CRYPTOGRAPHICALLY_VALID"
    assert res["all_hash_chains_verified"] is True
    assert res["tampered_artifacts_count"] == 0
    assert res["case_id"] == case_id
    assert "Section 63 Bharatiya Sakshya Adhiniyam" in res["legal_framework"]
    assert "Section 65B Indian Evidence Act" in res["legal_framework"]
    assert len(res["master_manifest_sha256"]) == 64

    # Exhibits
    exhibits = res["exhibits"]
    assert len(exhibits) >= 1
    for ex in exhibits:
        assert ex["exhibit_number"].startswith("Exhibit P-")
        assert len(ex["sha256_hash"]) == 64
        assert ex["file_size_bytes"] > 0
        assert "hardware_signature" in ex
        assert "device_make_model" in ex["hardware_signature"]
        assert ex["chain_of_custody_verified"] is True

    # NTP Record
    assert res["ntp_verification"]["stratum_level"] == 1
    assert res["ntp_verification"]["ntp_server_host"] == "time.nplindia.org"

    # Declarations
    sys_decl = res["system_incharge_declaration"]
    assert sys_decl["signatory_role"] == "SYSTEM_IN_CHARGE"
    assert "Section 63(4)(a)" in sys_decl["declaration_text"]
    assert sys_decl["esign_status"] == "PENDING_SIGNATURE"
    assert "eSIGN-SLOT" in sys_decl["esign_placeholder"]

    io_decl = res["investigating_officer_declaration"]
    assert io_decl["signatory_role"] == "INVESTIGATING_OFFICER"
    assert "Section 63(4)(b)" in io_decl["declaration_text"]
    assert io_decl["esign_status"] == "PENDING_SIGNATURE"

    # Printable HTML
    assert "IN THE COURT OF CHIEF METROPOLITAN MAGISTRATE" in res["court_printable_html"]
    assert "Schedule-A: Inventory of Electronic Evidence Exhibits" in res["court_printable_html"]


def test_tamper_gate_blocks_affidavit_generation(principal):
    """
    CRITICAL GATE TEST:
    Verify that if ANY artifact in the case bundle fails cryptographic hash chain validation,
    affidavit generation is BLOCKED and raises HTTP 422 with diagnostic details.
    """
    # 1. Ingest a new clean evidence item
    incident = incidents.create_incident(
        category="other",
        description="Affidavit tamper-test incident.",
        region="Central Zone",
    )
    ingest_req = EvidenceIngestRequest(
        incident_id=incident["id"],
        case_id="CASE-TAMPER-TEST-01",
        category="digital_arrest",
        title="Tamper Test Audio Intercept",
        source="audio_intercept",
        raw_content="AUTHENTIC-GENUINE-EVIDENCE-RECORD-CONTENT",
        file_name="digital_arrest_call_01.wav",
        officer_badge_id="OFF-TEST-IO",
    )
    created = evidence_router.ingest_evidence(ingest_req, principal=principal)
    ev_id = created["id"]

    # Verify initially valid
    ver = evidence_service.verify_evidence_integrity(ev_id)
    assert ver["verified"] is True

    # 2. Tamper with raw evidence payload
    evidence_service._raw_payloads[ev_id] = "MALICIOUSLY-MODIFIED-TAMPERED-CONTENT-DATA"

    # 3. Verify that verify_evidence_integrity detects corruption
    tampered_ver = evidence_service.verify_evidence_integrity(ev_id)
    assert tampered_ver["verified"] is False
    assert tampered_ver["sha256_match"] is False

    # 4. Attempt to compile Section 63 BSA affidavit - MUST BE BLOCKED
    affidavit_req = Section63AffidavitRequest(
        case_id="CASE-TAMPER-TEST-01",
        evidence_ids=[ev_id],
    )

    with pytest.raises(HTTPException) as exc_info:
        affidavit_router.compile_section63_affidavit_endpoint(affidavit_req)

    assert exc_info.value.status_code == 422
    detail = exc_info.value.detail
    assert detail["error"] == "COMPILATION_BLOCKED_TAMPER_DETECTED"
    assert detail["failed_artifact_id"] == ev_id
    assert "Arjun Panditrao Khotkar" in detail["statutory_note"]


def test_digital_signature_affixing():
    """Verify simulated digital signature token affixing for System In-Charge and IO."""
    case_id = "CASE-2026-DELHI-01"
    req = Section63AffidavitRequest(
        case_id=case_id,
        affix_digital_signature=True,
    )

    res = affidavit_router.compile_section63_affidavit_endpoint(req)
    assert res["status"] == "SEALED_CRYPTOGRAPHICALLY_VALID"

    sys_decl = res["system_incharge_declaration"]
    assert sys_decl["esign_status"] == "DSC_TOKEN_AFFIXED"
    assert sys_decl["signed_at"] is not None
    assert "DSC-CERT:" in sys_decl["esign_placeholder"]

    io_decl = res["investigating_officer_declaration"]
    assert io_decl["esign_status"] == "DSC_TOKEN_AFFIXED"
    assert io_decl["signed_at"] is not None
    assert "DSC-CERT:" in io_decl["esign_placeholder"]


def test_specific_evidence_ids_selection():
    """Verify that specifying evidence_ids includes only the selected exhibits."""
    all_items = evidence_service.list_evidence()
    target_ids = [all_items[0]["id"]]

    req = Section63AffidavitRequest(
        case_id="ANY-CASE",
        evidence_ids=target_ids,
    )

    res = affidavit_router.compile_section63_affidavit_endpoint(req)
    assert len(res["exhibits"]) == 1
    assert res["exhibits"][0]["evidence_id"] == target_ids[0]


def test_hardware_profiles_endpoint():
    """Verify hardware signature profiles endpoint returns valid profiles."""
    profiles = affidavit_router.get_hardware_profiles_endpoint()
    assert "audio_intercept" in profiles
    assert "mobile_seizure" in profiles
    assert "bank_slip" in profiles
    assert "currency_scan" in profiles
    assert "Dell PowerEdge" in profiles["audio_intercept"]["device_make_model"]
    assert "OnePlus 11 5G" in profiles["mobile_seizure"]["device_make_model"]


def test_preview_html_endpoint():
    """Verify preview HTML endpoint returns 200 with court formatting."""
    response = affidavit_router.get_affidavit_preview_html(
        case_id="CASE-2026-DELHI-01",
        fir="FIR No. 99/2026",
        court="Cyber Appellate Court",
    )
    assert response.status_code == 200
    html = response.body.decode("utf-8")
    assert "SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023" in html
    assert "time.nplindia.org" in html
    assert "FIR NO. 99/2026" in html
