"""
Backend Tests for Secure Evidence Upload Links with Expiry & Chain-of-Custody Metadata.

Validates:
1. Single-purpose upload link generation bound to report and allowed MIME types.
2. Short-lived token validity and expiry enforcement.
3. Passcode/OTP verification guardrails.
4. Secure evidence upload fulfillment into Evidence Vault with SHA-256 fingerprinting.
5. Chain-of-custody ledger logging with client IP, file hash, size, and receipt metadata.
6. Single-use fulfillment enforcement (completed links cannot be re-used).
7. Authorised officer link revocation.
8. Router endpoints for link creation, listing, validation, upload, and revocation.
"""
from __future__ import annotations

import time
import pytest
from fastapi.security import HTTPAuthorizationCredentials
from app import security
from app.models import (
    CreateUploadLinkRequest,
    RevokeUploadLinkRequest,
    UploadEvidenceViaLinkRequest,
)
from app.routers import evidence as evidence_router
from app.services import incidents
from app.services import evidence as evidence_service
from app.services import evidence_upload_link as link_service

TOKEN = "evidence-upload-test-token-that-is-long-enough-123456"


@pytest.fixture(autouse=True)
def clean_state():
    evidence_service.reset()
    link_service.reset()
    incidents.reset()
    incidents.seed_sample_evidence_incidents()
    yield
    evidence_service.reset()
    link_service.reset()
    incidents.reset()


@pytest.fixture
def principal(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        f'{{"{TOKEN}": "OFF-SUP-DELHI"}}',
    )
    return security.get_current_principal(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials=TOKEN)
    )


@pytest.fixture
def incident_id():
    incident = incidents.create_incident(
        category="other",
        description="Secure evidence upload test incident.",
        region="Central Zone",
    )
    return incident["id"]


def test_create_upload_link_bound_to_report(principal, incident_id):
    req = CreateUploadLinkRequest(
        report_id="RPT-0001",
        incident_id=incident_id,
        title="WhatsApp Digital Arrest Video Recording",
        description="Please provide screen recording of extortion call.",
        allowed_file_types=["video/mp4", "audio/wav", "application/pdf"],
        max_file_size_bytes=30 * 1024 * 1024,
        expiry_minutes=30,
        requires_passcode=False,
        created_by_badge="INSP-KUMAR-771",
        officer_name="Inspector R. Kumar",
        recipient_email="victim@example.com",
    )
    link = evidence_router.create_upload_link(req, principal=principal)

    assert link["link_id"].startswith("UPL-")
    assert len(link["token"]) >= 20
    assert link["report_id"] == "RPT-0001"
    assert link["incident_id"] == incident_id
    assert link["status"] == "active"
    assert link["is_expired"] is False
    assert link["allowed_file_types"] == ["video/mp4", "audio/wav", "application/pdf"]
    assert link["max_file_size_bytes"] == 30 * 1024 * 1024
    assert link["created_by_badge"] == principal.officer_id
    assert link["upload_url"].startswith("/evidence/upload?token=")


def test_validate_token_and_expiration():
    req = CreateUploadLinkRequest(
        report_id="RPT-0002",
        title="Bank Transfer Advice",
        expiry_minutes=1,  # 1 minute
        requires_passcode=False,
    )
    link = link_service.create_upload_link(req.model_dump())
    token = link["token"]

    # 1. Immediately valid
    val = link_service.validate_upload_token(token)
    assert val["valid"] is True
    assert val["status"] == "active"
    assert val["report_id"] == "RPT-0002"

    # 2. Simulate expiration by backdating expires_at
    link_internal = link_service._UPLOAD_LINKS[link["link_id"]]
    link_internal["expires_at"] = link_internal["created_at"] - 1000

    val_expired = link_service.validate_upload_token(token)
    assert val_expired["valid"] is False
    assert val_expired["status"] == "expired"
    assert "expired" in val_expired["error"].lower()


def test_passcode_verification():
    req = CreateUploadLinkRequest(
        report_id="CASE-2026-DELHI-01",
        title="Mule Cheque Leaf",
        requires_passcode=True,
        passcode="8832",
    )
    link = link_service.create_upload_link(req.model_dump())
    token = link["token"]

    # 1. No passcode provided -> passcode_required
    val1 = link_service.validate_upload_token(token)
    assert val1["valid"] is False
    assert val1["status"] == "passcode_required"

    # 2. Wrong passcode provided -> invalid_passcode
    val2 = link_service.validate_upload_token(token, passcode="1111")
    assert val2["valid"] is False
    assert val2["status"] == "invalid_passcode"

    # 3. Correct passcode -> valid
    val3 = link_service.validate_upload_token(token, passcode="8832")
    assert val3["valid"] is True
    assert val3["status"] == "active"


def test_upload_fulfillment_and_vault_chain_of_custody(incident_id):
    req = CreateUploadLinkRequest(
        report_id="RPT-0001",
        incident_id=incident_id,
        title="Extortion Call Audio",
        allowed_file_types=["audio/wav", "audio/mpeg"],
        max_file_size_bytes=10 * 1024 * 1024,
    )
    link = link_service.create_upload_link(req.model_dump())
    token = link["token"]

    raw_audio = "RIFF-WAVE-AUDIO-DATA-CALL-RECORDING-CBI-THREAT"
    upload_payload = UploadEvidenceViaLinkRequest(
        token=token,
        file_name="extortion_call_rec.wav",
        mime_type="audio/wav",
        raw_payload_content=raw_audio,
        uploader_name="Rohan Deshmukh",
        uploader_notes="Audio recorded on victim handset during WhatsApp video call.",
        client_ip="192.168.1.105",
        user_agent="CitizenApp/2.0",
    )

    result = evidence_router.fulfill_evidence_upload(upload_payload)
    assert result["success"] is True
    assert "evidence_id" in result
    evidence_id = result["evidence_id"]

    receipt = result["receipt"]
    assert receipt["report_id"] == "RPT-0001"
    assert receipt["file_name"] == "extortion_call_rec.wav"
    assert len(receipt["sha256_fingerprint"]) == 64
    assert receipt["rfc3161_serial"].startswith("TSA-")
    assert receipt["client_ip"] == "192.168.1.105"

    # Verify link state became completed
    updated_link = link_service.get_upload_link(link["link_id"])
    assert updated_link["status"] == "completed"
    assert updated_link["completed_at"] is not None
    assert updated_link["evidence_id"] == evidence_id

    # Verify evidence item ingested in Vault
    ev = evidence_service.get_evidence(evidence_id)
    assert ev is not None
    assert ev["source"] == "citizen_upload_link"
    assert ev["sha256_hash"] == receipt["sha256_fingerprint"]

    # Verify chain of custody ledger contains CITIZEN_SECURE_LINK_UPLOAD
    ledger = evidence_service.get_custodial_ledger(evidence_id)
    upload_log = next((e for e in ledger if e["action"] == "CITIZEN_SECURE_LINK_UPLOAD"), None)
    assert upload_log is not None
    assert "RPT-0001" in upload_log["details"]
    assert upload_log["client_ip"] == "192.168.1.105"

    # Single-use enforcement: Second upload on same link must fail
    with pytest.raises(Exception):
        evidence_router.fulfill_evidence_upload(upload_payload)


def test_file_type_and_size_restrictions():
    req = CreateUploadLinkRequest(
        report_id="RPT-0005",
        title="PDF Statement Only",
        allowed_file_types=["application/pdf"],
        max_file_size_bytes=1000,  # 1000 bytes max
    )
    link = link_service.create_upload_link(req.model_dump())
    token = link["token"]

    # 1. Reject disallowed MIME type
    bad_type_payload = UploadEvidenceViaLinkRequest(
        token=token,
        file_name="malicious.exe",
        mime_type="application/x-msdownload",
        raw_payload_content="BINARY-PAYLOAD",
    )
    with pytest.raises(Exception) as exc_info:
        link_service.upload_evidence_via_link(token, bad_type_payload.model_dump())
    assert "not allowed" in str(exc_info.value).lower()

    # 2. Reject file exceeding max size
    oversized_payload = UploadEvidenceViaLinkRequest(
        token=token,
        file_name="statement.pdf",
        mime_type="application/pdf",
        raw_payload_content="A" * 2000,  # 2000 bytes
    )
    with pytest.raises(Exception) as exc_info2:
        link_service.upload_evidence_via_link(token, oversized_payload.model_dump())
    assert "exceeds limit" in str(exc_info2.value).lower()


def test_authorised_officer_revocation(principal, incident_id):
    req = CreateUploadLinkRequest(
        report_id="RPT-0009",
        incident_id=incident_id,
        title="Suspect SMS Evidence",
    )
    link = link_service.create_upload_link(req.model_dump())
    link_id = link["link_id"]
    token = link["token"]

    # Revoke link
    revoke_req = RevokeUploadLinkRequest(
        revoked_by_badge="COMM-SINGH-01",
        officer_name="Commander Singh",
        revocation_reason="Complainant contacted precinct; phone seized physically under Section 102 CrPC.",
    )
    revoked = evidence_router.revoke_upload_link(
        link_id, revoke_req, principal=principal
    )
    assert revoked["status"] == "revoked"
    assert revoked["revoked_by_badge"] == principal.officer_id
    assert "Section 102" in revoked["revocation_reason"]

    # Validate token reports revoked
    val = link_service.validate_upload_token(token)
    assert val["valid"] is False
    assert val["status"] == "revoked"
    assert "revoked" in val["error"].lower()

    # Upload attempts on revoked link must fail
    upload_payload = UploadEvidenceViaLinkRequest(
        token=token,
        file_name="sms.png",
        mime_type="image/png",
        raw_payload_content="IMAGE-CONTENT",
    )
    with pytest.raises(Exception):
        link_service.upload_evidence_via_link(token, upload_payload.model_dump())
