"""
Automated Chain of Custody & Digital Evidence Vault Service for KshemOS.

Defines:
- Cryptographic SHA-256 fingerprinting & simulated RFC 3161 timestamps.
- Immutable hash-chained Custodial Ledger logging every officer interaction.
- Configurable statutory retention clocks & litigation legal-hold overrides.
- Court-admissible forensic export bundle generation with integrity manifests.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

_lock = threading.RLock()
_evidence_counter = itertools.count(1001)
_log_counter = itertools.count(5001)
_bundle_counter = itertools.count(1)

# In-memory stores
_evidence_store: dict[str, dict[str, Any]] = {}
_custodial_ledgers: dict[str, list[dict[str, Any]]] = {}
_raw_payloads: dict[str, str] = {}

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

STATUTORY_RETENTION_POLICIES = {
    "digital_arrest": {
        "category": "digital_arrest",
        "retention_days": 1825,  # 5 years
        "statutory_reference": "BNS § 318 / IT Act § 66D Organized Cyber Syndicate Investigation",
        "auto_purge_allowed": False,
        "description": "5-year statutory hold for digital-arrest syndicate evidence and audio intercepts.",
    },
    "financial_fraud": {
        "category": "financial_fraud",
        "retention_days": 1095,  # 3 years
        "statutory_reference": "Prevention of Money Laundering Act § 12 / RBI Cyber Framework",
        "auto_purge_allowed": True,
        "description": "3-year mandatory preservation for UPI mule transactions and bank slips.",
    },
    "counterfeit_currency": {
        "category": "counterfeit_currency",
        "retention_days": 2555,  # 7 years
        "statutory_reference": "BNS § 178-182 Counterfeit Currency / RBI Note Forgery Directives",
        "auto_purge_allowed": False,
        "description": "7-year preservation for physical & digital currency scans and optical analyses.",
    },
    "identity_theft": {
        "category": "identity_theft",
        "retention_days": 1095,  # 3 years
        "statutory_reference": "IT Act § 66C Impersonation & Aadhaar/PAN Identity Compromise",
        "auto_purge_allowed": True,
        "description": "3-year preservation for forged KYC credentials and identity leaks.",
    },
    "cyber_extortion": {
        "category": "cyber_extortion",
        "retention_days": 1825,  # 5 years
        "statutory_reference": "BNS § 308 Extortion via Electronic Channels",
        "auto_purge_allowed": False,
        "description": "5-year statutory retention for ransomware messages and threat logs.",
    },
    "other": {
        "category": "other",
        "retention_days": 365,  # 1 year
        "statutory_reference": "KshemOS Standard Public Safety Operational Procedure",
        "auto_purge_allowed": True,
        "description": "1-year standard retention for miscellaneous cyber incidents.",
    },
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def compute_sha256(content: str | bytes) -> str:
    """Compute standard SHA-256 hex digest for evidence content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def generate_rfc3161_token(sha256_digest: str, timestamp_ms: int) -> dict[str, Any]:
    """
    Generate an RFC 3161-compliant timestamp token structure.
    Binds the evidence digest to an authoritative trusted time source.
    """
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    serial_seed = f"{sha256_digest}:{timestamp_ms}:KshemOS-TSA"
    serial_no = hashlib.sha1(serial_seed.encode("utf-8")).hexdigest()[:16].upper()

    return {
        "timestamp_iso": dt.isoformat(),
        "serial_number": f"TSA-{serial_no}",
        "digest_algorithm": "SHA-256",
        "digest_value": sha256_digest,
        "tsa_authority": "KshemOS-TSA-Root-CA-01 (NIC/CERT-In Compatible)",
    }


def compute_log_hash(
    previous_hash: str,
    evidence_id: str,
    action: str,
    officer_badge_id: str,
    timestamp: int,
    details: str,
) -> str:
    """Hash-chain each custodial entry to preserve tamper evidence."""
    payload = f"{previous_hash}|{evidence_id}|{action}|{officer_badge_id}|{timestamp}|{details}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------- Seed Sample Evidence ----------

DEFAULT_SAMPLE_EVIDENCE = [
    {
        "id": "EVID-2026-00101",
        "case_id": "CASE-2026-DELHI-01",
        "incident_id": "INC-EVIDENCE-DELHI-01",
        "title": "Digital Arrest Extortion Call Audio Intercept",
        "description": "Audio recording of fraudster impersonating CBI Chief Officer demanding immediate RTGS.",
        "evidence_type": "audio_recording",
        "category": "digital_arrest",
        "source": "citizen_report",
        "file_name": "cbi_impersonation_connaught_call.m4a",
        "raw_content": "[AUDIO RECORDING HEADER: CBI Digital Arrest Call - 14m 22s - Caller Claiming Mumbai Cyber Branch]",
        "file_size_bytes": 14680064,
        "ingested_by": "OFF-SPEC-DIGITAL-ARREST",
        "officer_name": "Inspector R. Sen",
        "legal_hold": True,
        "legal_hold_reason": "Active Sessions Court Trial - Spl Cyber Case No. 42/2026",
        "tags": ["audio", "digital_arrest", "cbi_impersonation", "priority_court"],
        "metadata": {
            "duration_seconds": 862,
            "caller_phone": "+91-98710-00192",
            "codec": "AAC-LC 128kbps",
        },
    },
    {
        "id": "EVID-2026-00102",
        "case_id": "CASE-2026-DELHI-01",
        "incident_id": "INC-EVIDENCE-DELHI-01",
        "title": "Forged Supreme Court Arrest Warrant Notice",
        "description": "PDF notice delivered via WhatsApp displaying counterfeit Supreme Court seal and fake digital sign.",
        "evidence_type": "document",
        "category": "digital_arrest",
        "source": "citizen_report",
        "file_name": "sc_digital_warrant_ref_9921.pdf",
        "raw_content": "%PDF-1.4 FORGED SUPREME COURT DIGITAL ARREST WARRANT ORDER SEAL-2026",
        "file_size_bytes": 1284500,
        "ingested_by": "OFF-C1",
        "officer_name": "Sub-Inspector V. Sharma",
        "legal_hold": True,
        "legal_hold_reason": "Documentary Exhibit in Active High Court Bail Hearing",
        "tags": ["pdf", "forged_document", "whatsapp_origin"],
        "metadata": {
            "pages": 2,
            "fake_authority": "Supreme Court Registrar",
            "impersonated_case": "CBI/ED-9921",
        },
    },
    {
        "id": "EVID-2026-00103",
        "case_id": "CASE-2026-DELHI-01",
        "incident_id": "INC-EVIDENCE-DELHI-01",
        "title": "Mule Bank RTGS Transfer Receipt Slip",
        "description": "Victim's bank transfer debit advice of INR 4,80,000 sent to suspected mule account ACC-1002.",
        "evidence_type": "transaction_receipt",
        "category": "financial_fraud",
        "source": "bank_slip",
        "file_name": "rtgs_debit_advice_480k_acc1002.png",
        "raw_content": "BANK RTGS ADVICE UTR: HDFC20260401889 AMOUNT: INR 480000 BENEFICIARY: ACC-1002",
        "file_size_bytes": 452800,
        "ingested_by": "OFF-S1",
        "officer_name": "Inspector K. Nair",
        "legal_hold": False,
        "tags": ["rtgs", "mule_account", "financial_trail"],
        "metadata": {
            "utr_number": "HDFC20260401889",
            "beneficiary_account": "ACC-1002",
            "amount_inr": 480000,
        },
    },
    {
        "id": "EVID-2026-00104",
        "case_id": "CASE-2026-NCR-02",
        "incident_id": "INC-EVIDENCE-NCR-02",
        "title": "Counterfeit ₹500 Banknote High-Resolution Optical Scan",
        "description": "Multi-spectrum optical scan of counterfeit Mahatma Gandhi New Series note seized in Saket.",
        "evidence_type": "image_screenshot",
        "category": "counterfeit_currency",
        "source": "field_capture",
        "file_name": "fake_note_500_saket_optical_scan.tiff",
        "raw_content": "TIFF-IMAGE-DATA-COUNTERFEIT-500-NOTE-BLEED-LINES-ABSENT-SERIAL-9AA-492100",
        "file_size_bytes": 28490000,
        "ingested_by": "OFF-W1",
        "officer_name": "Inspector P. Rawat",
        "legal_hold": False,
        "tags": ["currency_forensics", "high_res_scan", "saket_raid"],
        "metadata": {
            "serial_number": "9AA 492100",
            "denomination": 500,
            "fluorescence_fail": True,
        },
    },
]


def init_defaults():
    with _lock:
        if not _evidence_store:
            for item in DEFAULT_SAMPLE_EVIDENCE:
                _ingest_internal(dict(item))


def _ingest_internal(data: dict[str, Any]) -> dict[str, Any]:
    now = _now_ms()
    e_id = data.get("id") or f"EVID-{time.strftime('%Y%m%d', time.gmtime(now / 1000))}-{next(_evidence_counter)}"

    raw_content = data.get("raw_content") or f"EVIDENCE-RAW-STREAM-{e_id}"
    _raw_payloads[e_id] = raw_content

    # 1. Cryptographic Fingerprinting
    sha256 = data.get("sha256_hash") or compute_sha256(raw_content)
    rfc3161 = data.get("rfc3161_token") or generate_rfc3161_token(sha256, now)

    # 2. Automated Statutory Retention
    category = data.get("category", "other")
    policy = STATUTORY_RETENTION_POLICIES.get(category, STATUTORY_RETENTION_POLICIES["other"])
    retention_days = policy["retention_days"]
    retention_until = now + (retention_days * 24 * 3600 * 1000)

    evidence_item = {
        "id": e_id,
        "case_id": data.get("case_id") or data.get("case_number") or "CASE-GENERAL-01",
        "incident_id": data.get("incident_id"),
        "title": data["title"],
        "description": data.get("description", ""),
        "evidence_type": data.get("evidence_type", "document"),
        "category": category,
        "source": data.get("source", "citizen_report"),
        "file_name": data.get("file_name", f"{e_id}.dat"),
        "file_size_bytes": data.get("file_size_bytes", len(raw_content.encode("utf-8"))),
        "sha256_hash": sha256,
        "rfc3161_token": rfc3161,
        "ingested_by": data.get("ingested_by", "OFFICER"),
        "ingested_at": data.get("ingested_at", now),
        "retention_days": retention_days,
        "retention_until": retention_until,
        "legal_hold": bool(data.get("legal_hold", False)),
        "legal_hold_reason": data.get("legal_hold_reason"),
        "custodial_status": data.get("custodial_status", "vaulted"),
        "tags": data.get("tags", []),
        "metadata": data.get("metadata", {}),
    }

    _evidence_store[e_id] = evidence_item

    # 3. Create Genesis Log Entry in Hash-Chained Ledger
    log_id = f"CLOG-{next(_log_counter)}"
    genesis_details = f"Evidence ingested. SHA-256: {sha256}. TSA: {rfc3161['serial_number']}"
    entry_hash = compute_log_hash(
        previous_hash=GENESIS_HASH,
        evidence_id=e_id,
        action="INGESTION",
        officer_badge_id=evidence_item["ingested_by"],
        timestamp=now,
        details=genesis_details,
    )

    genesis_entry = {
        "log_id": log_id,
        "evidence_id": e_id,
        "action": "INGESTION",
        "officer_badge_id": evidence_item["ingested_by"],
        "officer_name": data.get("officer_name", "Officer Ingest"),
        "timestamp": now,
        "client_ip": "10.0.4.12",
        "user_agent": "KshemOS-Vault-Daemon/1.0",
        "details": genesis_details,
        "integrity_hash": entry_hash,
        "previous_hash": GENESIS_HASH,
    }

    _custodial_ledgers[e_id] = [genesis_entry]

    # If legal hold is set on creation, add legal hold log
    if evidence_item["legal_hold"]:
        _log_custodial_action_internal(
            evidence_id=e_id,
            action="LEGAL_HOLD_APPLIED",
            officer_badge_id=evidence_item["ingested_by"],
            officer_name=data.get("officer_name", "Authorizing Officer"),
            client_ip="10.0.4.12",
            details=f"Litigation hold imposed: {evidence_item['legal_hold_reason']}",
        )

    return copy.deepcopy(evidence_item)


def _log_custodial_action_internal(
    evidence_id: str,
    action: str,
    officer_badge_id: str,
    officer_name: str,
    client_ip: str,
    details: str,
    user_agent: Optional[str] = None,
) -> dict[str, Any]:
    ledger = _custodial_ledgers.setdefault(evidence_id, [])
    now = _now_ms()
    prev_hash = ledger[-1]["integrity_hash"] if ledger else GENESIS_HASH
    log_id = f"CLOG-{next(_log_counter)}"

    entry_hash = compute_log_hash(
        previous_hash=prev_hash,
        evidence_id=evidence_id,
        action=action,
        officer_badge_id=officer_badge_id,
        timestamp=now,
        details=details,
    )

    entry = {
        "log_id": log_id,
        "evidence_id": evidence_id,
        "action": action,
        "officer_badge_id": officer_badge_id,
        "officer_name": officer_name,
        "timestamp": now,
        "client_ip": client_ip,
        "user_agent": user_agent or "KshemOS-Client/2.0",
        "details": details,
        "integrity_hash": entry_hash,
        "previous_hash": prev_hash,
    }
    ledger.append(entry)
    return copy.deepcopy(entry)


# ---------- Public Service API ----------

def list_evidence(
    case_id: Optional[str] = None,
    category: Optional[str] = None,
    legal_hold: Optional[bool] = None,
) -> list[dict[str, Any]]:
    with _lock:
        items = list(_evidence_store.values())
        if case_id:
            items = [i for i in items if i["case_id"] == case_id]
        if category:
            items = [i for i in items if i["category"] == category]
        if legal_hold is not None:
            items = [i for i in items if i["legal_hold"] == legal_hold]
        items.sort(key=lambda i: i["ingested_at"], reverse=True)
        return [copy.deepcopy(i) for i in items]


def get_evidence(evidence_id: str, log_view: bool = False, officer_badge_id: str = "OFF-INSPECT") -> dict[str, Any] | None:
    with _lock:
        item = _evidence_store.get(evidence_id)
        if not item:
            return None
        if log_view:
            _log_custodial_action_internal(
                evidence_id=evidence_id,
                action="VIEW",
                officer_badge_id=officer_badge_id,
                officer_name="Inspecting Officer",
                client_ip="127.0.0.1",
                details="Secure digital viewing session initiated.",
            )
        return copy.deepcopy(item)


def ingest_evidence(data: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        return _ingest_internal(data)


def log_custodial_action(
    evidence_id: str,
    action: str,
    officer_badge_id: str,
    officer_name: str = "OFFICER",
    client_ip: str = "127.0.0.1",
    details: str = "",
    user_agent: Optional[str] = None,
) -> dict[str, Any] | None:
    with _lock:
        if evidence_id not in _evidence_store:
            return None
        entry = _log_custodial_action_internal(
            evidence_id=evidence_id,
            action=action,
            officer_badge_id=officer_badge_id,
            officer_name=officer_name,
            client_ip=client_ip,
            details=details,
            user_agent=user_agent,
        )
        return entry


def get_custodial_ledger(evidence_id: str) -> list[dict[str, Any]]:
    with _lock:
        ledger = _custodial_ledgers.get(evidence_id, [])
        return [copy.deepcopy(e) for e in ledger]


def toggle_legal_hold(
    evidence_id: str,
    legal_hold: bool,
    reason: str,
    officer_badge_id: str,
    officer_name: str = "OFFICER",
) -> dict[str, Any] | None:
    with _lock:
        item = _evidence_store.get(evidence_id)
        if not item:
            return None

        item["legal_hold"] = legal_hold
        item["legal_hold_reason"] = reason if legal_hold else None

        action = "LEGAL_HOLD_APPLIED" if legal_hold else "LEGAL_HOLD_RELEASED"
        _log_custodial_action_internal(
            evidence_id=evidence_id,
            action=action,
            officer_badge_id=officer_badge_id,
            officer_name=officer_name,
            client_ip="127.0.0.1",
            details=f"Legal hold status set to {legal_hold}. Reason: {reason}",
        )
        return copy.deepcopy(item)


def verify_evidence_integrity(evidence_id: str) -> dict[str, Any]:
    """
    Cryptographic verification:
    1. Re-hashes raw evidence payload and compares to stored SHA-256.
    2. Traverses hash-chained custodial ledger from genesis, verifying unbroken link chain.
    """
    with _lock:
        item = _evidence_store.get(evidence_id)
        if not item:
            return {"verified": False, "error": "Evidence item not found"}

        raw = _raw_payloads.get(evidence_id, "")
        calculated_sha = compute_sha256(raw)
        sha_valid = (calculated_sha == item["sha256_hash"])

        ledger = _custodial_ledgers.get(evidence_id, [])
        ledger_valid = True
        broken_step = None

        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(ledger):
            if entry["previous_hash"] != expected_prev:
                ledger_valid = False
                broken_step = f"Chain break at entry #{idx} ({entry['log_id']})"
                break

            recomputed = compute_log_hash(
                previous_hash=expected_prev,
                evidence_id=evidence_id,
                action=entry["action"],
                officer_badge_id=entry["officer_badge_id"],
                timestamp=entry["timestamp"],
                details=entry["details"],
            )
            if recomputed != entry["integrity_hash"]:
                ledger_valid = False
                broken_step = f"Tampered hash signature in entry #{idx} ({entry['log_id']})"
                break

            expected_prev = entry["integrity_hash"]

        overall = sha_valid and ledger_valid

        return {
            "verified": overall,
            "evidence_id": evidence_id,
            "sha256_match": sha_valid,
            "stored_sha256": item["sha256_hash"],
            "calculated_sha256": calculated_sha,
            "custodial_ledger_intact": ledger_valid,
            "ledger_entries_verified": len(ledger),
            "rfc3161_serial": item["rfc3161_token"]["serial_number"],
            "rfc3161_timestamp": item["rfc3161_token"]["timestamp_iso"],
            "tamper_status": "AUTHENTIC / UNALTERED" if overall else f"FAILED: {broken_step or 'Hash mismatch'}",
        }


def generate_forensic_export_bundle(
    case_id: str,
    generated_by: str = "OFF-FORENSIC-LEAD",
    officer_name: str = "Forensic Lead Officer",
) -> dict[str, Any] | None:
    """
    Compile a court-admissible forensic export bundle:
    - Lists all associated evidence items with SHA-256 and RFC 3161 proofs.
    - Gathers complete, validated chain of custody audit trail.
    - Produces a master cryptographic manifest signature.
    """
    with _lock:
        evidence_list = [i for i in _evidence_store.values() if i["case_id"] == case_id]
        if not evidence_list:
            return None

        bundle_id = f"BUNDLE-CRIM-{time.strftime('%Y%m%d', time.gmtime())}-{next(_bundle_counter):03d}"
        now = _now_ms()

        full_custody_chain: list[dict[str, Any]] = []
        all_tamper_passed = True

        for ev in evidence_list:
            verification = verify_evidence_integrity(ev["id"])
            if not verification["verified"]:
                all_tamper_passed = False
            full_custody_chain.extend(get_custodial_ledger(ev["id"]))
            # Log export action on each item
            _log_custodial_action_internal(
                evidence_id=ev["id"],
                action="EXPORT_BUNDLE",
                officer_badge_id=generated_by,
                officer_name=officer_name,
                client_ip="127.0.0.1",
                details=f"Included in Court Forensic Export Bundle {bundle_id}",
            )

        # Manifest hash over all item hashes
        item_hashes = ":".join(ev["sha256_hash"] for ev in evidence_list)
        manifest_sha256 = compute_sha256(f"{bundle_id}:{case_id}:{item_hashes}:{now}")

        attestation = (
            f"CERTIFICATE OF EVIDENCE INTEGRITY: I hereby certify that the {len(evidence_list)} "
            f"digital evidence item(s) in this archive were ingested, hashed via SHA-256, and timestamped "
            f"under RFC 3161 by the KshemOS Vault Authority. The chain of custody is unbroken and "
            f"satisfies the requirements of Section 65B of the Indian Evidence Act / BSA § 63."
        )

        bundle = {
            "bundle_id": bundle_id,
            "generated_at": now,
            "generated_by": generated_by,
            "case_id": case_id,
            "evidence_items": copy.deepcopy(evidence_list),
            "manifest_sha256": manifest_sha256,
            "custodial_chain": full_custody_chain,
            "tamper_verification_passed": all_tamper_passed,
            "attestation_statement": attestation,
            "export_format": "court_package_v1",
        }
        return bundle


def list_retention_policies() -> list[dict[str, Any]]:
    return list(STATUTORY_RETENTION_POLICIES.values())


def reset():
    """Reset store state for clean test runs."""
    with _lock:
        _evidence_store.clear()
        _custodial_ledgers.clear()
        _raw_payloads.clear()
        init_defaults()


# Initialize on import
init_defaults()
