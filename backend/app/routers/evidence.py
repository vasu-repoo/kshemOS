
"""
FastAPI router for the digital evidence vault and secure upload links.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CustodialActionRequest,
    EvidenceIngestRequest,
    EvidenceItem,
    ForensicExportBundle,
    LegalHoldToggleRequest,
    CreateUploadLinkRequest,
    RevokeUploadLinkRequest,
    UploadEvidenceViaLinkRequest,
    SecureUploadLink,
    UploadLinkValidationResponse,
)
from app.security import (
    Principal,
    get_current_principal,
    require_roles,
    require_region_access,
)
from app.services import incidents, incident_notifications
from app.services import evidence as evidence_service
from app.services import evidence_upload_link as upload_link_service

router = APIRouter(prefix="/api/evidence", tags=["Digital Evidence Vault & Custody"])

def _require_evidence_access(evidence: dict, principal: Principal) -> None:
    incident_id = evidence.get("incident_id")
    if not incident_id:
        raise HTTPException(status_code=403, detail="Evidence is not linked to an authorized incident")

    with incidents._lock:
        incident = incidents._incidents.get(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    require_region_access(incident.get("region", ""), principal)


def _get_authorized_evidence(evidence_id: str, principal: Principal) -> dict:
    item = evidence_service.get_evidence(evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    _require_evidence_access(item, principal)
    return item


def _require_case_access(case_id: str, principal: Principal) -> list[dict]:
    if not case_id:
        raise HTTPException(status_code=400, detail="Case ID is required")

    items = evidence_service.list_evidence(case_id=case_id)
    if not items:
        raise HTTPException(status_code=404, detail="Case evidence not found")

    for item in items:
        _require_evidence_access(item, principal)

    return items


def _upload_link_incident_id(link) -> Optional[str]:
    if isinstance(link, dict):
        return link.get("incident_id") or link.get("report_id")
    return getattr(link, "incident_id", None) or getattr(link, "report_id", None)


@router.get("/items", response_model=list[EvidenceItem])
def list_evidence(
    case_id: Optional[str] = None,
    category: Optional[str] = None,
    legal_hold: Optional[bool] = None,
    principal: Principal = Depends(get_current_principal),
):
    items = evidence_service.list_evidence(
        case_id=case_id if isinstance(case_id, str) else None,
        category=category if isinstance(category, str) else None,
        legal_hold=legal_hold if isinstance(legal_hold, bool) else None,
    )
    allowed = []
    for item in items:
        try:
            _require_evidence_access(item, principal)
            allowed.append(item)
        except HTTPException:
            continue
    return allowed


@router.get("/items/{evidence_id}")
def get_evidence(
    evidence_id: str,
    log_view: bool = False,
    principal: Principal = Depends(get_current_principal),
):
    item = _get_authorized_evidence(evidence_id, principal)
    if log_view:
        evidence_service.log_custodial_action(
            evidence_id=evidence_id,
            action="VIEW",
            officer_badge_id=principal.officer_id,
            officer_name=principal.officer_id,
            details="Secure digital viewing session initiated.",
        )
    return item


@router.post("/ingest", response_model=EvidenceItem, status_code=201)
def ingest_evidence(
    payload: EvidenceIngestRequest,
    principal: Principal = Depends(get_current_principal),
):
    data = payload.model_dump()
    incident_id = data.get("incident_id")
    if not incident_id:
        raise HTTPException(status_code=400, detail="Evidence must be linked to an incident")

    with incidents._lock:
        incident = incidents._incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    require_region_access(incident.get("region", ""), principal)
    data["ingested_by"] = principal.officer_id
    data["officer_badge_id"] = principal.officer_id
    return evidence_service.ingest_evidence(data)


@router.get("/items/{evidence_id}/custody-ledger")
def get_custodial_ledger(
    evidence_id: str,
    principal: Principal = Depends(get_current_principal),
):
    _get_authorized_evidence(evidence_id, principal)
    return evidence_service.get_custodial_ledger(evidence_id)


@router.post("/items/{evidence_id}/log-action")
def log_action(
    evidence_id: str,
    payload: CustodialActionRequest,
    principal: Principal = Depends(get_current_principal),
):
    _get_authorized_evidence(evidence_id, principal)
    entry = evidence_service.log_custodial_action(
        evidence_id=evidence_id,
        action=payload.action,
        officer_badge_id=principal.officer_id,
        officer_name=principal.officer_id,
        details=payload.details,
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return entry


@router.post("/items/{evidence_id}/legal-hold")
def toggle_legal_hold(
    evidence_id: str,
    payload: LegalHoldToggleRequest,
    principal: Principal = Depends(require_roles("supervisor", "commander")),
):
    _get_authorized_evidence(evidence_id, principal)
    item = evidence_service.toggle_legal_hold(
        evidence_id=evidence_id,
        legal_hold=payload.legal_hold,
        reason=payload.reason,
        officer_badge_id=principal.officer_id,
        officer_name=principal.officer_id,
    )
    if not item:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return item


@router.post("/items/{evidence_id}/verify")
def verify_integrity(
    evidence_id: str,
    principal: Principal = Depends(get_current_principal),
):
    _get_authorized_evidence(evidence_id, principal)
    result = evidence_service.verify_evidence_integrity(evidence_id)
    if not result.get("verified") and result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/forensic-bundle", response_model=ForensicExportBundle)
def generate_forensic_bundle(
    case_id: str = Query(...),
    principal: Principal = Depends(require_roles("supervisor", "commander")),
):
    _require_case_access(case_id, principal)
    bundle = evidence_service.generate_forensic_export_bundle(
        case_id=case_id,
        generated_by=principal.officer_id,
        officer_name=principal.officer_id,
    )
    if not bundle:
        raise HTTPException(status_code=404, detail="Could not generate forensic bundle")
    return bundle


@router.get("/retention-policies")
def list_retention_policies(
    principal: Principal = Depends(get_current_principal),
):
    return evidence_service.list_retention_policies()


@router.post("/upload-links", response_model=SecureUploadLink, status_code=201)
def create_upload_link(
    payload: CreateUploadLinkRequest,
    principal: Principal = Depends(require_roles("supervisor", "commander")),
):
    data = payload.model_dump()
    incident_id = data.get("incident_id") or data.get("report_id")
    if not incident_id:
        raise HTTPException(status_code=400, detail="Upload link must reference an incident")
    with incidents._lock:
        incident = incidents._incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    require_region_access(incident.get("region", ""), principal)
    data["created_by_badge"] = principal.officer_id
    data["officer_name"] = principal.officer_id
    return upload_link_service.create_upload_link(data)


@router.get("/upload-links", response_model=list[SecureUploadLink])
def list_upload_links(
    report_id: Optional[str] = None,
    status: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    links = upload_link_service.list_upload_links(
        report_id=report_id if isinstance(report_id, str) else None,
        status=status if isinstance(status, str) else None,
    )
    allowed = []
    for link in links:
        incident_id = _upload_link_incident_id(link)
        if not incident_id:
            continue
        with incidents._lock:
            incident = incidents._incidents.get(incident_id)
        if incident:
            try:
                require_region_access(incident.get("region", ""), principal)
                allowed.append(link)
            except HTTPException:
                pass
    return allowed


@router.get("/upload-links/{link_id}", response_model=SecureUploadLink)
def get_upload_link(
    link_id: str,
    principal: Principal = Depends(get_current_principal),
):
    link = upload_link_service.get_upload_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Upload link not found")
    incident_id = _upload_link_incident_id(link)
    if not incident_id:
        raise HTTPException(status_code=403, detail="Upload link has no incident")
    with incidents._lock:
        incident = incidents._incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    require_region_access(incident.get("region", ""), principal)
    return link


@router.post("/upload-links/{link_id}/revoke", response_model=SecureUploadLink)
def revoke_upload_link(
    link_id: str,
    payload: RevokeUploadLinkRequest,
    principal: Principal = Depends(require_roles("supervisor", "commander")),
):
    link = upload_link_service.get_upload_link(link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Upload link not found")
    incident_id = _upload_link_incident_id(link)
    if not incident_id:
        raise HTTPException(status_code=403, detail="Upload link has no incident")
    with incidents._lock:
        incident = incidents._incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    require_region_access(incident.get("region", ""), principal)
    return upload_link_service.revoke_upload_link(
        link_id=link_id,
        revoked_by_badge=principal.officer_id,
        officer_name=principal.officer_id,
        revocation_reason=payload.revocation_reason,
    )


@router.get("/upload/validate", response_model=UploadLinkValidationResponse)
def validate_upload_token(token: str, passcode: Optional[str] = None):
    return upload_link_service.validate_upload_token(
        token=token,
        passcode=passcode if isinstance(passcode, str) else None,
    )


@router.post("/upload/fulfill")
def fulfill_evidence_upload(payload: UploadEvidenceViaLinkRequest):
    try:
        return upload_link_service.upload_evidence_via_link(
            token=payload.token,
            upload_data=payload.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
