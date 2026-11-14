from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    Incident,
    IncidentCreateRequest,
    IncidentFeedResponse,
    IncidentUpdateRequest,
    RegionStaffing,
    StaffingUpdateRequest,
    SyncBatchRequest,
    SyncBatchResponse,
)
from app.services import incidents, incident_notifications
from app.security import (
    Principal,
    get_current_principal,
    require_roles,
    require_region_access,
)

router = APIRouter(prefix="/api/incidents", tags=["Operational Incident Dashboard"])


def _incident_for_principal(incident_id: str, principal: Principal):
    feed = incidents.get_feed()
    incident = next(
        (item for item in feed["incidents"] if item["id"] == incident_id),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    require_region_access(incident["region"], principal)
    return incident


def _validate_create(payload: IncidentCreateRequest, principal: Principal):
    region = payload.region if payload.region in incidents.REGIONS else incidents.UNSPECIFIED_REGION
    require_region_access(region, principal)


def _validate_update(
    changes: dict,
    incident: dict,
    principal: Principal,
    force: bool,
):
    if force:
        raise HTTPException(
            status_code=403,
            detail="Forced version overrides are not permitted",
        )

    if principal.role == "responder":
        if incident.get("assigned_to") != principal.officer_id:
            raise HTTPException(
                status_code=403,
                detail="Responders may update only incidents assigned to them",
            )
        forbidden = set(changes) - {"status"}
        if forbidden:
            raise HTTPException(
                status_code=403,
                detail="Responders may only update incident status",
            )


@router.get("", response_model=IncidentFeedResponse)
def feed(principal: Principal = Depends(get_current_principal)):
    data = incidents.get_feed()
    allowed = set(principal.regions)

    def can_access(region: str) -> bool:
        return (
            region in allowed
            and incident_notifications.resolve_jurisdiction(region)
            == principal.jurisdiction_id
        )

    data["incidents"] = [
        item for item in data["incidents"]
        if can_access(item.get("region", ""))
    ]
    data["regions"] = [
        region for region in data["regions"]
        if can_access(region)
    ]
    data["staffing"] = [
        item for item in data["staffing"]
        if can_access(item.get("region", ""))
    ]
    return data

@router.post("", response_model=Incident, status_code=201)
def create(
    payload: IncidentCreateRequest,
    principal: Principal = Depends(get_current_principal),
):
    _validate_create(payload, principal)
    return incidents.create_incident(**payload.model_dump())


@router.patch("/{incident_id}", response_model=Incident)
def update(
    incident_id: str,
    payload: IncidentUpdateRequest,
    principal: Principal = Depends(get_current_principal),
):
    current = _incident_for_principal(incident_id, principal)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    changes.pop("expected_version", None)
    changes.pop("force", None)
    _validate_update(changes, current, principal, payload.force)

    result = incidents.update_incident(
        incident_id,
        changes,
        expected_version=payload.expected_version,
        force=False,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if isinstance(result, dict) and result.get("conflict"):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Conflict detected: incident was modified on server",
                "conflict": True,
                "server_incident": result["server_incident"],
                "expected_version": result["expected_version"],
                "current_version": result["current_version"],
                "conflicting_fields": result["conflicting_fields"],
            },
        )
    return result


@router.post("/sync", response_model=SyncBatchResponse)
def sync_batch(
    payload: SyncBatchRequest,
    principal: Principal = Depends(get_current_principal),
):
    validated = []
    for item in payload.items:
        raw = item.model_dump()
        if raw["action"] == "create":
            if raw.get("create_payload") is None:
                raise HTTPException(400, detail="Sync create item requires create_payload")
            _validate_create(item.create_payload, principal)
            validated.append(raw)
        elif raw["action"] == "update":
            if not raw.get("incident_id") or item.changes is None:
                raise HTTPException(400, detail="Sync update item requires incident_id and changes")
            current = _incident_for_principal(raw["incident_id"], principal)
            changes = item.changes.model_dump(exclude_unset=True, exclude_none=True)
            changes.pop("expected_version", None)
            changes.pop("force", None)
            force = raw.get("force", False) or item.changes.force
            _validate_update(changes, current, principal, force)
            raw["changes"] = changes
            raw["force"] = False
            raw["expected_version"] = (
                raw.get("expected_version")
                if raw.get("expected_version") is not None
                else item.changes.expected_version
            )
            validated.append(raw)

    return incidents.sync_queue_items(validated)


@router.put("/staffing/{region}", response_model=RegionStaffing)
def update_staffing(
    region: str,
    payload: StaffingUpdateRequest,
    principal: Principal = Depends(require_roles("supervisor", "commander")),
):
    require_region_access(region, principal)
    if not incidents.set_staffing(region, payload.officers_on_duty):
        raise HTTPException(status_code=404, detail="Unknown region")
    return {"region": region, "officers_on_duty": payload.officers_on_duty}


