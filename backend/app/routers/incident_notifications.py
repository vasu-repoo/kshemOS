from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app import security
from app.security import (
    Principal,
    get_current_principal,
    require_roles,
    require_region_access,
)
from app.models import (
    IncidentNotificationPayload,
    NotificationAuditResponse,
    OfficerDirectoryEntry,
    RetryNotificationResponse,
    SendNotificationRequest,
    UpdateOfficerPreferencesRequest,
)
from app.services import incidents, incident_notifications

router = APIRouter(prefix="/api/incident-notifications", tags=["Role-Aware Incident Notifications"])

def _require_notification_access(notification: dict, principal: Principal) -> None:
    incident_id = notification.get("incident_id")
    if not incident_id:
        raise HTTPException(status_code=403, detail="Notification access denied")

    with incidents._lock:
        incident = incidents._incidents.get(incident_id)

    if not incident:
        raise HTTPException(status_code=403, detail="Notification access denied")

    require_region_access(
        incident.get("region", incidents.UNSPECIFIED_REGION),
        principal,
    )

@router.get("", response_model=NotificationAuditResponse)
def get_notifications(
    incident_id: Optional[str] = Query(None),
    recipient_id: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    principal: Principal = Depends(get_current_principal),
):
    items = incident_notifications.list_delivery_audit(
        incident_id=incident_id,
        role=role,
        event_type=event_type,
        status=status,
        limit=500,
    )

    allowed = []
    for item in items:
        try:
            _require_notification_access(item, principal)
        except HTTPException:
            continue
        if recipient_id and item.get("recipient_id") != recipient_id:
            continue
        allowed.append(item)

    allowed = allowed[:limit]
    counts = {
        "total": len(allowed),
        "delivered": sum(i.get("delivery_status") == "delivered" for i in allowed),
        "retrying": sum(i.get("delivery_status") == "retrying" for i in allowed),
        "failed": sum(i.get("delivery_status") == "failed" for i in allowed),
        "suppressed": sum("suppressed" in str(i.get("delivery_status", "")) for i in allowed),
    }

    return {**counts, "notifications": allowed}


@router.get("/stats")
def get_stats(principal: Principal = Depends(get_current_principal)):
    items = incident_notifications.list_delivery_audit(limit=500)
    allowed = []
    for item in items:
        try:
            _require_notification_access(item, principal)
        except HTTPException:
            continue
        allowed.append(item)

    return {
        "total": len(allowed),
        "delivered": sum(i.get("delivery_status") == "delivered" for i in allowed),
        "retrying": sum(i.get("delivery_status") == "retrying" for i in allowed),
        "failed": sum(i.get("delivery_status") == "failed" for i in allowed),
        "suppressed": sum("suppressed" in str(i.get("delivery_status", "")) for i in allowed),
        "unauthorized": sum(i.get("delivery_status") == "unauthorized_jurisdiction" for i in allowed),
    }

@router.get("/directory", response_model=List[OfficerDirectoryEntry])
def get_directory(principal: Principal = Depends(get_current_principal)):
    officers = incident_notifications.list_officers()
    return [
        officer for officer in officers
        if officer.get("jurisdiction_id") == principal.jurisdiction_id
        and (
            "*" in principal.regions
            or any(region in principal.regions for region in officer.get("regions", []))
        )
    ]


@router.get("/preferences/{officer_id}")
def get_preferences(
    officer_id: str,
    principal: Principal = Depends(get_current_principal),
):
    if officer_id != principal.officer_id:
        require_roles("supervisor", "commander")(principal)

    officer = incident_notifications.get_registered_officer(officer_id)
    if not officer or officer.get("jurisdiction_id") != principal.jurisdiction_id:
        raise HTTPException(status_code=404, detail="Officer not found")

    return {"officer_id": officer_id, "preferences": officer.get("preferences", {})}

@router.put("/preferences/{officer_id}")
def update_preferences(
    officer_id: str,
    payload: UpdateOfficerPreferencesRequest,
    principal: Principal = Depends(get_current_principal),
):
    if officer_id != principal.officer_id:
        require_roles("supervisor", "commander")(principal)

    officer = incident_notifications.get_registered_officer(officer_id)
    if (
        not officer
        or officer.get("jurisdiction_id") != principal.jurisdiction_id
        or not (
            "*" in principal.regions
            or any(
                region in principal.regions
                for region in officer.get("regions", [])
            )
        )
    ):
        raise HTTPException(status_code=404, detail="Officer not found")

    try:
        return incident_notifications.update_officer_preferences(
            officer_id,
            payload.preferences.model_dump(
                exclude_unset=True,
                exclude_none=True,
            ),
        )
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))


@router.post("/retry/{notification_id}", response_model=RetryNotificationResponse)
def retry_failed_notification(
    notification_id: str,
    principal: Principal = Depends(get_current_principal),
):
    require_roles("supervisor", "commander")(principal)

    notification = incident_notifications.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    _require_notification_access(notification, principal)

    try:
        updated = incident_notifications.retry_notification(
            notification_id,
            force_success=True,
        )
        return {
            "success": updated.get("delivery_status") == "delivered",
            "notification": updated,
            "message": "Notification delivery retry processed successfully.",
        }
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))

@router.post("/dispatch")
def manual_dispatch(
    payload: SendNotificationRequest,
    principal: Principal = Depends(get_current_principal),
):
    require_roles("supervisor", "commander")(principal)

    with incidents._lock:
        inc = incidents._incidents.get(payload.incident_id)

    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    require_region_access(
        inc.get("region", incidents.UNSPECIFIED_REGION),
        principal,
    )

    dispatched = incident_notifications.dispatch_incident_notifications(
        inc,
        event_type=payload.event_type,
        actor_id=principal.officer_id,
    )

    return {
        "incident_id": payload.incident_id,
        "dispatched_count": len(dispatched),
        "outcomes": dispatched,
    }