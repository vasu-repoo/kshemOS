from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.services import audit, incident_notifications

bearer_scheme = HTTPBearer(auto_error=False)

ROLE_LEVELS = {
    "responder": 1,
    "supervisor": 2,
    "commander": 3,
}


@dataclass(frozen=True)
class Principal:
    officer_id: str
    role: str
    jurisdiction_id: str
    regions: tuple[str, ...]


def _deny(
    detail: str,
    status_code: int,
    *,
    actor_id: str = "anonymous",
    action: str = "authentication_denied",
) -> None:
    audit.record_event(
        actor_id=actor_id,
        actor_role="unknown",
        action=action,
        resource_type="api",
        outcome="denied",
        source="authorization",
        metadata={"reason": detail, "status_code": status_code},
    )
    headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else None
    raise HTTPException(
        status_code=status_code,
        detail=detail,
        headers=headers,
    )


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Principal:
    if credentials is None:
        _deny("Authentication is required", status.HTTP_401_UNAUTHORIZED)

    configured = os.getenv("KSHEMOS_API_TOKENS", "")
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    try:
        token_map = json.loads(configured)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication configuration is invalid",
        )

    if not isinstance(token_map, dict):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication configuration must be an object",
        )

    valid_entries = [
        (token, officer_id.strip())
        for token, officer_id in token_map.items()
        if isinstance(token, str)
        and len(token) >= 32
        and isinstance(officer_id, str)
        and officer_id.strip()
    ]

    if not valid_entries:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No valid API credentials are configured",
        )

    supplied = credentials.credentials.encode("utf-8")
    officer_id = None

    for token, configured_officer in valid_entries:
        if secrets.compare_digest(supplied, token.encode("utf-8")):
            officer_id = configured_officer

    if officer_id is None:
        _deny("Invalid bearer credentials", status.HTTP_401_UNAUTHORIZED)

    officer = incident_notifications.get_registered_officer(officer_id)
    if officer is None:
        _deny(
            "Credential is not linked to a registered officer",
            status.HTTP_401_UNAUTHORIZED,
        )

    role = officer.get("role")
    jurisdiction_id = officer.get("jurisdiction_id")
    regions = officer.get("regions")

    if (
        role not in ROLE_LEVELS
        or not isinstance(jurisdiction_id, str)
        or not jurisdiction_id
        or not isinstance(regions, list)
        or not all(isinstance(region, str) for region in regions)
    ):
        _deny(
            "Registered officer has an invalid authorization profile",
            status.HTTP_403_FORBIDDEN,
            actor_id=officer_id,
        )

    return Principal(
        officer_id=officer_id,
        role=role,
        jurisdiction_id=jurisdiction_id,
        regions=tuple(regions),
    )


def require_roles(*allowed_roles: str):
    if not allowed_roles or any(role not in ROLE_LEVELS for role in allowed_roles):
        raise ValueError("A valid allowed role is required")

    def dependency(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if principal.role not in allowed_roles:
            _deny(
                "Insufficient role permissions",
                status.HTTP_403_FORBIDDEN,
                actor_id=principal.officer_id,
                action="authorization_role_denied",
            )
        return principal

    return dependency


def require_region_access(region: str, principal: Principal) -> None:
    jurisdiction_id = incident_notifications.resolve_jurisdiction(region)
    if (
        principal.jurisdiction_id != jurisdiction_id
        or ("*" not in principal.regions and region not in principal.regions)
    ):
        _deny(
            "Access to this jurisdiction or region is forbidden",
            status.HTTP_403_FORBIDDEN,
            actor_id=principal.officer_id,
            action="authorization_scope_denied",
        )
