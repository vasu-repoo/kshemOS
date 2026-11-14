import json

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import security


TOKEN = "test-token-that-is-long-enough-for-security-123456"


def credentials(token=TOKEN):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_missing_credentials_returns_401():
    with pytest.raises(HTTPException) as exc:
        security.get_current_principal(None)
    assert exc.value.status_code == 401


def test_invalid_token_returns_401(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        json.dumps({TOKEN: "OFF-DELHI-101"}),
    )
    with pytest.raises(HTTPException) as exc:
        security.get_current_principal(credentials("invalid-token"))
    assert exc.value.status_code == 401


def test_unknown_officer_returns_401(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        json.dumps({TOKEN: "OFF-UNKNOWN"}),
    )
    monkeypatch.setattr(
        security.incident_notifications,
        "get_registered_officer",
        lambda officer_id: None,
    )
    with pytest.raises(HTTPException) as exc:
        security.get_current_principal(credentials())
    assert exc.value.status_code == 401


def test_valid_token_resolves_trusted_principal(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        json.dumps({TOKEN: "OFF-DELHI-101"}),
    )
    monkeypatch.setattr(
        security.incident_notifications,
        "get_registered_officer",
        lambda officer_id: {
            "officer_id": officer_id,
            "role": "responder",
            "jurisdiction_id": "JUR-DELHI-METRO",
            "regions": ["Central Zone", "North Zone"],
        },
    )

    principal = security.get_current_principal(credentials())

    assert principal.officer_id == "OFF-DELHI-101"
    assert principal.role == "responder"
    assert principal.jurisdiction_id == "JUR-DELHI-METRO"
    assert "Central Zone" in principal.regions


def test_role_requirement_rejects_responder_as_commander():
    principal = security.Principal(
        officer_id="OFF-DELHI-101",
        role="responder",
        jurisdiction_id="JUR-DELHI-METRO",
        regions=("Central Zone",),
    )
    with pytest.raises(HTTPException) as exc:
        security.require_roles("commander")(principal)
    assert exc.value.status_code == 403


def test_region_access_rejects_other_jurisdiction():
    principal = security.Principal(
        officer_id="OFF-DELHI-101",
        role="responder",
        jurisdiction_id="JUR-DELHI-METRO",
        regions=("Central Zone",),
    )
    with pytest.raises(HTTPException) as exc:
        security.require_region_access("South Zone", principal)
    assert exc.value.status_code == 403


def test_region_access_rejects_unassigned_region():
    principal = security.Principal(
        officer_id="OFF-DELHI-101",
        role="responder",
        jurisdiction_id="JUR-DELHI-METRO",
        regions=("Central Zone",),
    )
    with pytest.raises(HTTPException) as exc:
        security.require_region_access("North Zone", principal)
    assert exc.value.status_code == 403
