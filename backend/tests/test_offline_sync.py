import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from app import security
from app.routers import incidents as router
from app.models import (
    IncidentCreateRequest,
    IncidentUpdateRequest,
    SyncBatchRequest,
    SyncQueueItem,
)
from app.services import incidents

DELHI_TOKEN = "offline-delhi-test-token-that-is-long-enough-123456"
SOUTH_TOKEN = "offline-south-test-token-that-is-long-enough-123456"


@pytest.fixture
def principals(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        (
            f'{{"{DELHI_TOKEN}": "OFF-SUP-DELHI", '
            f'"{SOUTH_TOKEN}": "OFF-CMD-SOUTH"}}'
        ),
    )
    return {
        "delhi": security.get_current_principal(
            HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=DELHI_TOKEN
            )
        ),
        "south": security.get_current_principal(
            HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=SOUTH_TOKEN
            )
        ),
    }


def test_incident_versioning_and_concurrency(principals):
    incidents.reset()
    created = router.create(
        IncidentCreateRequest(
            category="scam_call",
            description="Field officer reported ongoing digital arrest scam.",
            region="North Zone",
        ),
        principal=principals["delhi"],
    )
    assert created["version"] == 1
    assert created["updated_at"] is not None

    # First update increments version to 2
    u1 = router.update(
        created["id"],
        IncidentUpdateRequest(status="in_progress", assigned_to="OFF-FIELD-1"),
        principal=principals["delhi"],
    )
    assert u1["version"] == 2
    assert u1["status"] == "in_progress"
    assert u1["assigned_to"] == "OFF-FIELD-1"

    # Conflicting update with stale expected_version=1 fails with 409
    with pytest.raises(Exception) as exc_info:
        router.update(
            created["id"],
            IncidentUpdateRequest(
                status="escalated",
                expected_version=1,  # Stale: server is already v2
            ),
            principal=principals["delhi"],
        )
    assert exc_info.value.status_code == 409
    conflict_detail = exc_info.value.detail
    assert conflict_detail["conflict"] is True
    assert conflict_detail["current_version"] == 2
    assert conflict_detail["expected_version"] == 1
    assert "status" in conflict_detail["conflicting_fields"]

    # Force update overrides the conflict
    with pytest.raises(HTTPException) as exc_info:
        router.update(
            created["id"],
            IncidentUpdateRequest(
                status="escalated",
                expected_version=1,
                force=True,
            ),
            principal=principals["delhi"],
        )
    assert exc_info.value.status_code == 403


def test_batch_offline_sync(principals):
    incidents.reset()
    # Create incident on HQ
    hq_inc = router.create(
        IncidentCreateRequest(
            category="other",
            description="HQ incident reported earlier.",
            region="West Zone",
        ),
        principal=principals["south"],
    )
    assert hq_inc["version"] == 1

    # Simulate HQ update to version 2
    router.update(
        hq_inc["id"],
        IncidentUpdateRequest(severity="high"),
        principal=principals["south"],
    )

    # Now field unit reconnects with a batch of 3 items:
    # Item 1: new incident created while field unit was offline
    # Item 2: update to hq_inc but field unit had expected_version=1 (conflict)
    # Item 3: update to non-existent incident (failed)
    batch = SyncBatchRequest(
        items=[
            SyncQueueItem(
                queue_id="Q-101",
                action="create",
                create_payload=IncidentCreateRequest(
                    category="fraud_tx",
                    description="Offline field intake: ATM skimming report.",
                    region="South Zone",
                ),
                client_timestamp=1700000000000,
            ),
            SyncQueueItem(
                queue_id="Q-102",
                action="update",
                incident_id=hq_inc["id"],
                changes=IncidentUpdateRequest(status="triaged", assigned_to="OFF-WEST-2"),
                expected_version=1,  # Stale, HQ is at v2
                client_timestamp=1700000001000,
                force=False,
            ),
        ]
    )

    res = router.sync_batch(batch, principal=principals["south"])
    assert res["applied_count"] == 1
    assert res["conflict_count"] == 1
    assert res["failed_count"] == 0

    r1 = next(r for r in res["results"] if r["queue_id"] == "Q-101")
    assert r1["status"] == "applied"
    assert r1["incident"]["category"] == "fraud_tx"

    r2 = next(r for r in res["results"] if r["queue_id"] == "Q-102")
    assert r2["status"] == "conflict"
    assert r2["server_incident"]["version"] == 2
    assert "status" in r2["conflicting_fields"]

    with pytest.raises(HTTPException) as exc_info:
        router.update(
            "INC-9999",
            IncidentUpdateRequest(status="in_progress"),
            principal=principals["south"],
        )
    assert exc_info.value.status_code == 404
