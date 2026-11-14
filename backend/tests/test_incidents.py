import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import incidents
from app import security

TOKEN = "test-token-that-is-long-enough-for-security-123456"

client = TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})

DIGITAL_ARREST = (
    "This is the CBI. You are under digital arrest. Do not tell anyone. "
    "Transfer the verification amount now or you will be arrested immediately."
)


@pytest.fixture(autouse=True)
def clean_store(monkeypatch):
    monkeypatch.setenv(
        "KSHEMOS_API_TOKENS",
        f'{{"{TOKEN}": "OFF-CMD-METRO"}}',
    )
    monkeypatch.setattr(
        security.incident_notifications,
        "get_registered_officer",
        lambda officer_id: {
            "officer_id": "OFF-CMD-METRO",
            "role": "commander",
            "jurisdiction_id": "JUR-DELHI-METRO",
            "regions": ["North Zone", "East Zone", "Central Zone", "Unspecified"],
        } if officer_id == "OFF-CMD-METRO" else None,
    )
    incidents.reset()
    yield
    incidents.reset()

def test_feed_starts_empty_with_zero_staffing():
    body = client.get("/api/incidents").json()

    assert body["incidents"] == []
    assert body["regions"] == ["North Zone", "East Zone", "Central Zone"]
    assert all(s["officers_on_duty"] == 0 for s in body["staffing"])


def test_created_incident_appears_in_feed_with_scored_severity():
    res = client.post(
        "/api/incidents",
        json={"category": "scam_call", "description": DIGITAL_ARREST, "region": "East Zone"},
    )
    assert res.status_code == 201
    created = res.json()

    assert created["status"] == "new"
    assert created["region"] == "East Zone"
    assert created["severity"] in ("high", "critical")
    assert created["first_response_at"] is None

    feed = client.get("/api/incidents").json()
    assert [i["id"] for i in feed["incidents"]] == [created["id"]]


def test_unknown_region_is_kept_as_unspecified():
    created = client.post(
        "/api/incidents", json={"category": "other", "description": "Odd SMS", "region": "Mars"}
    ).json()
    assert created["region"] == incidents.UNSPECIFIED_REGION


def test_citizen_report_creates_an_incident():
    res = client.post(
        "/api/citizen/report",
        json={
            "reporter_name": "Test",
            "category": "scam_call",
            "description": DIGITAL_ARREST,
            "region": "North Zone",
        },
    )
    assert res.status_code == 200
    incident_id = res.json()["incident_id"]

    feed = client.get("/api/incidents").json()
    assert any(i["id"] == incident_id and i["region"] == "North Zone" for i in feed["incidents"])


def test_officer_updates_track_response_escalation_and_resolution():
    incident = client.post(
        "/api/incidents", json={"category": "other", "description": "Fake KYC SMS", "region": "East Zone"}
    ).json()
    url = f"/api/incidents/{incident['id']}"

    assigned = client.patch(url, json={"assigned_to": "OFF-E1"}).json()
    assert assigned["assigned_to"] == "OFF-E1"
    assert assigned["first_response_at"] is not None

    raised = client.patch(url, json={"severity": "critical"}).json()
    assert raised["previous_severity"] == incident["severity"]
    assert raised["severity"] == "critical"

    resolved = client.patch(url, json={"status": "resolved"}).json()
    assert resolved["resolved_at"] is not None

    reopened = client.patch(url, json={"status": "in_progress"}).json()
    assert reopened["resolved_at"] is None

    unassigned = client.patch(url, json={"assigned_to": ""}).json()
    assert unassigned["assigned_to"] is None
    assert unassigned["first_response_at"] == assigned["first_response_at"], "first response is kept"


def test_update_rejects_invalid_values_and_unknown_incidents():
    incident = client.post("/api/incidents", json={"category": "other", "description": "x"}).json()

    assert client.patch(f"/api/incidents/{incident['id']}", json={"status": "closed"}).status_code == 422
    assert client.patch("/api/incidents/INC-9999", json={"status": "triaged"}).status_code == 404


def test_staffing_updates_and_validation():
    res = client.put("/api/incidents/staffing/East Zone", json={"officers_on_duty": 3})
    assert res.status_code == 200

    staffing = {s["region"]: s["officers_on_duty"] for s in client.get("/api/incidents").json()["staffing"]}
    assert staffing["East Zone"] == 3

    assert client.put("/api/incidents/staffing/Mars", json={"officers_on_duty": 1}).status_code == 403
    assert client.put("/api/incidents/staffing/East Zone", json={"officers_on_duty": -1}).status_code == 422


def test_derive_title_truncates_long_first_sentence():
    assert incidents.derive_title("Short one. Second sentence.") == "Short one"
    long_title = incidents.derive_title("word " * 40)
    assert len(long_title) == incidents.TITLE_MAX_LENGTH
    assert long_title.endswith("…")
