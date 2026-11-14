"""

Incident lifecycle for the Operational Incident Dashboard.



Every citizen report becomes an incident. Severity starts from the Digital

Arrest Agent's transcript risk band and officers can change it; status,

assignment, and staffing are updated by officers from the dashboard.



Mirrors `frontend/src/incidentDashboard.js` (`createIncident`,

`applyIncidentUpdate`), which the frontend uses when this backend is offline.

Keep the two in step.

"""

from __future__ import annotations



import itertools

import threading

import time

from typing import Any



from app.services.scam_detection import analyze_transcript
from app.services.incident_notifications import dispatch_incident_notifications



REGIONS = ["North Zone", "South Zone", "East Zone", "West Zone", "Central Zone"]

UNSPECIFIED_REGION = "Unspecified"

SEVERITIES = ["critical", "high", "medium", "low"]

STATUSES = ["new", "triaged", "in_progress", "escalated", "resolved"]



TITLE_MAX_LENGTH = 80



# In-memory, like `store.py` — swap for Postgres tables when moving beyond a

# single-process demo. Data resets when the server restarts.

_lock = threading.Lock()

_incident_id_counter = itertools.count(1)

_incidents: dict[str, dict[str, Any]] = {}

_staffing: dict[str, int] = {region: 0 for region in REGIONS}

_SAMPLE_EVIDENCE_INCIDENTS = (
    {
        "id": "INC-EVIDENCE-DELHI-01",
        "report_id": "CASE-2026-DELHI-01",
        "title": "Delhi digital arrest and financial fraud evidence",
        "description": "Investigation of digital arrest impersonation and related financial fraud.",
        "category": "digital_arrest",
        "region": "Central Zone",
    },
    {
        "id": "INC-EVIDENCE-NCR-02",
        "report_id": "CASE-2026-NCR-02",
        "title": "NCR counterfeit currency evidence",
        "description": "Investigation of counterfeit currency seized during a field operation.",
        "category": "counterfeit_currency",
        "region": "North Zone",
    },
)




def _now_ms() -> int:

    return int(time.time() * 1000)


def seed_sample_evidence_incidents() -> None:
    """Register the explicit, jurisdiction-scoped incidents that own sample evidence."""
    now = _now_ms()
    with _lock:
        for sample in _SAMPLE_EVIDENCE_INCIDENTS:
            _incidents.setdefault(
                sample["id"],
                {
                    **sample,
                    "severity": "medium",
                    "previous_severity": None,
                    "status": "in_progress",
                    "assigned_to": None,
                    "linked_account": None,
                    "opened_at": now,
                    "first_response_at": None,
                    "resolved_at": None,
                    "updated_at": now,
                    "version": 1,
                    "notes": [],
                },
            )


seed_sample_evidence_incidents()





def derive_title(description: str) -> str:

    text = " ".join(description.split())

    first_sentence = text.split(". ")[0]

    if len(first_sentence) <= TITLE_MAX_LENGTH:

        return first_sentence or "Untitled report"

    return first_sentence[: TITLE_MAX_LENGTH - 1].rstrip() + "…"





def create_incident(

    *,

    category: str,

    description: str,

    region: str | None = None,

    report_id: str | None = None,

    linked_account: str | None = None,

    now: int | None = None,

) -> dict[str, Any]:

    now = now if now is not None else _now_ms()

    risk_band = analyze_transcript(description)["risk_band"]
    severity = risk_band if risk_band in SEVERITIES else "low"



    with _lock:

        incident_id = f"INC-{next(_incident_id_counter):04d}"

        incident = {

            "id": incident_id,

            "report_id": report_id,

            "title": derive_title(description),

            "description": description,

            "category": category,

            "severity": severity,

            "previous_severity": None,

            "region": region if region in REGIONS else UNSPECIFIED_REGION,

            "status": "new",

            "assigned_to": None,

            "linked_account": linked_account or None,

            "opened_at": now,

            "first_response_at": None,

            "resolved_at": None,

            "updated_at": now,

            "version": 1,

            "notes": [],

        }

        _incidents[incident_id] = incident
        if severity == "critical":
            try:
                dispatch_incident_notifications(incident, "escalation", now=now)
            except Exception:
                pass

        return dict(incident)





def apply_update(incident: dict[str, Any], changes: dict[str, Any], now: int) -> dict[str, Any]:

    """Return a copy of `incident` with officer `changes` applied.



    The first officer action — assigning someone or moving the status off

    "new" — counts as the first response for response-target tracking.

    """

    updated = dict(incident)



    if "severity" in changes and changes["severity"] != incident["severity"]:

        updated["previous_severity"] = incident["severity"]

        updated["severity"] = changes["severity"]



    if "assigned_to" in changes:

        updated["assigned_to"] = (changes["assigned_to"] or "").strip() or None



    if "linked_account" in changes:

        updated["linked_account"] = (changes["linked_account"] or "").strip().upper() or None



    if "status" in changes:

        updated["status"] = changes["status"]

        updated["resolved_at"] = (incident["resolved_at"] or now) if changes["status"] == "resolved" else None



    if "notes" in changes and changes["notes"]:

        note_text = str(changes["notes"]).strip()

        if note_text:

            existing = list(incident.get("notes") or [])

            existing.append(note_text)

            updated["notes"] = existing



    if updated["first_response_at"] is None and (updated["assigned_to"] or updated["status"] != "new"):

        updated["first_response_at"] = now



    updated["version"] = incident.get("version", 1) + 1

    updated["updated_at"] = now



    return updated





def update_incident(

    incident_id: str,

    changes: dict[str, Any],

    now: int | None = None,

    expected_version: int | None = None,

    force: bool = False,

) -> dict[str, Any] | None:

    now = now if now is not None else _now_ms()

    with _lock:

        incident = _incidents.get(incident_id)

        if incident is None:

            return None



        current_version = incident.get("version", 1)

        if expected_version is not None and not force:

            if current_version != expected_version:

                conflicting_fields = [

                    k for k, v in changes.items()

                    if k not in ("expected_version", "force", "notes")

                    and k in incident and incident[k] != v

                ]

                return {

                    "conflict": True,

                    "server_incident": dict(incident),

                    "expected_version": expected_version,

                    "current_version": current_version,

                    "conflicting_fields": conflicting_fields,

                }



        # Clean changes dictionary of internal flags

        cleaned_changes = {

            k: v for k, v in changes.items()

            if k not in ("expected_version", "force")

        }

        _incidents[incident_id] = apply_update(incident, cleaned_changes, now)
        updated_inc = _incidents[incident_id]
        old_assigned = incident.get("assigned_to")
        old_status = incident.get("status")
        old_severity = incident.get("severity")
        new_assigned = updated_inc.get("assigned_to")
        new_status = updated_inc.get("status")
        new_severity = updated_inc.get("severity")
        try:
            if new_assigned and new_assigned != old_assigned:
                if not old_assigned:
                    dispatch_incident_notifications(updated_inc, "assignment", now=now)
                else:
                    dispatch_incident_notifications(updated_inc, "reassignment", previous_assigned_to=old_assigned, now=now)
            if new_status == "escalated" and old_status != "escalated":
                dispatch_incident_notifications(updated_inc, "escalation", now=now)
            if new_severity == "critical" and old_severity != "critical":
                dispatch_incident_notifications(updated_inc, "supervisor_review", now=now)
        except Exception:
            pass

        return dict(_incidents[incident_id])





def sync_queue_items(items: list[dict[str, Any]]) -> dict[str, Any]:

    now = _now_ms()

    results = []

    applied = 0

    conflicts = 0

    failed = 0



    for item in items:

        queue_id = item.get("queue_id", "")

        action = item.get("action")



        if action == "create":

            payload = item.get("create_payload") or {}

            if isinstance(payload, dict):

                inc = create_incident(**payload, now=now)

            else:

                inc = create_incident(**payload.model_dump(), now=now)

            results.append({

                "queue_id": queue_id,

                "status": "applied",

                "incident": inc,

                "server_incident": None,

                "conflicting_fields": None,

                "error": None,

            })

            applied += 1



        elif action == "update":

            incident_id = item.get("incident_id")

            changes = item.get("changes") or {}

            if not isinstance(changes, dict):

                changes = changes.model_dump(exclude_unset=True, exclude_none=True)

            expected_version = item.get("expected_version")

            force = item.get("force", False)



            res = update_incident(

                incident_id,

                changes,

                now=now,

                expected_version=expected_version,

                force=force,

            )



            if res is None:

                results.append({

                    "queue_id": queue_id,

                    "status": "failed",

                    "incident": None,

                    "server_incident": None,

                    "conflicting_fields": None,

                    "error": f"Incident {incident_id} not found on server",

                })

                failed += 1

            elif isinstance(res, dict) and res.get("conflict"):

                results.append({

                    "queue_id": queue_id,

                    "status": "conflict",

                    "incident": None,

                    "server_incident": res["server_incident"],

                    "conflicting_fields": res["conflicting_fields"],

                    "error": f"Server has newer version (v{res['current_version']}) than field expected (v{res['expected_version']})",

                })

                conflicts += 1

            else:

                results.append({

                    "queue_id": queue_id,

                    "status": "applied",

                    "incident": res,

                    "server_incident": None,

                    "conflicting_fields": None,

                    "error": None,

                })

                applied += 1

        else:

            results.append({

                "queue_id": queue_id,

                "status": "failed",

                "incident": None,

                "server_incident": None,

                "conflicting_fields": None,

                "error": f"Unknown sync action: {action}",

            })

            failed += 1



    return {

        "results": results,

        "applied_count": applied,

        "conflict_count": conflicts,

        "failed_count": failed,

        "server_time": now,

    }





def set_staffing(region: str, officers_on_duty: int) -> bool:

    if region not in REGIONS:

        return False

    with _lock:

        _staffing[region] = officers_on_duty

    return True





def get_feed() -> dict[str, Any]:

    with _lock:

        return {

            "regions": list(REGIONS),

            "staffing": [{"region": r, "officers_on_duty": _staffing[r]} for r in REGIONS],

            "incidents": [dict(i) for i in _incidents.values()],

        }





def reset() -> None:

    """Clear all incidents and staffing. Used by tests."""

    global _incident_id_counter

    with _lock:

        _incidents.clear()

        _staffing.update({region: 0 for region in REGIONS})

        _incident_id_counter = itertools.count(1)
