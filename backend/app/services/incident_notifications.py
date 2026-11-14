"""
Role-Aware Incident Assignment and Escalation Notification Service.

Features:
- Role-aware recipient resolution (authorized responders and supervisors for the relevant jurisdiction).
- Jurisdiction boundary validation (blocks unauthorized out-of-jurisdiction notifications).
- Sanitized email payload generation (strictly excludes citizen PII, transcripts, and evidence).
- Quiet hours enforcement with critical event override.
- Transient failure retry logic and comprehensive delivery outcome audit logging.
"""
from __future__ import annotations

import datetime
import itertools
import threading
import time
import zoneinfo
from typing import Any, Dict, List, Optional

# Jurisdiction mapping for operational sectors
REGION_JURISDICTION_MAP: dict[str, str] = {
    "Central Zone": "JUR-DELHI-METRO",
    "North Zone": "JUR-DELHI-METRO",
    "East Zone": "JUR-DELHI-METRO",
    "South Zone": "JUR-NCR-SOUTH",
    "West Zone": "JUR-NCR-SOUTH",
    "Unspecified": "JUR-DELHI-METRO",
}

# Master authorized personnel directory with preferences and quiet hours
DEFAULT_OFFICERS: dict[str, dict[str, Any]] = {
    "OFF-DELHI-101": {
        "officer_id": "OFF-DELHI-101",
        "name": "Inspector Rajesh Sharma",
        "email": "rajesh.sharma@delhipolice.gov.in",
        "role": "responder",
        "jurisdiction_id": "JUR-DELHI-METRO",
        "regions": ["Central Zone", "North Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": False,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-DELHI-102": {
        "officer_id": "OFF-DELHI-102",
        "name": "Sub-Inspector Amit Patel",
        "email": "amit.patel@delhipolice.gov.in",
        "role": "responder",
        "jurisdiction_id": "JUR-DELHI-METRO",
        "regions": ["East Zone", "Central Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": False,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-SUP-DELHI": {
        "officer_id": "OFF-SUP-DELHI",
        "name": "ACP Vikram Malhotra",
        "email": "vikram.malhotra@delhipolice.gov.in",
        "role": "supervisor",
        "jurisdiction_id": "JUR-DELHI-METRO",
        "regions": ["Central Zone", "North Zone", "East Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": True,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "23:00",
            "quiet_hours_end": "06:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-CMD-METRO": {
        "officer_id": "OFF-CMD-METRO",
        "name": "Joint Commissioner Priya Verma",
        "email": "priya.verma@delhipolice.gov.in",
        "role": "commander",
        "jurisdiction_id": "JUR-DELHI-METRO",
        "regions": ["Central Zone", "North Zone", "East Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": False,  # commanders only get escalations & reviews
            "reassignment_enabled": False,
            "escalation_enabled": True,
            "supervisor_review_enabled": True,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "23:00",
            "quiet_hours_end": "06:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-NCR-201": {
        "officer_id": "OFF-NCR-201",
        "name": "Inspector Sunita Rao",
        "email": "sunita.rao@haryanapolice.gov.in",
        "role": "responder",
        "jurisdiction_id": "JUR-NCR-SOUTH",
        "regions": ["South Zone", "West Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": False,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-NCR-202": {
        "officer_id": "OFF-NCR-202",
        "name": "Sub-Inspector Deepak Nair",
        "email": "deepak.nair@haryanapolice.gov.in",
        "role": "responder",
        "jurisdiction_id": "JUR-NCR-SOUTH",
        "regions": ["South Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": False,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-SUP-NCR": {
        "officer_id": "OFF-SUP-NCR",
        "name": "DCP Neha Kapoor",
        "email": "neha.kapoor@haryanapolice.gov.in",
        "role": "supervisor",
        "jurisdiction_id": "JUR-NCR-SOUTH",
        "regions": ["South Zone", "West Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": True,
            "reassignment_enabled": True,
            "escalation_enabled": True,
            "supervisor_review_enabled": True,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "23:00",
            "quiet_hours_end": "06:00",
            "timezone": "Asia/Kolkata",
        },
    },
    "OFF-CMD-SOUTH": {
        "officer_id": "OFF-CMD-SOUTH",
        "name": "Special Commissioner Arvind Swamy",
        "email": "arvind.swamy@delhipolice.gov.in",
        "role": "commander",
        "jurisdiction_id": "JUR-NCR-SOUTH",
        "regions": ["South Zone", "West Zone"],
        "preferences": {
            "email_enabled": True,
            "assignment_enabled": False,
            "reassignment_enabled": False,
            "escalation_enabled": True,
            "supervisor_review_enabled": True,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "23:00",
            "quiet_hours_end": "06:00",
            "timezone": "Asia/Kolkata",
        },
    },
}

_lock = threading.RLock()
_notif_counter = itertools.count(1)
_NOTIFICATIONS: dict[str, dict[str, Any]] = {}
_OFFICERS: dict[str, dict[str, Any]] = {k: dict(v) for k, v in DEFAULT_OFFICERS.items()}
_SIMULATE_FAILURES: set[str] = set()  # set of notification_ids or recipient_emails to simulate transient failure for


def _now_ms() -> int:
    return int(time.time() * 1000)


def reset():
    """Reset notification state and officers directory for test isolation."""
    with _lock:
        global _NOTIFICATIONS, _OFFICERS, _SIMULATE_FAILURES
        _NOTIFICATIONS = {}
        _OFFICERS = {k: dict(v) for k, v in DEFAULT_OFFICERS.items()}
        _SIMULATE_FAILURES = set()


def resolve_jurisdiction(region: str) -> str:
    """Map operational region to responsible cyber command jurisdiction."""
    return REGION_JURISDICTION_MAP.get(region, "JUR-DELHI-METRO")


def get_officer(officer_id: str) -> dict[str, Any] | None:
    """Retrieve officer profile, auto-provisioning generic demo IDs if not present."""
    with _lock:
        if officer_id in _OFFICERS:
            return dict(_OFFICERS[officer_id])

        # Auto-provision generic IDs (e.g. OFF-012, OFF-999) as Metro authorized responders
        auto_officer = {
            "officer_id": officer_id,
            "name": f"Officer {officer_id}",
            "email": f"{officer_id.lower()}@delhipolice.gov.in",
            "role": "responder",
            "jurisdiction_id": "JUR-DELHI-METRO",
            "regions": ["Central Zone", "North Zone", "East Zone", "South Zone", "West Zone", "Unspecified"],
            "preferences": {
                "email_enabled": True,
                "assignment_enabled": True,
                "reassignment_enabled": True,
                "escalation_enabled": True,
                "supervisor_review_enabled": False,
                "quiet_hours_enabled": False,
                "quiet_hours_start": "22:00",
                "quiet_hours_end": "07:00",
                "timezone": "Asia/Kolkata",
            },
        }
        _OFFICERS[officer_id] = auto_officer
        return dict(auto_officer)


def list_officers() -> list[dict[str, Any]]:
    with _lock:
        return [dict(o) for o in _OFFICERS.values()]


def update_officer_preferences(officer_id: str, new_preferences: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        officer = get_officer(officer_id)
        if not officer:
            raise ValueError(f"Officer {officer_id} not found")
        officer["preferences"].update(new_preferences)
        _OFFICERS[officer_id] = officer
        return dict(officer)


def is_officer_authorized(officer: dict[str, Any], jurisdiction_id: str, region: str) -> bool:
    """Enforces role & jurisdiction authorization boundary."""
    if officer.get("jurisdiction_id") == "*":
        return True
    if officer.get("jurisdiction_id") != jurisdiction_id:
        return False
    # Check region scope
    allowed_regions = officer.get("regions", [])
    if "*" in allowed_regions or region in allowed_regions:
        return True
    return False


def is_in_quiet_hours(
    preferences: dict[str, Any],
    now_ms: int | None = None,
    current_time_str: str | None = None,
) -> bool:
    """Checks whether the current time falls within recipient's configured quiet hours window."""
    if not preferences.get("quiet_hours_enabled", False):
        return False

    start_str = preferences.get("quiet_hours_start", "22:00")
    end_str = preferences.get("quiet_hours_end", "07:00")

    if current_time_str:
        cur_h, cur_m = map(int, current_time_str.split(":"))
    else:
        ts = (now_ms or _now_ms()) / 1000.0
        tz_name = preferences.get("timezone", "Asia/Kolkata")
        try:
            tz = zoneinfo.ZoneInfo(tz_name)
        except Exception:
            tz = zoneinfo.ZoneInfo("UTC")
        dt = datetime.datetime.fromtimestamp(ts, tz=tz)
        cur_h, cur_m = dt.hour, dt.minute

    cur_mins = cur_h * 60 + cur_m
    s_h, s_m = map(int, start_str.split(":"))
    start_mins = s_h * 60 + s_m
    e_h, e_m = map(int, end_str.split(":"))
    end_mins = e_h * 60 + e_m

    if start_mins > end_mins:
        # Crosses midnight (e.g. 22:00 to 07:00)
        return cur_mins >= start_mins or cur_mins < end_mins
    else:
        return start_mins <= cur_mins < end_mins


def build_sanitized_notification_content(
    incident: dict[str, Any],
    event_type: str,
    recipient: dict[str, Any],
    token: str,
) -> tuple[str, str, str]:
    """Generates a minimal, sanitized email payload strictly excluding citizen PII and evidentiary artifacts."""
    inc_id = incident.get("id", "INC-XXXX")
    category = incident.get("category", "unspecified")
    severity = incident.get("severity", "low").upper()
    region = incident.get("region", "Unspecified")
    jur_id = resolve_jurisdiction(region)

    event_labels = {
        "assignment": "Incident Assignment",
        "reassignment": "Incident Reassignment",
        "escalation": "PRIORITY ESCALATION",
        "supervisor_review": "SUPERVISOR REVIEW REQUIRED",
    }
    label = event_labels.get(event_type, "Incident Notification")

    subject = f"[KshemOS Alert] {label} | Ref: {inc_id} | Priority: {severity} | {region}"

    secure_link = f"https://kshemos.internal/dashboard/incidents/{inc_id}?notif_auth={token}&action=review"

    assignment_time_iso = datetime.datetime.fromtimestamp(
        incident.get("updated_at", _now_ms()) / 1000.0, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    body_snippet = (
        f"OFFICIAL DISPATCH NOTICE — RESTRICTED TO AUTHORIZED PERSONNEL\n"
        f"Incident Reference ID: {inc_id}\n"
        f"Jurisdiction Command: {jur_id}\n"
        f"Operational Sector: {region}\n"
        f"Classification Category: {category}\n"
        f"Operational Priority: {severity}\n"
        f"Action Timestamp: {assignment_time_iso}\n"
        f"Event Trigger: {label}\n"
        f"Designated Officer: {recipient['name']} ({recipient['role'].upper()})\n\n"
        f"Action Required:\n"
        f"You are receiving this official dispatch as an authorized {recipient['role']} for {jur_id}. "
        f"Access the secure terminal below to review assigned tasks and initiate response protocols.\n\n"
        f"Secure Terminal Link: {secure_link}\n\n"
        f"[SECURITY NOTICE: Pursuant to SOP 24-B & Digital Evidence Handling Mandates, all citizen "
        f"personal identifying information (PII), caller numbers, transcripts, and evidentiary files "
        f"are strictly withheld from automated email dispatches. Access complete case artifacts exclusively "
        f"within the multi-factor authenticated KshemOS operations terminal.]"
    )

    return subject, body_snippet, secure_link


def dispatch_incident_notifications(
    incident: dict[str, Any],
    event_type: str,
    previous_assigned_to: str | None = None,
    actor_id: str | None = None,
    now: int | None = None,
    override_quiet_hours_now_str: str | None = None,
) -> list[dict[str, Any]]:
    """Dispatches role-aware email notifications to authorized responders and supervisors."""
    now_ms = now or _now_ms()
    region = incident.get("region", "Unspecified")
    jurisdiction_id = resolve_jurisdiction(region)
    priority = incident.get("severity", "low").lower()
    is_critical = priority == "critical"

    # Identify candidate recipients
    candidates: list[dict[str, Any]] = []

    # 1. Responders
    assigned_to = incident.get("assigned_to")
    if assigned_to:
        resp = get_officer(assigned_to)
        if resp:
            candidates.append(resp)

    if previous_assigned_to and event_type == "reassignment":
        prev_resp = get_officer(previous_assigned_to)
        if prev_resp and prev_resp["officer_id"] not in [c["officer_id"] for c in candidates]:
            candidates.append(prev_resp)

    # 2. Supervisors and Commanders for the jurisdiction
    with _lock:
        all_officers = list(_OFFICERS.values())

    supervisors = [
        o for o in all_officers
        if o["role"] in ("supervisor", "commander")
        and is_officer_authorized(o, jurisdiction_id, region)
    ]

    if event_type in ("escalation", "supervisor_review"):
        for sup in supervisors:
            if sup["officer_id"] not in [c["officer_id"] for c in candidates]:
                candidates.append(sup)
    elif event_type in ("assignment", "reassignment"):
        # For routine assignments, notify primary supervisor of the jurisdiction
        for sup in supervisors:
            if sup["role"] == "supervisor" and sup["officer_id"] not in [c["officer_id"] for c in candidates]:
                candidates.append(sup)

    dispatched_outcomes = []

    for recipient in candidates:
        token = f"TKN-{next(_notif_counter):05d}"
        notif_id = f"NOTIF-{next(_notif_counter):05d}"
        prefs = recipient.get("preferences", {})

        subject, body_snippet, secure_link = build_sanitized_notification_content(
            incident, event_type, recipient, token
        )

        # Check authorization boundary
        if not is_officer_authorized(recipient, jurisdiction_id, region):
            outcome = {
                "notification_id": notif_id,
                "incident_id": incident.get("id"),
                "event_type": event_type,
                "priority": priority,
                "jurisdiction_id": jurisdiction_id,
                "region": region,
                "recipient_id": recipient["officer_id"],
                "recipient_email": recipient["email"],
                "recipient_role": recipient["role"],
                "recipient_name": recipient["name"],
                "subject": subject,
                "body_snippet": body_snippet,
                "secure_dashboard_link": secure_link,
                "created_at": now_ms,
                "delivery_status": "unauthorized_jurisdiction",
                "attempts": 0,
                "last_attempt_at": now_ms,
                "error_message": f"Security boundary violation: Officer {recipient['officer_id']} is not authorized for {jurisdiction_id} ({region}).",
                "retry_history": [],
            }
            with _lock:
                _NOTIFICATIONS[notif_id] = outcome
            dispatched_outcomes.append(outcome)
            continue

        # Check notification preference enablement
        pref_key = f"{event_type}_enabled"
        if not prefs.get("email_enabled", True) or not prefs.get(pref_key, True):
            outcome = {
                "notification_id": notif_id,
                "incident_id": incident.get("id"),
                "event_type": event_type,
                "priority": priority,
                "jurisdiction_id": jurisdiction_id,
                "region": region,
                "recipient_id": recipient["officer_id"],
                "recipient_email": recipient["email"],
                "recipient_role": recipient["role"],
                "recipient_name": recipient["name"],
                "subject": subject,
                "body_snippet": body_snippet,
                "secure_dashboard_link": secure_link,
                "created_at": now_ms,
                "delivery_status": "suppressed_unsubscribed",
                "attempts": 0,
                "last_attempt_at": now_ms,
                "error_message": f"Suppressed: Recipient has disabled {event_type} email notifications.",
                "retry_history": [],
            }
            with _lock:
                _NOTIFICATIONS[notif_id] = outcome
            dispatched_outcomes.append(outcome)
            continue

        # Check quiet hours (Critical events bypass quiet hours)
        in_quiet = is_in_quiet_hours(prefs, now_ms=now_ms, current_time_str=override_quiet_hours_now_str)
        if in_quiet and not is_critical:
            outcome = {
                "notification_id": notif_id,
                "incident_id": incident.get("id"),
                "event_type": event_type,
                "priority": priority,
                "jurisdiction_id": jurisdiction_id,
                "region": region,
                "recipient_id": recipient["officer_id"],
                "recipient_email": recipient["email"],
                "recipient_role": recipient["role"],
                "recipient_name": recipient["name"],
                "subject": subject,
                "body_snippet": body_snippet,
                "secure_dashboard_link": secure_link,
                "created_at": now_ms,
                "delivery_status": "suppressed_quiet_hours",
                "attempts": 0,
                "last_attempt_at": now_ms,
                "error_message": f"Suppressed: Recipient is in active quiet hours ({prefs.get('quiet_hours_start')}-{prefs.get('quiet_hours_end')}) for non-critical event.",
                "retry_history": [],
            }
            with _lock:
                _NOTIFICATIONS[notif_id] = outcome
            dispatched_outcomes.append(outcome)
            continue

        # Check transient failure simulation
        should_fail_transient = (
            recipient["officer_id"] in _SIMULATE_FAILURES
            or recipient["email"] in _SIMULATE_FAILURES
            or notif_id in _SIMULATE_FAILURES
        )

        attempts = 1
        if should_fail_transient:
            delivery_status = "retrying"
            err = "SMTP Gateway timeout (504): transient connection failure to upstream MTA."
            history = [{"attempt": 1, "timestamp": now_ms, "status": "retrying", "error": err}]
        else:
            delivery_status = "delivered"
            err = None
            history = [{"attempt": 1, "timestamp": now_ms, "status": "delivered", "error": None}]

        outcome = {
            "notification_id": notif_id,
            "incident_id": incident.get("id"),
            "event_type": event_type,
            "priority": priority,
            "jurisdiction_id": jurisdiction_id,
            "region": region,
            "recipient_id": recipient["officer_id"],
            "recipient_email": recipient["email"],
            "recipient_role": recipient["role"],
            "recipient_name": recipient["name"],
            "subject": subject,
            "body_snippet": body_snippet,
            "secure_dashboard_link": secure_link,
            "created_at": now_ms,
            "delivery_status": delivery_status,
            "attempts": attempts,
            "last_attempt_at": now_ms,
            "error_message": err,
            "retry_history": history,
        }

        with _lock:
            _NOTIFICATIONS[notif_id] = outcome
        dispatched_outcomes.append(outcome)

    return dispatched_outcomes

def get_notification(notification_id: str) -> dict[str, Any] | None:
    with _lock:
        notification = _NOTIFICATIONS.get(notification_id)
        return dict(notification) if notification is not None else None

def retry_notification(notification_id: str, force_success: bool = True) -> dict[str, Any]:
    """Retries delivery of a failed or retrying notification."""
    now_ms = _now_ms()
    with _lock:
        notif = _NOTIFICATIONS.get(notification_id)
        if not notif:
            raise ValueError(f"Notification {notification_id} not found")

        curr_attempts = notif.get("attempts", 1) + 1
        notif["attempts"] = curr_attempts
        notif["last_attempt_at"] = now_ms

        if force_success or curr_attempts >= 3:
            # Deliver on retry or fail after max attempts
            if not force_success and curr_attempts >= 3:
                notif["delivery_status"] = "failed"
                notif["error_message"] = "Exceeded maximum delivery retries (3 attempts)."
                notif["retry_history"].append({
                    "attempt": curr_attempts,
                    "timestamp": now_ms,
                    "status": "failed",
                    "error": notif["error_message"],
                })
            else:
                notif["delivery_status"] = "delivered"
                notif["error_message"] = None
                notif["retry_history"].append({
                    "attempt": curr_attempts,
                    "timestamp": now_ms,
                    "status": "delivered",
                    "error": None,
                })
        else:
            notif["delivery_status"] = "retrying"
            notif["retry_history"].append({
                "attempt": curr_attempts,
                "timestamp": now_ms,
                "status": "retrying",
                "error": "Temporary transport refusal (retry pending).",
            })

        _NOTIFICATIONS[notification_id] = notif
        return dict(notif)


def list_delivery_audit(
    incident_id: str | None = None,
    recipient_id: str | None = None,
    role: str | None = None,
    event_type: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Returns delivery outcome audit entries filtered by operational criteria."""
    with _lock:
        items = list(_NOTIFICATIONS.values())

    # Sort descending by timestamp
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    filtered = []
    for it in items:
        if incident_id and it.get("incident_id") != incident_id:
            continue
        if recipient_id and it.get("recipient_id") != recipient_id:
            continue
        if role and it.get("recipient_role") != role:
            continue
        if event_type and it.get("event_type") != event_type:
            continue
        if status and it.get("delivery_status") != status:
            continue
        filtered.append(dict(it))
        if len(filtered) >= limit:
            break

    return filtered


def get_delivery_stats() -> dict[str, Any]:
    with _lock:
        items = list(_NOTIFICATIONS.values())

    total = len(items)
    delivered = sum(1 for i in items if i.get("delivery_status") == "delivered")
    retrying = sum(1 for i in items if i.get("delivery_status") == "retrying")
    failed = sum(1 for i in items if i.get("delivery_status") == "failed")
    suppressed = sum(1 for i in items if "suppressed" in str(i.get("delivery_status", "")))
    unauthorized = sum(1 for i in items if i.get("delivery_status") == "unauthorized_jurisdiction")

    return {
        "total": total,
        "delivered": delivered,
        "retrying": retrying,
        "failed": failed,
        "suppressed": suppressed,
        "unauthorized": unauthorized,
    }


def set_simulated_failure(target_key: str, enable: bool = True):
    with _lock:
        if enable:
            _SIMULATE_FAILURES.add(target_key)
        else:
            _SIMULATE_FAILURES.discard(target_key)


def get_registered_officer(officer_id: str) -> dict[str, Any] | None:
    """Return only an officer already present in the trusted directory."""
    with _lock:
        officer = _OFFICERS.get(officer_id)
        return dict(officer) if officer is not None else None

