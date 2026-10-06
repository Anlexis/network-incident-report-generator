"""AgentCore Platform v1.0"""

# TEL-C2-007 — caller-field validation contract (single source of truth).
#
# Every field of the caller-supplied incident record is hostile until proven
# bounded. This module owns the rules; PreProcessNode applies them at the
# caller boundary and InputValidateNode re-applies them inside the domain
# workflow (defense in depth — the inner pipeline holds its own guarantee even
# when driven directly).
#
# Principles:
#   - Strict typing, not coercion: a bool is not a count, a float is not a
#     count, and "3000" is not a count. int() would happily accept all three —
#     and int(float("inf")) raises OverflowError, which the old
#     (TypeError, ValueError) net did not catch. Non-finite floats (NaN,
#     +/-Infinity) parse fine and arrive over the wire as raw JSON; every
#     comparison against NaN is False, which silently fails OPEN on the exact
#     regulatory decision this template exists to make. Counts are therefore
#     accepted ONLY as Python ints within explicit bounds.
#   - Fail closed with a field-naming error; the rejected VALUE is never
#     echoed into errors, logs, or audit events.
#   - Identifier fields are locked to inert character sets; free-text fields
#     are length-capped, control-stripped, and PII/injection-screened.

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from framework.security.injection_detector import detect_injection
from framework.security.pii_detector import detect_pii
from framework.security.pii_masking import mask_pii


class FieldContractError(ValueError):
    """A caller field failed the validation contract.

    The message names the FIELD and the rule — never the rejected value.
    """


class ContentRefusedError(FieldContractError):
    """Caller content the agent REFUSES outright — not a value to correct.

    The contract stops a request for two different reasons, and the caller can
    act on only one of them. A wrong type, an out-of-range count, a malformed
    timestamp — those name a value the caller can fix and send again. Content
    that carries an instruction-override attempt, or a personal identifier that
    has no place in an incident record, is refused: there is no corrected form
    of it to send, and reporting it as a correctable value would read as an
    invitation to reword the request until it gets through.

    Raising a distinct TYPE is what lets the nodes tell the two apart. Matching
    on the message text would tie the branch to wording that is free to change
    and would silently misclassify a refusal the day someone rephrases it.

    Subclasses FieldContractError deliberately: every existing
    ``except FieldContractError`` keeps catching it, so callers that do not need
    the distinction — and the contract's own single-exception surface — are
    unchanged. A handler that DOES need it catches this class first.
    """


# ── Bounds (explicit, domain-grounded) ─────────────────────────────────────────

# Japan counts ~220M mobile service subscriptions; 200M is a generous ceiling
# for a single incident's affected-subscriber count.
MAX_AFFECTED_SUBSCRIBERS = 200_000_000
# One year of outage minutes — far beyond any recorded incident.
MAX_DURATION_MINUTES = 525_600

MAX_SERVICES = 32
MAX_SERVICE_NAME_LEN = 48
MAX_REMEDIATION_ACTIONS = 50
MAX_ACTION_LEN = 2_000
MAX_FREE_TEXT_LEN = 4_000

# Inert identifier: leading alphanumeric, then alphanumerics / '_' / '-'.
_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# Service labels: alphanumerics plus space, dot, underscore, hyphen.
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
# Status tokens: lowercase identifier vocabulary.
_STATUS_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
# ISO-8601 timestamp shape (date, optional time, optional zone) — bounded, no
# free text can satisfy it.
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?)?$")

_SEVERITY_VOCAB = frozenset({"critical", "high", "medium", "low", "unknown"})

# C0/C1 control characters except newline and tab (which formatted notes use).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# PII finding types that REFUSE the request outright: contact and government/
# financial identifiers have no place in a network incident record.
_REFUSING_PII_TYPES = frozenset({"email", "phone_jp", "phone_us", "ssn_us", "my_number_jp", "credit_card"})
# The `name` / `name_jp` heuristics are deliberately EXCLUDED from refusal:
# the high-recall Title-Case-pair rule flags legitimate telecom labels
# ("Wi-Fi Calling", vendor and equipment names) as personal names, so refusing
# on it would block real incident records. Name findings in free-text fields
# are MASKED instead, so a person's name still never reaches the report.


# ── Numeric contract ──────────────────────────────────────────────────────────


def parse_bounded_count(value: Any, field_name: str, maximum: int) -> int:
    """Strictly parse a caller-controlled count.

    Accepts ONLY a Python int (bool explicitly rejected — it subclasses int)
    in [0, maximum]. Everything else — floats (including NaN/Infinity, which
    arrive via raw JSON), numeric strings, None — is refused with an error
    that names the field but never the value.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise FieldContractError(f"{field_name} must be an integer (bounded count); the supplied value was rejected")
    if value < 0 or value > maximum:
        raise FieldContractError(f"{field_name} must be between 0 and {maximum}; the supplied value was rejected")
    return int(value)


# ── String contracts ──────────────────────────────────────────────────────────


def validate_incident_id(value: Any) -> str:
    if not isinstance(value, str) or not _INCIDENT_ID_RE.match(value):
        raise FieldContractError("incident_id must be 1-64 characters of [A-Za-z0-9_-] starting alphanumeric")
    return value


def validate_status_token(value: Any, field_name: str, default: str = "pending") -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, str) or not _STATUS_RE.match(value):
        raise FieldContractError(f"{field_name} must be a lowercase token of [a-z0-9_], at most 32 characters")
    return value


def validate_severity(value: Any) -> str:
    if value is None or value == "":
        return "unknown"
    if not isinstance(value, str) or value not in _SEVERITY_VOCAB:
        raise FieldContractError("severity must be one of: critical, high, medium, low, unknown")
    return value


def validate_timestamp(value: Any, field_name: str, required: bool) -> Optional[str]:
    if value is None or value == "":
        if required:
            raise FieldContractError(f"{field_name} is required (ISO-8601 timestamp)")
        return None
    if not isinstance(value, str) or len(value) > 40 or not _TIMESTAMP_RE.match(value):
        raise FieldContractError(f"{field_name} must be an ISO-8601 timestamp")
    return value


def validate_service_names(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise FieldContractError("affected_services must be a list of service names")
    if len(value) > MAX_SERVICES:
        raise FieldContractError(f"affected_services accepts at most {MAX_SERVICES} entries")
    services: List[str] = []
    for entry in value:
        if not isinstance(entry, str) or not _SERVICE_NAME_RE.match(entry):
            raise FieldContractError(
                "affected_services entries must be 1-48 characters of " "[A-Za-z0-9 ._-] starting alphanumeric"
            )
        services.append(entry)
    return services


# ── Free-text contract (screened narrative fields) ────────────────────────────


def screen_free_text(value: Any, field_name: str, max_len: int = MAX_FREE_TEXT_LEN) -> str:
    """Validate and sanitise a caller narrative field that renders into the report.

    - type + length bound (fail closed),
    - control characters stripped (newline/tab kept),
    - REFUSE on contact/identifier PII (types above) — the error names the
      field and the finding type, never the matched text,
    - REFUSE on high-confidence injection findings (the detector's own
      confidence taxonomy; lower confidences match ordinary prose),
    - person-name heuristic findings are masked, not refused (see the
      exclusion note above).
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FieldContractError(f"{field_name} must be a string")
    if len(value) > max_len:
        raise FieldContractError(f"{field_name} exceeds the {max_len}-character limit")
    text = _CONTROL_CHARS_RE.sub("", value)
    if not text:
        return ""

    findings = detect_pii(text)
    refused = sorted({f["type"] for f in findings if f["type"] in _REFUSING_PII_TYPES})
    if refused:
        # A refusal, not a correctable value — see ContentRefusedError.
        raise ContentRefusedError(
            f"{field_name} contains disallowed personal-identifier content "
            f"({', '.join(refused)}); remove it and resubmit"
        )

    injections = [f for f in detect_injection(text) if f["confidence"] == "high"]
    if injections:
        # A refusal, not a correctable value — see ContentRefusedError.
        raise ContentRefusedError(f"{field_name} cannot be processed safely")

    name_findings = [f for f in findings if f["type"] in ("name", "name_jp")]
    if name_findings:
        text = mask_pii(text, name_findings)
    return text


# ── Whole-record contract ─────────────────────────────────────────────────────


def validate_incident_record(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Validate the full caller incident record against the contract.

    Returns (projected_record, screened_field_names). Unknown keys are dropped
    (whitelist projection). Raises FieldContractError on the first violation —
    the error names the field, never the value.
    """
    if not isinstance(payload, dict):
        raise FieldContractError("incident record must be a JSON object")

    incident_id = validate_incident_id(payload.get("incident_id"))
    services = validate_service_names(payload.get("affected_services"))

    timeline_raw = payload.get("timeline")
    if not isinstance(timeline_raw, dict):
        raise FieldContractError("timeline must be an object")
    detected_at = validate_timestamp(timeline_raw.get("detected_at"), "timeline.detected_at", required=True)
    resolved_at = validate_timestamp(timeline_raw.get("resolved_at"), "timeline.resolved_at", required=False)
    duration_minutes = parse_bounded_count(
        timeline_raw.get("duration_minutes", 0), "timeline.duration_minutes", MAX_DURATION_MINUTES
    )

    impact_raw = payload.get("customer_impact", {})
    if impact_raw is None:
        impact_raw = {}
    if not isinstance(impact_raw, dict):
        raise FieldContractError("customer_impact must be an object")
    affected_subscribers = parse_bounded_count(
        impact_raw.get("affected_subscribers", 0),
        "customer_impact.affected_subscribers",
        MAX_AFFECTED_SUBSCRIBERS,
    )
    impact_description = screen_free_text(impact_raw.get("impact_description"), "customer_impact.impact_description")

    root_cause = screen_free_text(payload.get("root_cause"), "root_cause")

    actions_raw = payload.get("remediation_actions", [])
    if actions_raw is None:
        actions_raw = []
    if not isinstance(actions_raw, list):
        raise FieldContractError("remediation_actions must be a list of strings")
    if len(actions_raw) > MAX_REMEDIATION_ACTIONS:
        raise FieldContractError(f"remediation_actions accepts at most {MAX_REMEDIATION_ACTIONS} entries")
    actions = [screen_free_text(a, f"remediation_actions[{i}]", MAX_ACTION_LEN) for i, a in enumerate(actions_raw)]

    record: Dict[str, Any] = {
        "incident_id": incident_id,
        "affected_services": services,
        "timeline": {
            "detected_at": detected_at,
            "resolved_at": resolved_at,
            "duration_minutes": duration_minutes,
        },
        "root_cause": root_cause or None,
        "customer_impact": {
            "affected_subscribers": affected_subscribers,
            "impact_description": impact_description,
        },
        "remediation_actions": actions,
        "mic_notification_status": validate_status_token(
            payload.get("mic_notification_status"), "mic_notification_status"
        ),
        "severity": validate_severity(payload.get("severity")),
    }
    screened = ["customer_impact.impact_description", "root_cause", "remediation_actions"]
    return record, screened
