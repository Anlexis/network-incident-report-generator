"""AgentCore Platform v1.0"""

# TEL-C2-007 — MIC serious-accident regulatory policy (single source of truth).
#
# Correction history: the previous universal rule
# (affected_subscribers >= 3,000 OR duration_minutes >= 120) was materially
# INCORRECT and could emit false "MIC notification required" verdicts.
#
# Correct basis — Telecommunications Business Act Enforcement Regulations
# Art. 58(2) (電気通信事業法施行規則 第58条第2項), the statutory basis for the
# MIC (総務省) "重大な事故 / Report of Significant Accidents" duty: the reporting
# threshold is SERVICE-CATEGORY-specific and requires BOTH an affected-user
# count AND an outage duration (not either/or). For typical voice /
# internet-access categories the thresholds are:
#     30,000 affected users for >= 2 hours (120 min),  OR
#    100,000 affected users for >= 1 hour  (60 min).
# An incident is reportable when ANY (min_users, min_minutes) pair is FULLY met.
#
# This module is the VERSIONED single source of truth consumed by both
# ParseIncidentDataNode (pre-check) and ComplianceCheckNode (authoritative
# determination) so the rule is encoded in exactly one place.
#
# ⚠️ Scope note (v1): the review cited the typical voice / internet-access
# thresholds and noted that other service classes differ. Art. 58(2) does
# define distinct thresholds for further classes (e.g. emergency-call /
# 緊急通報 voice, and leased-line / data-transmission services). Pending
# regulatory confirmation of the full per-class table, v1 applies the typical
# voice / internet thresholds to every category. See docs/02_design.md
# "MIC Art. 58(2) threshold policy". This is flagged for regulatory review
# before production sign-off.

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Bump this when the threshold table below changes.
MIC_POLICY_VERSION = "2026-07"

# Regulatory basis string surfaced in the report's compliance note (bilingual —
# the report may be filed with MIC, which is JA-native).
MIC_REGULATORY_BASIS = (
    "電気通信事業法施行規則 第58条第2項 " "(Telecommunications Business Act Enforcement Regulations Art. 58(2))"
)

# Notification deadline once an incident is determined reportable.
MIC_NOTIFICATION_DEADLINE_HOURS = 24

# Service categories used for threshold selection.
CATEGORY_VOICE = "voice"
CATEGORY_INTERNET = "internet"
CATEGORY_OTHER = "other"

# (min_affected_users, min_duration_minutes) — BOTH must be met for a pair to
# trigger reportability. Typical voice / internet-access categories share
# the same pair set.
_TYPICAL_PAIRS: List[Tuple[int, int]] = [(30_000, 120), (100_000, 60)]

MIC_THRESHOLD_PAIRS: Dict[str, List[Tuple[int, int]]] = {
    CATEGORY_VOICE: list(_TYPICAL_PAIRS),
    CATEGORY_INTERNET: list(_TYPICAL_PAIRS),
    CATEGORY_OTHER: list(_TYPICAL_PAIRS),
}

# Canonical service names (see InputValidateNode aliases) that map to the
# voice / messaging regulatory category. Anything else in a non-empty list is
# treated as internet-access (data). An empty list is insufficient to classify
# (-> OTHER); InputValidateNode already rejects empty affected_services upstream.
_VOICE_SERVICES = frozenset(
    {
        "LTE",
        "5G NR",
        "VoLTE",
        "IMS",
        "SMS",
        "MMS",
        "Wi-Fi Calling",
    }
)


def classify_service_category(affected_services: Optional[List[str]]) -> str:
    """Resolve the MIC service category from the affected-services list.

    Any voice / messaging service present -> 'voice'; a non-empty list with no
    voice service -> 'internet'; an empty / missing list -> 'other' (insufficient
    input to classify the service).
    """
    if not affected_services:
        return CATEGORY_OTHER
    for svc in affected_services:
        if svc in _VOICE_SERVICES:
            return CATEGORY_VOICE
    return CATEGORY_INTERNET


def _pairs_for(category: str) -> List[Tuple[int, int]]:
    return MIC_THRESHOLD_PAIRS.get(category, list(_TYPICAL_PAIRS))


def is_mic_reportable(
    affected_subscribers: int,
    duration_minutes: int,
    affected_services: Optional[List[str]] = None,
) -> bool:
    """Return True iff the incident meets ANY MIC Art. 58(2) threshold pair.

    Each pair requires BOTH the affected-user count AND the outage duration.
    """
    category = classify_service_category(affected_services)
    return any(
        affected_subscribers >= min_users and duration_minutes >= min_minutes
        for min_users, min_minutes in _pairs_for(category)
    )


def evaluate(
    affected_subscribers: int,
    duration_minutes: int,
    affected_services: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Full MIC Art. 58(2) reportability evaluation with traceability data.

    Returns a dict suitable for JSON serialisation into `compliance_flags`.
    """
    category = classify_service_category(affected_services)
    pairs = _pairs_for(category)

    met = [(u, m) for (u, m) in pairs if affected_subscribers >= u and duration_minutes >= m]
    mic_required = bool(met)

    if mic_required:
        reason = "; ".join(
            f"Affected subscribers ({affected_subscribers:,}) >= {u:,} "
            f"AND duration ({duration_minutes} min) >= {m} min"
            for (u, m) in met
        )
    else:
        reason = (
            f"No MIC threshold pair fully met for the '{category}' service "
            f"category (actual: {affected_subscribers:,} affected users, "
            f"{duration_minutes} min outage; requires "
            + " OR ".join(f"{u:,} users AND {m} min" for (u, m) in pairs)
            + ")"
        )

    return {
        "mic_required": mic_required,
        "reason": reason,
        "service_category": category,
        "policy_version": MIC_POLICY_VERSION,
        "regulatory_basis": MIC_REGULATORY_BASIS,
        "thresholds_applied": [{"min_subscribers": u, "min_duration_minutes": m} for (u, m) in pairs],
        "met_threshold_pairs": [{"min_subscribers": u, "min_duration_minutes": m} for (u, m) in met],
        "actual_subscribers": affected_subscribers,
        "actual_duration_minutes": duration_minutes,
        "notification_deadline_hours": MIC_NOTIFICATION_DEADLINE_HOURS,
    }
