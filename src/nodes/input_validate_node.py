"""AgentCore Platform v1.0"""

# TEL-C2-007 — InputValidateNode
# Inner domain node 1: domain-level validation of the incident payload.
#
# Distinct from PreProcessNode (trust gate + caller-data contract at the outer
# boundary): this node RE-APPLIES the same field contract — defense in depth,
# so the inner pipeline holds its own guarantee even when driven directly —
# and then applies domain business rules: service-name normalisation to the
# canonical vocabulary and timeline extraction.
#
# Input source order:
#   1. incident_payload — validated record seeded from the context bridge
#      (the canonical path; a template-owned key outside the framework's
#      masked string channels, so Title Case service names arrive intact)
#   2. validated_input / user_input — direct-drive and legacy paths
#
# Inner node — ANONYMOUS trust: the outer pre_process slot (VERIFIED_EXTERNAL)
# already enforced caller trust; inner nodes must be ANONYMOUS so the outer
# InvocationContext passes through the subgraph boundary without rejection.
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import json
import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.services.progress import emit_progress
from src.services.failure_message import INVALID_VALUE

from src.schemas.state import to_json
from src.services.field_validation import (
    ContentRefusedError,
    FieldContractError,
    validate_incident_record,
)

logger = logging.getLogger(__name__)

# Known service-name aliases for normalisation (MIC filings require canonical names).
_SERVICE_ALIASES: Dict[str, str] = {
    "lte": "LTE",
    "4g": "LTE",
    "5g": "5G NR",
    "5gnr": "5G NR",
    "5g nr": "5G NR",
    "volte": "VoLTE",
    "ims": "IMS",
    "sms": "SMS",
    "mms": "MMS",
    "wifi": "Wi-Fi Calling",
    "wi-fi": "Wi-Fi Calling",
    "wi-fi calling": "Wi-Fi Calling",
}


def _normalise_services(raw_services: List[str]) -> List[str]:
    """Normalise and deduplicate the affected_services list (shape pre-validated)."""
    normalised: List[str] = []
    seen: set[str] = set()
    for svc in raw_services:
        canonical = _SERVICE_ALIASES.get(svc.lower().strip(), svc.strip())
        if canonical and canonical not in seen:
            seen.add(canonical)
            normalised.append(canonical)
    return normalised


class InputValidateNode(FunctionNode):
    """Domain validation of the incident payload for TEL-C2-007.

    Re-applies the caller-field contract (src/services/field_validation.py)
    and then the domain business rules: service normalisation, timeline
    extraction, non-empty service list.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        incident_payload: str — validated JSON from the context bridge (canonical)
        validated_input:  str — direct-drive fallback
        user_input:       str — legacy fallback

    Output state keys (partial dict):
        incident_data: str   — JSON-serialised normalised incident payload
        status:        str
        error_code:    str        — set when the run COMPLETES without acting,
                                    because the caller can correct the value
        error_log:     list[str]  — the internal reason, on either stop path
                                    (names fields, never values)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        raw = state.get("incident_payload") or state.get("validated_input") or state.get("user_input", "")

        # ── Parse ─────────────────────────────────────────────────────────────
        try:
            payload: Dict[str, Any] = json.loads(raw) if isinstance(raw, str) else {}
        except (json.JSONDecodeError, ValueError):
            logger.error("InputValidateNode: incident payload is not valid JSON")
            emit_trace_event(
                "input_validate_failed",
                {"reason": "json_parse_error"},
                state,
            )
            emit_progress(INVALID_VALUE)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": ["InputValidateNode: incident payload is not valid JSON"],
            }

        if not isinstance(payload, dict) or not payload:
            emit_trace_event(
                "input_validate_failed",
                {"reason": "payload_not_dict"},
                state,
            )
            emit_progress(INVALID_VALUE)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": ["InputValidateNode: incident payload is missing or not an object"],
            }

        # ── Re-apply the caller-field contract (defense in depth) ─────────────
        #
        # Same two-kinds-of-stop split as PreProcessNode, and for the same
        # reason: this node re-applies the identical contract, so it must
        # report its outcomes identically or the inner pipeline would soften a
        # refusal that the outer boundary terminates on. ContentRefusedError
        # (instruction override / personal identifier) terminates; every other
        # contract violation is a value the caller can correct and completes
        # carrying the reason. Branch on the TYPE, not the message — and catch
        # the subclass FIRST.
        try:
            validated, _ = validate_incident_record(payload)
        except ContentRefusedError as exc:
            emit_trace_event(
                "input_validate_failed",
                {"reason": "content_refused", "detail": str(exc)},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"InputValidateNode: {exc}"],
            }
        except FieldContractError as exc:
            emit_trace_event(
                "input_validate_failed",
                {"reason": "field_contract_violation", "detail": str(exc)},
                state,
            )
            emit_progress(INVALID_VALUE)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": [f"InputValidateNode: {exc}"],
            }

        incident_id = validated["incident_id"]

        # ── Normalise services (canonical vocabulary) ─────────────────────────
        normalised_services = _normalise_services(validated["affected_services"])
        if not normalised_services:
            emit_trace_event(
                "input_validate_failed",
                {"reason": "no_affected_services"},
                state,
            )
            emit_progress(INVALID_VALUE)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": ["InputValidateNode: affected_services is empty"],
            }

        timeline = validated["timeline"]
        duration_minutes = timeline["duration_minutes"]
        affected_subscribers = validated["customer_impact"]["affected_subscribers"]

        # ── Build normalised incident_data ────────────────────────────────────
        incident_data: Dict[str, Any] = {
            "incident_id": incident_id,
            "affected_services": normalised_services,
            "timeline": {
                "detected_at": timeline["detected_at"],
                "resolved_at": timeline["resolved_at"],
                "duration_minutes": duration_minutes,
            },
            "root_cause": validated["root_cause"],
            "customer_impact": {
                "affected_subscribers": affected_subscribers,
                "impact_description": validated["customer_impact"]["impact_description"],
            },
            "remediation_actions": validated["remediation_actions"],
            "mic_notification_status": validated["mic_notification_status"],
            "severity": validated["severity"],
            "duration_minutes": duration_minutes,
            "affected_subscribers": affected_subscribers,
        }

        logger.info(
            "InputValidateNode: incident_id=%s services=%d subscribers=%d duration=%dmin",
            incident_id,
            len(normalised_services),
            affected_subscribers,
            duration_minutes,
        )
        emit_trace_event(
            "input_validate_complete",
            {
                "incident_id": incident_id,
                "service_count": len(normalised_services),
                "affected_subscribers": affected_subscribers,
                "duration_minutes": duration_minutes,
            },
            state,
        )

        return {
            "incident_data": to_json(incident_data),
            "status": AgentStatus.SUCCESS.value,
        }
