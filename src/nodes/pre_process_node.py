"""AgentCore Platform v1.0"""

# TEL-C2-007 — PreProcessNode
# Outer backbone pre_process slot (trust gate + caller-data contract).
#
# Responsibilities:
#   - Enforce VERIFIED_EXTERNAL trust (required_trust_level — the trust gate)
#   - Accept the incident record from input_context["incident"] (canonical
#     structured channel) or, as a legacy fallback, as a JSON string in
#     user_input
#   - Validate EVERY caller field against the explicit contract in
#     src/services/field_validation.py (strict types, bounds, inert
#     identifiers, PII / injection screens on free text) — fail closed,
#     never echoing a rejected value
#   - Write validated_input (normalised JSON string) + enriched_context
#   - Emit an audit event for every validation decision
#
# Channel note: the structured input_context channel is canonical because the
# framework rewrites the user_input string channel at every node boundary
# (masking); its personal-name heuristic matches consecutive Title Case words,
# which is the exact shape of canonical service names ("Wi-Fi Calling"). A
# record sent on the legacy user_input channel may therefore arrive with such
# tokens already rewritten — the contract still applies, but only the
# structured channel guarantees proper nouns arrive intact.
#
# The template owns this contract itself: the screens run in execute(), so the
# guarantee holds wherever the agent runs, with or without any
# platform-side input filtering in front of it.
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import json
import logging
from typing import Any, ClassVar, Dict, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.services.progress import emit_progress
from src.services.failure_message import EMPTY_INPUT, INVALID_VALUE

from src.schemas.state import to_json
from src.services.field_validation import (
    ContentRefusedError,
    FieldContractError,
    validate_incident_record,
)

logger = logging.getLogger(__name__)


def _record_from_context(input_context: Any) -> Optional[Dict[str, Any]]:
    """Return the incident record from the structured channel, if present."""
    if isinstance(input_context, dict):
        record = input_context.get("incident")
        if isinstance(record, dict):
            return record
    return None


class PreProcessNode(FunctionNode):
    """Caller-data contract enforcement for TEL-C2-007.

    Validates the caller-supplied incident record before the domain workflow
    runs. This is the outer backbone's pre_process slot — the only node with
    VERIFIED_EXTERNAL trust, so unauthenticated or anonymous callers are
    rejected here (fail-fast; inner domain nodes carry ANONYMOUS trust and
    never see unvalidated input directly).

    Input state keys:
        input_context: dict — canonical channel; incident record under "incident"
        user_input:    str  — legacy channel; JSON incident payload

    Output state keys (partial dict):
        validated_input:  str        — normalised JSON string of the validated record
        enriched_context: str        — JSON-serialised channel metadata
        status:           str        — AgentStatus.SUCCESS.value or AgentStatus.ERROR.value
        error_code:       str        — set when the run COMPLETES without acting,
                                       because the caller can correct the value
                                       and send the request again
        error_log:        list[str]  — the internal reason, on either stop path
                                       (names fields, never values)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> dict[str, Any]:
        user_input = state.get("user_input", "")
        input_context = state.get("input_context", {})

        # ── Channel selection ─────────────────────────────────────────────────
        record = _record_from_context(input_context)
        channel = "input_context"
        if record is None:
            channel = "user_input"
            if not user_input or not isinstance(user_input, str) or not user_input.strip():
                logger.warning("PreProcessNode: no incident record supplied on either channel")
                emit_trace_event(
                    "pre_process_validation_failed",
                    {"reason": "empty_input"},
                    state,
                )
                emit_progress(EMPTY_INPUT)
                return {
                    "status": AgentStatus.SUCCESS.value,
                    "error_code": "EMPTY_INPUT",
                    "error_log": [
                        "PreProcessNode: supply the incident record as "
                        "input_context['incident'] (or legacy JSON in input)"
                    ],
                }
            try:
                parsed = json.loads(user_input.strip())
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning("PreProcessNode: JSON parse failed — %s", exc)
                emit_trace_event(
                    "pre_process_validation_failed",
                    {"reason": "json_parse_error"},
                    state,
                )
                emit_progress(INVALID_VALUE)
                return {
                    "status": AgentStatus.SUCCESS.value,
                    "error_code": "INVALID_REQUEST",
                    "error_log": ["PreProcessNode: input is not valid JSON"],
                }
            if not isinstance(parsed, dict):
                emit_trace_event(
                    "pre_process_validation_failed",
                    {"reason": "payload_not_object"},
                    state,
                )
                emit_progress(INVALID_VALUE)
                return {
                    "status": AgentStatus.SUCCESS.value,
                    "error_code": "INVALID_REQUEST",
                    "error_log": ["PreProcessNode: JSON root must be an object"],
                }
            record = parsed

        # ── Caller-data contract (fail closed; errors name fields, not values) ─
        #
        # One contract, two kinds of stop, and they must not be reported the
        # same way. ContentRefusedError is a refusal — instruction-override
        # content, or a personal identifier that has no place in an incident
        # record. There is no corrected form of it to send, so the run
        # TERMINATES; completing it with a reason would read as an invitation
        # to reword the request until it gets through.
        #
        # The branch is on the exception TYPE, never on its message text: the
        # wording is free to change, and a text match would silently start
        # treating a refusal as a correctable value the day someone rephrases
        # it. ContentRefusedError subclasses FieldContractError, so it must be
        # caught FIRST — the order of these two clauses is the whole guarantee.
        try:
            validated, screened_fields = validate_incident_record(record)
        except ContentRefusedError as exc:
            logger.warning("PreProcessNode: content refused — %s", exc)
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "content_refused", "detail": str(exc), "channel": channel},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PreProcessNode: {exc}"],
            }
        except FieldContractError as exc:
            # A value the caller can correct — wrong type, out of range,
            # malformed shape. The run COMPLETES carrying the reason so the
            # request can be fixed and sent again on the same conversation.
            logger.warning("PreProcessNode: contract violation — %s", exc)
            emit_trace_event(
                "pre_process_validation_failed",
                {"reason": "field_contract_violation", "detail": str(exc), "channel": channel},
                state,
            )
            emit_progress(INVALID_VALUE)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "error_log": [f"PreProcessNode: {exc}"],
            }

        # ── Success ───────────────────────────────────────────────────────────
        incident_id = validated["incident_id"]
        normalised_json = json.dumps(validated, ensure_ascii=False)

        logger.info(
            "PreProcessNode: validated incident_id=%s channel=%s",
            incident_id,
            channel,
        )
        emit_trace_event(
            "pre_process_validated",
            {
                "incident_id": incident_id,
                "channel": channel,
                "payload_keys": sorted(validated.keys()),
                "screened_fields": screened_fields,
            },
            state,
        )

        return {
            "validated_input": normalised_json,
            "enriched_context": to_json(
                {
                    "source": "NetworkIncidentReportGeneratorAgent",
                    "channel": (
                        input_context.get("channel", "unknown") if isinstance(input_context, dict) else "unknown"
                    ),
                    "incident_id": incident_id,
                }
            ),
            "status": AgentStatus.SUCCESS.value,
        }
