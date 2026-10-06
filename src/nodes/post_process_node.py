"""AgentCore Platform v1.0"""

# TEL-C2-007 — PostProcessNode
# Outer backbone post_process slot: output boundary + expose the final
# incident report as formatted_output and result.
#
# Output invariant (see docs/02_design.md — "Output boundary"):
#   The report is a regulatory filing draft. Figures (subscriber counts,
#   durations, thresholds) must be EXACT — no rounding grid applies to this
#   template, because a rounded figure would falsify the filing. What the
#   boundary enforces instead:
#     Layer 1 — credential scan: API keys, JWTs, Bearer tokens, credential
#               assignments must never ship; a hit replaces the whole report
#               with a sanitised stub (fail closed).
#     Layer 2 — personal-identifier redaction: contact and government/
#               financial identifiers (emails, phone numbers, national ID /
#               card patterns) are masked in place, each with an audit event.
#               The person-name HEURISTIC is deliberately excluded here: it
#               matches consecutive Title Case words, i.e. canonical service
#               names ("Wi-Fi Calling"), and masking those would corrupt the
#               filing. Person names in narrative fields were already masked
#               at intake (field contract).
#   Layer 1 runs first, on the untouched text: a pattern scan must see the
#   text before anything rewrites it, or an earlier redaction could split a
#   credential into pieces the scanner no longer recognises.
#
# The domain gate is a module-level function (_security_gate_output) called
# from inside execute() — NOT an instance method on the node class (the
# framework auto-wraps node gate hooks; defining one on the node would
# collide with that machinery).
#
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
import re
from typing import Any, ClassVar, List, Optional

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from framework.security.pii_detector import detect_pii
from framework.security.pii_masking import mask_pii
from shared.utils.audit_logger import emit_trace_event
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED, INVALID_VALUE, TOO_LONG

logger = logging.getLogger(__name__)

# Patterns that MUST NOT appear in the formatted incident report output.
_CREDENTIAL_PATTERNS: List[tuple[str, str]] = [
    (r"(?:sk|pk|ak)-[A-Za-z0-9]{16,}", "api_key_pattern"),
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt_pattern"),
    (r"Bearer\s+[A-Za-z0-9_\-\.]{8,}", "bearer_token"),
    (
        r"(?:password|passwd|secret|api_key|token|access_key|private_key)" r"\s*[:=]\s*\S{8,}",
        "credential_assignment",
    ),
]

# Personal-identifier finding types redacted from the report (layer 2).
# The name/name_jp heuristics are excluded — see the module note.
_REDACTED_PII_TYPES = frozenset({"email", "phone_jp", "phone_us", "ssn_us", "my_number_jp", "credit_card"})


def _security_gate_output(content: str) -> Optional[str]:
    """Scan output for disallowed credential/secret patterns (layer 1).

    Returns the first violation name, or None if the output is clean.
    Module-level function (not a node instance method) — required to avoid
    the framework's node-hook auto-wrap.
    """
    for pattern, name in _CREDENTIAL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return name
    return None


def _redact_personal_identifiers(content: str) -> tuple[str, list[str]]:
    """Mask contact/identifier PII patterns in the report (layer 2).

    Returns (redacted_text, sorted list of finding types masked). Runs on the
    report AFTER the credential scan has seen the untouched text.
    """
    findings = [f for f in detect_pii(content) if f["type"] in _REDACTED_PII_TYPES]
    if not findings:
        return content, []
    return mask_pii(content, findings), sorted({f["type"] for f in findings})


# Reason code -> the sentence the caller reads. A code with no entry falls
# back to the generic one rather than leaking the code itself.
_DEGRADED_MESSAGES = {
    "EMPTY_INPUT": EMPTY_INPUT,
    "QUESTION_TOO_LONG": TOO_LONG,
    "INVALID_REQUEST": INVALID_VALUE,
}


class PostProcessNode(FunctionNode):
    """Apply the output boundary and expose the final incident report.

    Outer backbone post_process slot.  Declared ANONYMOUS — trust was
    already enforced at PreProcessNode (VERIFIED_EXTERNAL).

    Input state keys:
        incident_report: str   — formatted report from inner OutputFormatNode
        mic_required:    bool  — MIC notification flag

    Output state keys (partial dict):
        formatted_output: str        — the report, or the reason sentence when
                                       the run completed without acting
        result:           str        — same content as formatted_output
        status:           str
        error_code:       str        — carried onward from the declining node
        error_log:        list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A run declined upstream has nothing to format. Render the reason as
        # the caller-facing body and carry the marker onward.
        marker = state.get("error_code")
        if marker:
            message = _DEGRADED_MESSAGES.get(marker, INPUT_REJECTED)
            emit_trace_event("post_process_degraded", {"reason": marker}, state)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": marker,
                "formatted_output": message,
                "result": message,
            }
        incident_report: str = state.get("incident_report") or ""
        mic_required: bool = bool(state.get("mic_required"))

        # ── Fallback for empty report ─────────────────────────────────────────
        if not incident_report.strip():
            logger.warning("PostProcessNode: incident_report is empty — using fallback message")
            incident_report = (
                "[Network Incident Report] No report content generated. " "Check error_log for upstream failures."
            )

        # ── Layer 1: credential scan (on the untouched text) ──────────────────
        violation = _security_gate_output(incident_report)
        if violation:
            logger.error("PostProcessNode: output gate violation detected — %s", violation)
            emit_trace_event(
                "post_process_output_gate_violation",
                {"violation": violation},
                state,
            )
            sanitised = (
                f"[INCIDENT REPORT REDACTED: output contained a disallowed pattern "
                f"({violation}). Contact the NOC security team for the original report.]"
            )
            return {
                "formatted_output": sanitised,
                "result": sanitised,
                "status": AgentStatus.ERROR.value,
                "error_log": [f"PostProcessNode: output gate blocked a credential pattern — {violation}"],
            }

        # ── Layer 2: personal-identifier redaction ────────────────────────────
        incident_report, redacted_types = _redact_personal_identifiers(incident_report)
        if redacted_types:
            logger.warning(
                "PostProcessNode: personal identifiers redacted from report — %s",
                redacted_types,
            )
            emit_trace_event(
                "post_process_pii_redacted",
                {"types": redacted_types},
                state,
            )

        logger.info(
            "PostProcessNode: output boundary passed — length=%d mic_required=%s",
            len(incident_report),
            mic_required,
        )
        emit_trace_event(
            "post_process_complete",
            {
                "output_length": len(incident_report),
                "mic_required": mic_required,
            },
            state,
        )

        return {
            "formatted_output": incident_report,
            "result": incident_report,
            "status": AgentStatus.SUCCESS.value,
        }
