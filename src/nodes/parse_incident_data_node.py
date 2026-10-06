"""AgentCore Platform v1.0"""

# TEL-C2-007 — ParseIncidentDataNode
# Inner domain node 2: enrich and classify the validated incident data.
#
# Responsibilities:
#   - Classify incident severity from duration + subscriber count
#   - Derive MIC reportability indicator
#   - Annotate the incident_data with derived fields for downstream nodes
#
# Inner node — ANONYMOUS trust (the outer pre_process slot already enforced
# caller trust; inner nodes stay ANONYMOUS so the outer InvocationContext
# passes the subgraph boundary without rejection).
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
from typing import Any, ClassVar, Dict

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json
from src.services import mic_policy

logger = logging.getLogger(__name__)


def _classify_severity(affected_subscribers: int, duration_minutes: int) -> str:
    """Classify incident severity based on scope and duration.

    Returns "critical", "high", "medium", or "low".
    """
    if affected_subscribers >= 100_000 or duration_minutes >= 360:
        return "critical"
    if affected_subscribers >= 10_000 or duration_minutes >= 120:
        return "high"
    if affected_subscribers >= 3_000 or duration_minutes >= 60:
        return "medium"
    return "low"


class ParseIncidentDataNode(FunctionNode):
    """Enrich incident data with severity classification and derived fields.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        incident_data: str  — JSON-serialised incident payload

    Output state keys (partial dict):
        incident_data: str  — enriched JSON string, same key updated
        status:        str
        error_log:     list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        incident_data: Dict[str, Any] = from_json(state.get("incident_data"), {})

        if not incident_data:
            logger.error("ParseIncidentDataNode: incident_data is empty or missing")
            emit_trace_event(
                "parse_incident_data_failed",
                {"reason": "missing_incident_data"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["ParseIncidentDataNode: incident_data missing in state"],
            }

        incident_id = incident_data.get("incident_id", "unknown")
        affected_subscribers = int(incident_data.get("affected_subscribers", 0))
        duration_minutes = int(incident_data.get("duration_minutes", 0))
        affected_services = incident_data.get("affected_services", []) or []

        # ── Severity classification ───────────────────────────────────────────
        severity = _classify_severity(affected_subscribers, duration_minutes)

        # ── MIC Art. 58(2) pre-check (service-category aware) ──────────────────
        # Single source of truth: src/services/mic_policy.py. Requires BOTH the
        # affected-user count AND the outage duration to meet a category pair.
        service_category = mic_policy.classify_service_category(affected_services)
        mic_reportable = mic_policy.is_mic_reportable(affected_subscribers, duration_minutes, affected_services)

        # ── Enrich incident_data ──────────────────────────────────────────────
        enriched: Dict[str, Any] = dict(incident_data)
        enriched["severity"] = severity
        enriched["service_category"] = service_category
        enriched["mic_reportable"] = mic_reportable
        enriched["duration_minutes"] = duration_minutes
        enriched["affected_subscribers"] = affected_subscribers

        logger.info(
            "ParseIncidentDataNode: incident_id=%s severity=%s mic_reportable=%s",
            incident_id,
            severity,
            mic_reportable,
        )
        emit_trace_event(
            "parse_incident_data_complete",
            {
                "incident_id": incident_id,
                "severity": severity,
                "service_category": service_category,
                "mic_reportable": mic_reportable,
                "affected_subscribers": affected_subscribers,
                "duration_minutes": duration_minutes,
            },
            state,
        )

        return {
            "incident_data": to_json(enriched),
            "status": AgentStatus.SUCCESS.value,
        }
