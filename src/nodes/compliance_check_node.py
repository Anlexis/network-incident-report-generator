"""AgentCore Platform v1.0"""

# TEL-C2-007 — ComplianceCheckNode
# Inner domain node 4: MIC serious-accident (重大な事故) compliance check.
#
# Determines whether the incident meets the regulatory reporting threshold
# requiring a notification to the Ministry of Internal Affairs and
# Communications (MIC / 総務省) within 24 hours of occurrence.
#
# Basis — Telecommunications Business Act Enforcement Regulations Art. 58(2)
# (電気通信事業法施行規則 第58条第2項). The reporting duty is SERVICE-CATEGORY
# specific and requires BOTH an affected-user count AND an outage duration
# (not either/or). The full versioned threshold table lives in the single
# source of truth src/services/mic_policy.py; this node applies it.
#
# Correction history: the previous universal rule
# "affected_subscribers >= 3,000 OR duration_minutes >= 120" was materially
# incorrect and could emit false "MIC notification required" verdicts. See
# src/services/mic_policy.py and docs/02_design.md.
#
# Inner node — ANONYMOUS trust (the outer pre_process slot already enforced
# caller trust; inner nodes stay ANONYMOUS so the outer InvocationContext
# passes the subgraph boundary without rejection).
# Returns ONLY the state keys this node writes (partial-dict contract).

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import from_json, to_json
from src.services import mic_policy

logger = logging.getLogger(__name__)


def _coerce_nonneg_int(value: Any) -> int:
    """Coerce an internal numeric field to a non-negative int.

    incident_data reaches this node already validated by InputValidateNode
    (malformed / negative values are rejected there with a controlled error).
    This is a defensive fallback so a stray non-int never raises inside the
    compliance decision; unparseable / negative values clamp to 0.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    return n if n >= 0 else 0


class ComplianceCheckNode(FunctionNode):
    """MIC Art. 58(2) serious-accident compliance check for TEL-C2-007.

    Evaluates whether the incident requires MIC notification and produces a
    compliance_flags dict with full traceability data (service category,
    applied thresholds, met pairs, policy version) for the report's MIC section.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        incident_data: str  — JSON-serialised enriched incident payload

    Output state keys (partial dict):
        compliance_flags: str   — JSON-serialised compliance result dict
        mic_required:     bool  — True if MIC notification is required
        status:           str
        error_log:        list[str]  (only on ERROR)
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
            logger.error("ComplianceCheckNode: incident_data missing in state")
            emit_trace_event(
                "compliance_check_failed",
                {"reason": "missing_incident_data"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["ComplianceCheckNode: incident_data missing in state"],
            }

        incident_id = incident_data.get("incident_id", "unknown")
        affected_subscribers = _coerce_nonneg_int(incident_data.get("affected_subscribers", 0))
        duration_minutes = _coerce_nonneg_int(incident_data.get("duration_minutes", 0))
        affected_services: List[str] = incident_data.get("affected_services", []) or []

        # ── MIC Art. 58(2) evaluation (service-category aware) ────────────────
        compliance_result = mic_policy.evaluate(affected_subscribers, duration_minutes, affected_services)
        mic_required = bool(compliance_result["mic_required"])

        logger.info(
            "ComplianceCheckNode: incident_id=%s mic_required=%s category=%s " "subscribers=%d duration=%dmin",
            incident_id,
            mic_required,
            compliance_result["service_category"],
            affected_subscribers,
            duration_minutes,
        )
        emit_trace_event(
            "compliance_check_complete",
            {
                "incident_id": incident_id,
                "mic_required": mic_required,
                "service_category": compliance_result["service_category"],
                "met_threshold_pairs": compliance_result["met_threshold_pairs"],
            },
            state,
        )

        return {
            "compliance_flags": to_json(compliance_result),
            "mic_required": mic_required,
            "status": AgentStatus.SUCCESS.value,
        }
