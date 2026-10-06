"""AgentCore Platform v1.0"""

# TEL-C2-007 — OutputFormatNode (inner domain node 5, last in DomainWorkflowGraph)
# Assembles the final incident report document from report_sections and
# compliance_flags.  This is the last inner node — it produces the
# incident_report string that the outer PostProcessNode's output boundary
# will scan.
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

from src.schemas.state import from_json

logger = logging.getLogger(__name__)

# Section order for the final report (MIC filing recommended order).
_SECTION_ORDER = [
    "incident_summary",
    "affected_services",
    "timeline",
    "root_cause_analysis",
    "customer_impact",
    "remediation_actions",
    "mic_notification_status",
]

# Human-readable section headers.
_SECTION_HEADERS: Dict[str, str] = {
    "incident_summary": "1. Incident Summary",
    "affected_services": "2. Affected Services",
    "timeline": "3. Timeline of Events",
    "root_cause_analysis": "4. Root Cause Analysis",
    "customer_impact": "5. Customer Impact",
    "remediation_actions": "6. Remediation Actions",
    "mic_notification_status": "7. MIC Notification Status",
}

_SEPARATOR = "=" * 72
_SUBSEP = "-" * 72


def _assemble_report(
    incident_id: str,
    sections: Dict[str, str],
    compliance: Dict[str, Any],
) -> str:
    """Assemble the full incident report from sections and compliance data."""
    lines = [
        _SEPARATOR,
        "NETWORK INCIDENT REPORT",
        f"Incident ID: {incident_id}",
        _SEPARATOR,
        "",
    ]

    for key in _SECTION_ORDER:
        header = _SECTION_HEADERS.get(key, key.replace("_", " ").title())
        content = sections.get(key, "(Section not generated)")
        lines.append(header)
        lines.append(_SUBSEP)
        lines.append(content)
        lines.append("")

    # Append compliance trailer.
    mic_required = compliance.get("mic_required", False)
    reason = compliance.get("reason", "N/A")
    regulatory = compliance.get(
        "regulatory_basis",
        "電気通信事業法施行規則 第58条第2項 (Telecommunications Business Act Enforcement Regulations Art. 58(2))",
    )
    deadline = compliance.get("notification_deadline_hours", 24)
    lines += [
        _SEPARATOR,
        "REGULATORY COMPLIANCE NOTE",
        _SUBSEP,
        f"  Regulatory Basis:        {regulatory}",
        f"  MIC Notification Required: {'YES — must notify within %dh' % deadline if mic_required else 'NO'}",
        f"  Determination Basis:     {reason}",
        _SEPARATOR,
    ]

    return "\n".join(lines)


class OutputFormatNode(FunctionNode):
    """Assemble the final incident report document (inner domain node).

    Reads report_sections and compliance_flags from State, renders
    the full MIC-compliant incident report text, and writes it to
    incident_report (and result) for the outer PostProcessNode.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        report_sections:  str  — JSON-serialised section dict
        compliance_flags: str  — JSON-serialised compliance result
        incident_data:    str  — JSON-serialised incident payload

    Output state keys (partial dict):
        incident_report: str
        result:          str  (same as incident_report — backbone convention)
        status:          str
        error_log:       list[str]  (only on ERROR)
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> dict[str, Any]:
        # A reason settled earlier in the run is the real one: pass it through
        # untouched instead of doing work on input that was already declined.
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        sections: Dict[str, str] = from_json(state.get("report_sections"), {})
        compliance: Dict[str, Any] = from_json(state.get("compliance_flags"), {})
        incident_data: Dict[str, Any] = from_json(state.get("incident_data"), {})

        incident_id = incident_data.get("incident_id", "unknown")

        if not sections:
            logger.error(
                "OutputFormatNode: report_sections missing in state for incident_id=%s",
                incident_id,
            )
            emit_trace_event(
                "output_format_failed",
                {"reason": "missing_report_sections", "incident_id": incident_id},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": [f"OutputFormatNode: report_sections missing for incident_id={incident_id}"],
            }

        # ── Assemble the report ───────────────────────────────────────────────
        report = _assemble_report(incident_id, sections, compliance)

        logger.info(
            "OutputFormatNode: incident_id=%s report_chars=%d mic_required=%s",
            incident_id,
            len(report),
            compliance.get("mic_required", False),
        )
        emit_trace_event(
            "output_format_complete",
            {
                "incident_id": incident_id,
                "report_length": len(report),
                "section_count": len(sections),
                "mic_required": compliance.get("mic_required", False),
            },
            state,
        )

        return {
            "incident_report": report,
            "result": report,
            "status": AgentStatus.SUCCESS.value,
        }
