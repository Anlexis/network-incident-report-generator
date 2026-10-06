"""AgentCore Platform v1.0"""

# TEL-C2-007 — GenerateReportSectionsNode
# Inner domain node 3: generate all 7 incident-report sections.
#
# v1 implementation: deterministic template-based synthesis. The section text is
# assembled directly from the incident_data fields using fixed templates. There
# is no LLM client in SDK v1 (no framework.services.llm_client), so v1 does NOT
# read or invoke any LLM configuration. Live-LLM synthesis wires in v-next:
# render prompts/network_incident.j2 (the manifest's llm.system_prompt_template,
# forwarded to DomainWorkflowGraph via its constructor — see graph.py
# _parent_config; the node would receive it via constructor injection, since
# the node contract execute(self, state) takes no config parameter) and
# invoke the platform SDK LLM. See docs/02_design.md "v1 Implementation Note —
# LLM synthesis".
#
# Sections produced:
#   1. incident_summary
#   2. affected_services
#   3. timeline
#   4. root_cause_analysis
#   5. customer_impact
#   6. remediation_actions
#   7. mic_notification_status
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


def _section_incident_summary(d: Dict[str, Any]) -> str:
    """Generate the Incident Summary section."""
    severity = d.get("severity", "unknown").upper()
    incident_id = d.get("incident_id", "N/A")
    services = ", ".join(d.get("affected_services", []))
    detected = (d.get("timeline") or {}).get("detected_at", "N/A")
    resolved = (d.get("timeline") or {}).get("resolved_at") or "Ongoing"
    duration = d.get("duration_minutes", 0)
    lines = [
        f"Incident ID: {incident_id}",
        f"Severity:    {severity}",
        f"Affected Services: {services}",
        f"Detected:    {detected}",
        f"Resolved:    {resolved}",
        f"Duration:    {duration} minutes",
    ]
    return "\n".join(lines)


def _section_affected_services(d: Dict[str, Any]) -> str:
    """Generate the Affected Services section."""
    services: List[str] = d.get("affected_services", [])
    if not services:
        return "No services listed."
    lines = [f"  - {svc}" for svc in services]
    return "\n".join(lines)


def _section_timeline(d: Dict[str, Any]) -> str:
    """Generate the Timeline section from the timeline dict."""
    tl: Dict[str, Any] = d.get("timeline") or {}
    detected = tl.get("detected_at", "N/A")
    resolved = tl.get("resolved_at") or "Ongoing"
    duration = int(tl.get("duration_minutes", d.get("duration_minutes", 0)))
    lines = [
        f"  {detected}  Incident detected / first alert raised.",
        f"  {'[resolution]' if resolved != 'Ongoing' else '[ongoing]'}",
        f"  {resolved}  Incident resolved (or ongoing if blank).",
        f"  Total duration: {duration} minutes.",
    ]
    return "\n".join(lines)


def _section_root_cause(d: Dict[str, Any]) -> str:
    """Generate the Root Cause Analysis section."""
    rc = d.get("root_cause")
    if not rc:
        return (
            "Root cause is under investigation. "
            "This section will be updated when the post-incident analysis (PIA) is complete."
        )
    return str(rc)


def _section_customer_impact(d: Dict[str, Any]) -> str:
    """Generate the Customer Impact section."""
    ci: Dict[str, Any] = d.get("customer_impact") or {}
    subscribers = int(ci.get("affected_subscribers", d.get("affected_subscribers", 0)))
    description = str(ci.get("impact_description", "")) or "Service degradation experienced by affected subscribers."
    lines = [
        f"  Affected Subscribers: {subscribers:,}",
        f"  Impact Description:   {description}",
    ]
    return "\n".join(lines)


def _section_remediation(d: Dict[str, Any]) -> str:
    """Generate the Remediation Actions section."""
    actions: List[Any] = d.get("remediation_actions", [])
    if not actions:
        return "No remediation actions recorded."
    lines = [f"  {i+1}. {action}" for i, action in enumerate(actions)]
    return "\n".join(lines)


def _section_mic_status(d: Dict[str, Any]) -> str:
    """Generate the MIC Notification Status section.

    Renders the MIC Art. 58(2) service-category threshold evaluation. Each pair
    requires BOTH the affected-user count AND the outage duration to be met.
    """
    status_val = str(d.get("mic_notification_status", "pending")).lower()
    mic_reportable = d.get("mic_reportable", False)
    subscribers = int(d.get("affected_subscribers", 0))
    duration = int(d.get("duration_minutes", 0))
    services = d.get("affected_services", []) or []
    category = d.get("service_category") or mic_policy.classify_service_category(services)
    pairs = mic_policy.MIC_THRESHOLD_PAIRS.get(category, mic_policy.MIC_THRESHOLD_PAIRS["other"])
    lines = [
        f"  Notification Status: {status_val.upper()}",
        f"  Regulatory Basis: {mic_policy.MIC_REGULATORY_BASIS}",
        f"  Service Category: {category}",
        f"  MIC Reportable: {'YES' if mic_reportable else 'NO'}",
        f"  Actuals: {subscribers:,} affected subscribers, {duration} min outage",
        "  Threshold pairs (reportable if ANY pair met — BOTH count AND duration required):",
    ]
    for min_users, min_minutes in pairs:
        met = subscribers >= min_users and duration >= min_minutes
        lines.append(f"    - >= {min_users:,} users AND >= {min_minutes} min: " f"{'MET' if met else 'NOT MET'}")
    return "\n".join(lines)


class GenerateReportSectionsNode(FunctionNode):
    """Generate all 7 MIC-compliant incident report sections.

    v1: deterministic template-based synthesis (no LLM configuration is read).
    v-next: render prompts/network_incident.j2 (the manifest's
    llm.system_prompt_template, forwarded to the inner graph's constructor and
    injected into this node via its own constructor — execute(self, state)
    takes no config parameter) and invoke the platform SDK LLM here.
    See docs/02_design.md.

    Inner node — ANONYMOUS trust (see module docstring).

    Input state keys:
        incident_data: str  — JSON-serialised enriched incident payload

    Output state keys (partial dict):
        report_sections: str  — JSON-serialised section dict
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
        incident_data: Dict[str, Any] = from_json(state.get("incident_data"), {})

        # v1 is deterministic and reads no LLM configuration. The manifest's
        # llm.* settings reach DomainWorkflowGraph via its constructor (see
        # graph.py _parent_config); v-next injects them into this node through
        # its constructor, renders the prompt template, and invokes the SDK LLM
        # here. See docs/02_design.md.

        if not incident_data:
            logger.error("GenerateReportSectionsNode: incident_data missing in state")
            emit_trace_event(
                "generate_report_sections_failed",
                {"reason": "missing_incident_data"},
                state,
            )
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["GenerateReportSectionsNode: incident_data missing in state"],
            }

        incident_id = incident_data.get("incident_id", "unknown")

        # ── Generate all sections ─────────────────────────────────────────────
        sections: Dict[str, str] = {
            "incident_summary": _section_incident_summary(incident_data),
            "affected_services": _section_affected_services(incident_data),
            "timeline": _section_timeline(incident_data),
            "root_cause_analysis": _section_root_cause(incident_data),
            "customer_impact": _section_customer_impact(incident_data),
            "remediation_actions": _section_remediation(incident_data),
            "mic_notification_status": _section_mic_status(incident_data),
        }

        logger.info(
            "GenerateReportSectionsNode: incident_id=%s sections=%d",
            incident_id,
            len(sections),
        )
        emit_trace_event(
            "generate_report_sections_complete",
            {
                "incident_id": incident_id,
                "section_count": len(sections),
                "section_keys": sorted(sections.keys()),
            },
            state,
        )

        return {
            "report_sections": to_json(sections),
            "status": AgentStatus.SUCCESS.value,
        }
