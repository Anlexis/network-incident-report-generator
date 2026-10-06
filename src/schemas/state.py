"""AgentCore Platform v1.0"""

# State must be a flat TypedDict — never Pydantic BaseModel.
# LangGraph checkpoints use msgpack serialization; Pydantic objects
# cause silent corruption.  Extend AgentState with agent-specific
# fields only.  Do NOT add credentials, secrets, or Pydantic models.
#
# TEL-C2-007 — Network Incident Report Generator
# Two-layer nested Cat 2 graph: outer backbone (AgentBaseGraph) + inner
# domain workflow (BaseGraph).  Fields below cover both layers.
#
# Serialization contract: all dict/list-valued fields are stored as JSON-
# serialized Optional[str].  Use to_json() / from_json() helpers below
# at every producer and consumer node — one contract end-to-end.
# Never type a dict/list field as a bare dict/list; msgpack checkpoint
# serialization fails on them.

import json
from typing import Any, NotRequired, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a value to a JSON string for State storage."""
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def from_json(value: Optional[str], default: Any = None) -> Any:
    """Deserialize a JSON string from State storage."""
    if value is None:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


class State(AgentState):
    """Flat TypedDict for TEL-C2-007.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, etc.) are inherited from AgentState.

    Dict/list fields use JSON-serialized Optional[str] (see module note).
    formatted_output is NOT re-declared here — it is inherited from AgentState.
    """

    # ------------------------------------------------------------------
    # Outer layer — set by PreProcessNode (pre_process backbone, trust gate)
    # ------------------------------------------------------------------

    # Validated and normalised JSON string of the incident payload.
    # Produced by PreProcessNode. NOTE: this key is one of the framework's
    # masked/scanned string channels, so the inner graph never reads it —
    # the payload crosses the subgraph boundary via the context bridge into
    # incident_payload below.
    validated_input: NotRequired[Optional[str]]

    # JSON-serialised channel/request metadata dict (stored as str).
    # Shape: {"source": str, "channel": str, "incident_id": str}
    enriched_context: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Inner layer — domain nodes (DomainWorkflowGraph)
    # ------------------------------------------------------------------

    # Validated incident payload (JSON string), seeded into the INNER graph's
    # initial state from the context bridge (DomainWorkflowGraph.
    # _extra_initial_state). Template-owned key: not one of the framework's
    # masked/scanned string channels, so Title Case service names survive.
    # Consumed by InputValidateNode.
    incident_payload: NotRequired[Optional[str]]

    # JSON-serialised parsed incident payload (stored as str).
    # Shape: {incident_id, affected_services (list), timeline (dict),
    #   root_cause (str|None), customer_impact (dict),
    #   remediation_actions (list), mic_notification_status (str),
    #   severity (str), duration_minutes (int), affected_subscribers (int)}
    incident_data: NotRequired[Optional[str]]

    # JSON-serialised report section dict (stored as str).
    # Keys match the 7 MIC-required sections:
    #   incident_summary, affected_services, timeline,
    #   root_cause_analysis, customer_impact,
    #   remediation_actions, mic_notification_status
    # Each value is the rendered text for that section.
    report_sections: NotRequired[Optional[str]]

    # JSON-serialised MIC Art. 58(2) compliance check result (stored as str).
    # Shape: {mic_required: bool, reason: str, service_category: str,
    #   policy_version: str, regulatory_basis: str,
    #   thresholds_applied: list[{min_subscribers, min_duration_minutes}],
    #   met_threshold_pairs: list[{min_subscribers, min_duration_minutes}],
    #   actual_subscribers: int, actual_duration_minutes: int,
    #   notification_deadline_hours: int}
    compliance_flags: NotRequired[Optional[str]]

    # True if MIC (総務省) serious-accident notification is required.
    # Basis: Telecommunications Business Act Enforcement Regulations Art. 58(2).
    # Service-category thresholds require BOTH an affected-user count AND an
    # outage duration (e.g. voice/internet: 30,000 users for >=2h OR 100,000 for
    # >=1h). Single source of truth: src/services/mic_policy.py.
    mic_required: NotRequired[Optional[bool]]

    # Final formatted incident report document (plain text, MIC-ready).
    # Assembled by inner OutputFormatNode from report_sections + compliance_flags.
    incident_report: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Outer layer — set by PostProcessNode (post_process backbone, output gate)
    # ------------------------------------------------------------------

    # Primary result surfaced to the caller.
    # Set to the same content as incident_report after the output gate passes.
    # formatted_output (from AgentState) is also set by PostProcessNode.
    result: NotRequired[Optional[str]]

    # ------------------------------------------------------------------
    # Tracing / audit — framework-managed; do NOT write from node code
    # ------------------------------------------------------------------

    trace_id: NotRequired[Optional[str]]
    correlation_id: NotRequired[Optional[str]]

    # Reason a run COMPLETED without carrying out the request, because the
    # caller can correct the value and send it again: "EMPTY_INPUT",
    # "QUESTION_TOO_LONG", "INVALID_REQUEST". A closed set of codes, never
    # caller content. Written by the declining node, passed through untouched
    # by every node after it, and rendered as the caller-facing sentence by
    # PostProcessNode. Absent on a run that produced a report, and absent on a
    # run that TERMINATED (a refusal, or a contract breach the caller cannot
    # act on) — those keep AgentStatus.ERROR.
    error_code: NotRequired[Optional[str]]
    # node_history inherited from AgentState
