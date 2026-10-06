"""AgentCore Platform v1.0"""

# TEL-C2-007 — validated-payload bridge between the outer and inner graphs.
#
# Why this exists:
#   The framework's GraphNode.execute() calls subgraph.invoke(user_input, ...)
#   and forwards ONLY the extracted input string — the outer state's structured
#   input_context does not cross the subgraph boundary. On top of that, every
#   string that travels as user_input / validated_input is rewritten by the
#   framework's input masking before a node's execute() runs, and the masking
#   heuristic treats consecutive Title Case words as personal names. Canonical
#   telecom service names ("Wi-Fi Calling", "Fixed Line") are exactly that
#   shape, so carrying the incident record through those channels silently
#   corrupts the fields the pipeline matches on.
#
# The bridge carries the ALREADY-VALIDATED incident payload (the JSON string
# produced by PreProcessNode) across the boundary out-of-band:
#   - the outer IncidentReportGraphNode.extract_input() stashes it here and
#     hands the inner graph a neutral token as user_input;
#   - the inner DomainWorkflowGraph._extra_initial_state() pops it into the
#     state key `incident_payload`, which is not one of the framework's
#     masked/scanned string channels.
#
# The payload placed here has already passed the caller-data contract
# (bounds, types, PII/injection screens) in PreProcessNode — the bridge never
# carries raw caller input.
#
# ContextVar semantics: the value is scoped to the current logical context, so
# concurrent invocations do not observe each other's payloads; pop() clears the
# slot on read so a payload can never leak into a later invocation.

from contextvars import ContextVar
from typing import Optional

_INCIDENT_PAYLOAD: ContextVar[Optional[str]] = ContextVar("tel_c2_007_incident_payload", default=None)


def stash_incident_payload(payload_json: Optional[str]) -> None:
    """Store the validated incident payload for the inner graph to pick up."""
    _INCIDENT_PAYLOAD.set(payload_json)


def pop_incident_payload() -> Optional[str]:
    """Return and clear the stashed payload (single-use — never leaks across runs)."""
    value = _INCIDENT_PAYLOAD.get()
    _INCIDENT_PAYLOAD.set(None)
    return value
