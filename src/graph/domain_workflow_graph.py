"""AgentCore Platform v1.0"""

# TEL-C2-007 — DomainWorkflowGraph (inner BaseGraph)
#
# This is the INNER graph for the Cat 2 two-layer nested architecture.
# It encapsulates the network incident report generation pipeline:
#
#   START
#     → input_validate          (InputValidateNode)
#     → parse_incident_data     (ParseIncidentDataNode)
#     → generate_report_sections (GenerateReportSectionsNode)
#     → compliance_check        (ComplianceCheckNode)
#     → output_format           (OutputFormatNode)
#     → END
#
# Called by IncidentReportGraphNode.get_subgraph() (graph.py).
# get_output() shapes the sub_result dict consumed by merge_output() there.
#
# Rules enforced:
#   ✅ Inherits BaseGraph (fully custom topology — no forced backbone)
#   ✅ Implements all 7 BaseGraph ABC methods
#   ✅ register_nodes() does NOT call super() (abstract in BaseGraph)
#   ✅ Does NOT register initialize / finalize (outer backbone concerns)
#   ✅ All inner nodes declare required_trust_level = TrustLevel.ANONYMOUS
#      (the outer pre_process slot already enforced caller trust)
#   ✅ get_output() designed together with IncidentReportGraphNode.merge_output()
#   ✅ All inner node ctors are empty-parens (no constructor args)
#   ❌ No platform-internal SDK imports
#   ❌ Not placed under src/subagents/

from typing import Any

from langgraph.graph import END, START

from framework.errors import ConfigError
from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.nodes.compliance_check_node import ComplianceCheckNode
from src.nodes.generate_report_sections_node import GenerateReportSectionsNode
from src.nodes.input_validate_node import InputValidateNode
from src.nodes.output_format_node import OutputFormatNode
from src.nodes.parse_incident_data_node import ParseIncidentDataNode
from src.graph.context_bridge import pop_incident_payload
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for TEL-C2-007.

    Inherits BaseGraph directly for a fully custom node topology.
    Called by IncidentReportGraphNode.get_subgraph() in graph.py.

    Pipeline (linear):
        START
          → input_validate            (InputValidateNode)
          → parse_incident_data       (ParseIncidentDataNode)
          → generate_report_sections  (GenerateReportSectionsNode)
          → compliance_check          (ComplianceCheckNode)
          → output_format             (OutputFormatNode)
          → END

    All nodes are FunctionNode subclasses with ANONYMOUS trust_level.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "tel_c2_007_network_incident_report_workflow"

    @property
    def state_schema(self) -> type:
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """Type-check every declared runtime value forwarded by the outer graph.

        No key is mandatory for the deterministic pipeline, but a DECLARED key
        must be well-formed: a malformed declaration fails the invocation here
        (ConfigError) instead of silently degrading to defaults. This is what
        keeps config/config.yaml live end-to-end — garbage in the file cannot
        run.
        """
        configurable = self.config.get("configurable", {})
        if not isinstance(configurable, dict):
            raise ConfigError("'configurable' must be a mapping")

        template = configurable.get("system_prompt_template")
        if template is not None and (not isinstance(template, str) or not template.endswith(".j2")):
            raise ConfigError("'llm.system_prompt_template' must be a .j2 template path")
        temperature = configurable.get("temperature")
        if temperature is not None and (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not (0.0 <= float(temperature) <= 2.0)
        ):
            raise ConfigError("'llm.temperature' must be a number in [0.0, 2.0]")
        max_tokens = configurable.get("max_tokens")
        if max_tokens is not None and (
            isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not (1 <= max_tokens <= 200_000)
        ):
            raise ConfigError("'llm.max_tokens' must be an integer in [1, 200000]")

        for key in ("timeout_s", "max_retry"):
            value = self.config.get(key)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ConfigError(f"'{key}' must be a non-negative integer")

    # ── Initial state (context-bridge seeding) ───────────────────────────────

    def _extra_initial_state(self) -> dict[str, Any]:
        """Seed the validated incident payload from the context bridge.

        The outer IncidentReportGraphNode.extract_input() stashes the validated
        record there because the framework's GraphNode does not forward
        input_context to subgraph.invoke(), and the user_input string channel
        is rewritten by input masking at every node boundary (which corrupts
        Title Case service names). incident_payload is a template-owned state
        key outside the masked channels; the bridge pops on read, so a stale
        payload can never leak into a later invocation.
        """
        payload = pop_incident_payload()
        return {"incident_payload": payload} if payload is not None else {}

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all 5 domain nodes.

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize; those are outer backbone
        concerns handled by AgentBaseGraph in graph.py.
        Every key registered here is referenced in add_edges().
        All nodes are instantiated with empty-parens (no ctor args) —
        FunctionNode subclasses take no constructor arguments.
        """
        self._nodes["input_validate"] = InputValidateNode()
        self._nodes["parse_incident_data"] = ParseIncidentDataNode()
        self._nodes["generate_report_sections"] = GenerateReportSectionsNode()
        self._nodes["compliance_check"] = ComplianceCheckNode()
        self._nodes["output_format"] = OutputFormatNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear incident-report generation topology.

        Linear flow:
            input_validate → parse_incident_data → generate_report_sections
            → compliance_check → output_format → END.

        No conditional branching — all paths through the report pipeline are
        linear in v1.  route() satisfies the ABC but is not used at runtime.
        """
        self._sg.add_edge(START, "input_validate")
        self._sg.add_edge("input_validate", "parse_incident_data")
        self._sg.add_edge("parse_incident_data", "generate_report_sections")
        self._sg.add_edge("generate_report_sections", "compliance_check")
        self._sg.add_edge("compliance_check", "output_format")
        self._sg.add_edge("output_format", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Conditional routing — required by BaseGraph ABC.

        Linear topology; add_conditional_edges() is not used, so this method
        is never called at runtime.  Returns END on error so an unexpected
        invocation does not re-enter a processing node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "output_format"

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> dict[str, Any]:
        """Shape the output dict returned to the outer graph as sub_result.

        This dict is received by IncidentReportGraphNode.merge_output()
        in graph.py as the `sub_result` argument.  Both methods are designed
        together to guarantee field-name consistency:

            Inner get_output() emits:   "incident_report", "report_sections",
                                        "compliance_flags", "mic_required", "status"
            Outer merge_output() reads: sub_result.get(...) for each key above.
        """
        return {
            # the reason must leave the subgraph or the outer graph cannot report it
            "error_code": state.get("error_code"),
            "incident_report": state.get("incident_report"),
            "report_sections": state.get("report_sections"),
            "compliance_flags": state.get("compliance_flags"),
            "mic_required": state.get("mic_required", False),
            "status": state.get("status"),
            "node_history": state.get("node_history", []),
            "correlation_id": state.get("correlation_id"),
        }
