"""AgentCore Platform v1.0"""

# TEL-C2-007 — Outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Architecture (Cat 2):
#
#   Outer backbone (fixed — identical to Cat 1, do NOT override add_edges()):
#     START → initialize → pre_process → main → {route} → post_process → finalize → END
#                                             ↓ (RETRY, max 3)
#                                          pre_process
#
#   `main` slot is a GraphNode subclass (IncidentReportGraphNode) that delegates
#   the full domain workflow to DomainWorkflowGraph (inner BaseGraph).
#
#   Domain complexity is fully encapsulated inside the inner graph. The outer
#   backbone is never modified.
#
# Directory layout:
#   src/graph/graph.py                 ← outer graph (this file)
#   src/graph/domain_workflow_graph.py ← inner graph (multi-step topology)
#   src/graph/context_bridge.py        ← validated-payload bridge (outer → inner)
#
# Rules enforced:
#   ✅ NetworkIncidentReportGeneratorAgent inherits AgentBaseGraph
#   ✅ super().register_nodes() called first (fills initialize + finalize)
#   ✅ IncidentReportGraphNode assigned to self._nodes["main"]
#   ✅ PreProcessNode (VERIFIED_EXTERNAL) in pre_process slot (trust gate)
#   ✅ PostProcessNode (ANONYMOUS) in post_process slot (output gate)
#   ✅ merge_output() returns only changed keys
#   ✅ class name matches config/agent.yaml class: field exactly
#   ❌ add_edges() NOT overridden on the outer graph
#   ❌ No platform-internal SDK imports

import os
from typing import TYPE_CHECKING, Any, ClassVar

from framework.schemas.agent_status import AgentStatus
from framework.errors import ConfigError
from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from src.graph.context_bridge import stash_incident_payload
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State

if TYPE_CHECKING:
    from src.graph.domain_workflow_graph import DomainWorkflowGraph

# Runtime parameters — config/config.yaml at the repo root (three levels up
# from this file: src/graph/graph.py -> src/graph -> src -> <repo root>).
# The static manifest (config/agent.yaml) holds registry/identity keys only;
# every runtime value (max_retry, timeout_s, llm.*, security.*) lives in
# config/config.yaml and is loaded from there.
_RUNTIME_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "config.yaml",
)

# Neutral token handed to the inner graph as its user_input. The real incident
# record crosses the boundary via the context bridge (see context_bridge.py) —
# never via the masked user_input string channel.
_INNER_INPUT_TOKEN = "incident-report-request"


def load_runtime_config() -> dict[str, Any]:
    """Load config/config.yaml (the runtime parameter file).

    Fails LOUDLY (ConfigError) when the file is missing or malformed: the file
    ships with the repository, so its absence is a broken deployment. Silently
    degrading to hard-coded defaults would run the agent with every declared
    runtime value ignored — worse than refusing to start.
    """
    import yaml

    try:
        with open(_RUNTIME_CONFIG_PATH, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        raise ConfigError(
            f"runtime config not found at {_RUNTIME_CONFIG_PATH}; " "config/config.yaml must ship with the deployment"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"runtime config is not valid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError("runtime config must be a YAML mapping")
    return loaded


class IncidentReportGraphNode(GraphNode):
    """GraphNode subclass assigned to the `main` slot of NetworkIncidentReportGeneratorAgent.

    Wraps DomainWorkflowGraph (inner Cat 2 BaseGraph).
    Called by the AgentBaseGraph backbone after pre_process and before post_process.

    Contracts:
      get_subgraph()  — instantiate and return DomainWorkflowGraph
      extract_input() — stash the validated incident payload on the context
                        bridge and hand the inner graph a neutral token
      merge_output()  — map sub_result fields into outer state delta (changed keys only)
      error_strategy  — "propagate": re-raise inner errors as SubgraphError (fail-fast)
    """

    error_strategy: ClassVar[str] = "propagate"
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> "DomainWorkflowGraph":
        """Instantiate and return the inner domain workflow graph.

        DomainWorkflowGraph is imported lazily (inside the method) to avoid
        circular-import risk at module load time.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=self._parent_config())

    def execute(self, state: AgentState) -> dict[str, Any]:
        """Skip the inner graph when the request was already found unacceptable.

        A request declined by pre_process has no validated input to act on, so
        running the inner graph would only produce a second, vaguer reason for
        the same rejection - and overwrite the specific one already settled.
        """
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        result: dict[str, Any] = super().execute(state)
        return result

    def extract_input(self, state: AgentState) -> str:
        """Bridge the validated payload to the inner graph; return a neutral token.

        PreProcessNode validates the caller record and writes the normalised
        JSON to validated_input. That string must NOT travel to the inner graph
        as its user_input: the framework rewrites the user_input/validated_input
        channels at every node boundary (its personal-name masking heuristic
        matches consecutive Title Case words, which is exactly the shape of
        canonical service names like "Wi-Fi Calling"). The payload therefore
        crosses via the context bridge, and the inner graph receives only a
        fixed token on the string channel.

        The bridge is stashed even when validated_input is absent (upstream
        error paths): pop-on-read semantics keep a stale payload from a prior
        run from ever being observed.
        """
        stash_incident_payload(state.get("validated_input"))
        return _INNER_INPUT_TOKEN

    def merge_output(self, state: AgentState, sub_result: dict[str, Any]) -> dict[str, Any]:
        """Map inner graph sub_result back into the outer state delta.

        sub_result is the dict returned by DomainWorkflowGraph.get_output().
        Returns ONLY changed keys — never the full state.

        Key coupling (designed together with DomainWorkflowGraph.get_output()):
          Inner get_output() emits  → "incident_report", "report_sections",
                                       "compliance_flags", "mic_required", "status"
          This merge_output() reads → sub_result.get(...) for each of these keys.

        PostProcessNode (outer post_process) reads incident_report + mic_required
        from state to apply the output gate and set formatted_output.
        """
        return {
            # Outer reason wins: a reason settled before the inner run is the real
            # one, and a plain sub_result.get() would erase it.
            "error_code": state.get("error_code") or sub_result.get("error_code", ""),
            "incident_report": sub_result.get("incident_report"),
            "report_sections": sub_result.get("report_sections"),
            "compliance_flags": sub_result.get("compliance_flags"),
            "mic_required": sub_result.get("mic_required", False),
            "status": sub_result.get("status"),
        }

    def _parent_config(self) -> dict[str, Any]:
        """Forward the declared runtime config to the inner graph.

        Loads config/config.yaml (the same file the standalone server and the
        registry pass to the outer graph's constructor) and forwards the
        declared llm settings under the ``configurable`` key — the shape the
        inner graph validates and its nodes consume via constructor injection
        (the node execute() contract allows no config parameter) — together
        with the runtime bounds (``timeout_s``, ``max_retry``). Only keys the
        file actually declares are forwarded; the inner graph's
        _validate_config() then type-checks every declared value, so a
        malformed declaration fails the invocation instead of silently
        degrading to defaults.
        """
        cfg = load_runtime_config()
        llm = cfg.get("llm", {}) or {}
        declared = {
            "system_prompt_template": llm.get("system_prompt_template"),
            "temperature": llm.get("temperature"),
            "max_tokens": llm.get("max_tokens"),
        }
        forwarded: dict[str, Any] = {
            "configurable": {k: v for k, v in declared.items() if v is not None},
        }
        for key in ("timeout_s", "max_retry"):
            if cfg.get(key) is not None:
                forwarded[key] = cfg[key]
        return forwarded


class NetworkIncidentReportGeneratorAgent(AgentBaseGraph):
    """Outer graph for TEL-C2-007 (Cat 2 — document-generation pipeline).

    Inherits AgentBaseGraph (the framework base class) directly. Domain logic
    is fully encapsulated in IncidentReportGraphNode (main slot), which
    delegates to DomainWorkflowGraph (inner BaseGraph).

    Backbone (fixed — identical to Cat 1):
        START → initialize → pre_process → main → post_process → finalize → END

    register_nodes() is the ONLY override:
      - super().register_nodes() fills: initialize, finalize (framework defaults)
      - pre_process: PreProcessNode    (VERIFIED_EXTERNAL — trust gate)
      - main:        IncidentReportGraphNode (delegates to DomainWorkflowGraph)
      - post_process: PostProcessNode  (ANONYMOUS — output gate)

    add_edges() is NOT overridden — backbone wiring belongs to the framework.

    Class name MUST match config/agent.yaml `class:` field exactly.
    server.py imports this as `Graph` via the alias below and constructs it
    with ``Graph(config=load_runtime_config())`` so the declared runtime
    values (max_retry, hitl, memory) govern the backbone's routing — a bare
    ``Graph()`` would silently run on hard-coded defaults.
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with AgentRegistry."""
        return "NetworkIncidentReportGeneratorAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the
        framework's default InitializeNode (sets schema_version, session_id,
        trust_level) and FinalizeNode (builds response_metadata, total_time_ms).
        """
        super().register_nodes()  # fills: initialize, finalize

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = IncidentReportGraphNode()
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


# Alias for backward compat (server.py imports Graph).
# Class name NetworkIncidentReportGeneratorAgent matches config/agent.yaml class: field.
Graph = NetworkIncidentReportGeneratorAgent
