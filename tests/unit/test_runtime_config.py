# TEL-C2-007 — Runtime-config liveness tests
#
# config/config.yaml is only worth shipping if every declared value provably
# ARRIVES at its consumer. These tests pin the whole chain:
#
#   config/config.yaml --load_runtime_config()--> outer Graph(config=...)
#                       \--IncidentReportGraphNode._parent_config()-->
#                          DomainWorkflowGraph(config=...) [validated at compile()]
#
# and pin the failure mode: a malformed declaration raises ConfigError instead
# of silently degrading to defaults.

import pytest

from framework.errors import ConfigError


class TestLoader:
    def test_shipped_file_loads_with_declared_values(self):
        from src.graph.graph import load_runtime_config

        cfg = load_runtime_config()
        # The declared values in the shipped config/config.yaml.
        assert cfg["max_retry"] == 3
        assert cfg["timeout_s"] == 30
        assert cfg["llm"]["system_prompt_template"] == "prompts/network_incident.j2"
        assert cfg["llm"]["temperature"] == 0.0
        assert cfg["llm"]["max_tokens"] == 4000
        assert cfg["security"]["s3_gate_enabled"] is True

    def test_missing_file_fails_loudly(self, monkeypatch):
        import src.graph.graph as graph_mod

        monkeypatch.setattr(graph_mod, "_RUNTIME_CONFIG_PATH", "/nonexistent/config.yaml")
        with pytest.raises(ConfigError):
            graph_mod.load_runtime_config()

    def test_malformed_file_fails_loudly(self, tmp_path, monkeypatch):
        import src.graph.graph as graph_mod

        bad = tmp_path / "config.yaml"
        bad.write_text("just a scalar")
        monkeypatch.setattr(graph_mod, "_RUNTIME_CONFIG_PATH", str(bad))
        with pytest.raises(ConfigError):
            graph_mod.load_runtime_config()


class TestDeclaredValuesReachTheInnerGraph:
    def test_parent_config_forwards_declared_values(self):
        from src.graph.graph import IncidentReportGraphNode

        inner = IncidentReportGraphNode().get_subgraph()
        # The inner graph instance carries the declared values...
        assert inner.config["configurable"]["system_prompt_template"] == "prompts/network_incident.j2"
        assert inner.config["configurable"]["temperature"] == 0.0
        assert inner.config["configurable"]["max_tokens"] == 4000
        assert inner.config["timeout_s"] == 30
        assert inner.config["max_retry"] == 3
        # ...and they survive its own compile-time validation.
        inner._validate_config()

    def test_absent_keys_are_omitted_not_defaulted(self, tmp_path, monkeypatch):
        import src.graph.graph as graph_mod

        partial = tmp_path / "config.yaml"
        partial.write_text("llm:\n  temperature: 0.5\n")
        monkeypatch.setattr(graph_mod, "_RUNTIME_CONFIG_PATH", str(partial))
        inner = graph_mod.IncidentReportGraphNode().get_subgraph()
        assert inner.config["configurable"] == {"temperature": 0.5}
        assert "timeout_s" not in inner.config
        assert "max_retry" not in inner.config


class TestMalformedDeclarationsFailTheInvocation:
    @pytest.mark.parametrize(
        "yaml_text,expect",
        [
            ("llm:\n  temperature: 9.5\n", "temperature"),
            ("llm:\n  temperature: yes\n", "temperature"),
            ("llm:\n  max_tokens: 0\n", "max_tokens"),
            ("llm:\n  max_tokens: many\n", "max_tokens"),
            ("llm:\n  system_prompt_template: prompts/wrong.txt\n", "system_prompt_template"),
            ("timeout_s: -5\n", "timeout_s"),
            ("timeout_s: soon\n", "timeout_s"),
            ("max_retry: true\n", "max_retry"),
        ],
    )
    def test_inner_graph_rejects_garbage_declarations(self, tmp_path, monkeypatch, yaml_text, expect):
        import src.graph.graph as graph_mod

        bad = tmp_path / "config.yaml"
        bad.write_text(yaml_text)
        monkeypatch.setattr(graph_mod, "_RUNTIME_CONFIG_PATH", str(bad))
        inner = graph_mod.IncidentReportGraphNode().get_subgraph()
        with pytest.raises(ConfigError, match=expect):
            inner.compile()

    def test_outer_graph_validates_its_own_config(self):
        from src.graph.graph import NetworkIncidentReportGeneratorAgent

        agent = NetworkIncidentReportGeneratorAgent(config={"max_retry": -1})
        with pytest.raises(ConfigError):
            agent.compile()


class TestServerConstructsWithConfig:
    def test_shipped_config_compiles_the_outer_graph(self):
        # The standalone server does Graph(config=load_runtime_config()) —
        # prove that exact construction compiles with the shipped file.
        from src.graph.graph import Graph, load_runtime_config

        agent = Graph(config=load_runtime_config())
        agent.compile()
        assert agent.config["max_retry"] == 3
