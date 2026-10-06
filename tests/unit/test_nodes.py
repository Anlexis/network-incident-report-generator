# TEL-C2-007 — Unit Tests: domain nodes + graph wiring
#
# Real unit tests over the real modules: report content, MIC Art. 58(2)
# thresholds, trust levels, the output gate, and the Cat 2 two-layer graph
# composition.
#
# Audit events are patched at the node MODULE level (not via a sys.modules
# stub, which would break the real `shared` package the framework loads at import
# time). Patch pattern per node:
#     monkeypatch.setattr("src.nodes.<mod>.emit_trace_event", lambda *a, **k: None)

import json

import pytest

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.schemas.state import from_json, to_json


# ── Shared fixtures / helpers ─────────────────────────────────────────────────


def _incident_payload(**overrides) -> dict:
    """A complete, valid raw incident payload (as a caller would POST)."""
    payload = {
        "incident_id": "TEL-INC-20260712-001",
        "severity": "high",
        "affected_services": ["5G", "VoLTE", "SMS"],
        "timeline": {
            "detected_at": "2026-07-12T02:14:00+09:00",
            "resolved_at": "2026-07-12T05:36:00+09:00",
            "duration_minutes": 202,
        },
        "root_cause": "Core router BGP session flap in the Tokyo metro ring.",
        "customer_impact": {
            "affected_subscribers": 48200,
            "impact_description": "Voice call setup failures across the Kanto region.",
        },
        "remediation_actions": [
            "Failed over the core router to the standby chassis.",
            "Cleared stale BGP sessions.",
        ],
        "mic_notification_status": "pending",
    }
    payload.update(overrides)
    return payload


VALID_PAYLOAD = json.dumps(_incident_payload())


def _incident_data(subscribers: int = 48200, duration: int = 202, **overrides) -> dict:
    """The normalised incident_data dict shape produced by InputValidateNode
    (i.e. the input the downstream inner nodes consume)."""
    data = {
        "incident_id": "TEL-INC-20260712-001",
        "affected_services": ["5G NR", "VoLTE", "SMS"],
        "timeline": {
            "detected_at": "2026-07-12T02:14:00+09:00",
            "resolved_at": "2026-07-12T05:36:00+09:00",
            "duration_minutes": duration,
        },
        "root_cause": "Core router BGP session flap in the Tokyo metro ring.",
        "customer_impact": {
            "affected_subscribers": subscribers,
            "impact_description": "Voice call setup failures across the Kanto region.",
        },
        "remediation_actions": ["Failed over to standby.", "Cleared BGP sessions."],
        "mic_notification_status": "pending",
        "severity": "high",
        "duration_minutes": duration,
        "affected_subscribers": subscribers,
    }
    data.update(overrides)
    return data


# ── PreProcessNode (outer pre_process, VERIFIED_EXTERNAL trust gate) ───────────


class TestPreProcessNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.pre_process_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.pre_process_node import PreProcessNode

        self.node = PreProcessNode()

    def test_valid_payload_returns_success(self):
        result = self.node(
            {"user_input": VALID_PAYLOAD, "input_context": {}, "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["validated_input"] is not None
        assert json.loads(result["validated_input"])["incident_id"] == "TEL-INC-20260712-001"

    def test_enriched_context_carries_incident_id(self):
        result = self.node(
            {
                "user_input": VALID_PAYLOAD,
                "input_context": {"channel": "noc"},
                "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
            }
        )
        ctx = from_json(result["enriched_context"])
        assert ctx["incident_id"] == "TEL-INC-20260712-001"
        assert ctx["channel"] == "noc"

    def test_empty_input_returns_error(self):
        result = self.node(
            {"user_input": "", "input_context": {}, "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("incident record" in e for e in result["error_log"])

    def test_invalid_json_returns_error(self):
        result = self.node(
            {
                "user_input": "{not valid json}",
                "input_context": {},
                "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
            }
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("JSON" in e or "json" in e for e in result["error_log"])

    def test_non_object_json_returns_error(self):
        result = self.node(
            {"user_input": "[1, 2, 3]", "input_context": {}, "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("object" in e for e in result["error_log"])

    def test_missing_required_field_returns_error(self):
        payload = {"incident_id": "X", "affected_services": ["5G"]}  # no 'timeline'
        result = self.node(
            {
                "user_input": json.dumps(payload),
                "input_context": {},
                "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
            }
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("timeline" in e for e in result["error_log"])

    def test_trust_level_is_verified_external(self):
        assert self.node.required_trust_level == TrustLevel.VERIFIED_EXTERNAL

    def test_execute_signature_is_state_first(self):
        import inspect
        from src.nodes.pre_process_node import PreProcessNode

        params = list(inspect.signature(PreProcessNode.execute).parameters.keys())
        assert params[0] == "self" and params[1] == "state"
        assert "_invoke_impl" not in PreProcessNode.__dict__


# ── InputValidateNode (inner domain node 1, ANONYMOUS) ─────────────────────────


class TestInputValidateNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.input_validate_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.input_validate_node import InputValidateNode

        self.node = InputValidateNode()

    def test_valid_input_builds_incident_data(self):
        result = self.node({"validated_input": VALID_PAYLOAD, "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        data = from_json(result["incident_data"])
        assert data["incident_id"] == "TEL-INC-20260712-001"
        assert data["affected_subscribers"] == 48200
        assert data["duration_minutes"] == 202

    def test_service_aliases_are_normalised(self):
        payload = _incident_payload(affected_services=["5g", "volte", "4g", "5G NR"])
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        data = from_json(result["incident_data"])
        # 5g/5G NR -> "5G NR" (deduped), volte -> "VoLTE", 4g -> "LTE"
        assert data["affected_services"] == ["5G NR", "VoLTE", "LTE"]

    def test_falls_back_to_user_input(self):
        result = self.node({"user_input": VALID_PAYLOAD, "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_empty_incident_id_returns_error(self):
        payload = _incident_payload(incident_id="")
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("incident_id" in e for e in result["error_log"])

    def test_empty_services_returns_error(self):
        payload = _incident_payload(affected_services=[])
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("affected_services" in e for e in result["error_log"])

    def test_missing_detected_at_returns_error(self):
        payload = _incident_payload(timeline={"duration_minutes": 30})
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("detected_at" in e for e in result["error_log"])

    # Malformed / negative numeric fields must yield a CONTROLLED validation
    # error before the MIC compliance decision — never an uncaught ValueError
    # or a misleading "not reportable" result.

    def test_negative_subscribers_returns_error(self):
        payload = _incident_payload(
            customer_impact={
                "affected_subscribers": -5,
                "impact_description": "negative count",
            }
        )
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("affected_subscribers" in e and "between 0" in e for e in result["error_log"])

    def test_malformed_subscribers_returns_error(self):
        payload = _incident_payload(
            customer_impact={
                "affected_subscribers": "not-a-number",
                "impact_description": "malformed count",
            }
        )
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("affected_subscribers" in e for e in result["error_log"])

    def test_negative_duration_returns_error(self):
        payload = _incident_payload(
            timeline={
                "detected_at": "2026-07-12T02:14:00+09:00",
                "duration_minutes": -30,
            }
        )
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("duration_minutes" in e and "between 0" in e for e in result["error_log"])

    def test_malformed_duration_returns_error(self):
        payload = _incident_payload(
            timeline={
                "detected_at": "2026-07-12T02:14:00+09:00",
                "duration_minutes": "abc",
            }
        )
        result = self.node({"validated_input": json.dumps(payload), "caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.SUCCESS.value
        # Completes carrying the reason, so the caller can correct the value and send the request again.
        assert result.get("error_code")
        assert any("duration_minutes" in e for e in result["error_log"])

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS


# ── ParseIncidentDataNode (inner domain node 2, ANONYMOUS) ─────────────────────


class TestParseIncidentDataNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.parse_incident_data_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.parse_incident_data_node import ParseIncidentDataNode

        self.node = ParseIncidentDataNode()

    def _run(self, subscribers, duration):
        state = {
            "incident_data": to_json(_incident_data(subscribers=subscribers, duration=duration)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        return self.node(state)

    def test_critical_severity_by_subscribers(self):
        data = from_json(self._run(subscribers=150000, duration=30)["incident_data"])
        assert data["severity"] == "critical"

    def test_high_severity_by_duration(self):
        data = from_json(self._run(subscribers=500, duration=130)["incident_data"])
        assert data["severity"] == "high"

    def test_medium_severity(self):
        data = from_json(self._run(subscribers=4000, duration=30)["incident_data"])
        assert data["severity"] == "medium"

    def test_low_severity(self):
        data = from_json(self._run(subscribers=100, duration=10)["incident_data"])
        assert data["severity"] == "low"

    def test_mic_reportable_flag_when_pair_fully_met(self):
        # 48,200 subs AND 202 min → meets the (30,000, 2h) voice pair.
        data = from_json(self._run(subscribers=48200, duration=202)["incident_data"])
        assert data["mic_reportable"] is True

    def test_not_mic_reportable_when_under_both_thresholds(self):
        data = from_json(self._run(subscribers=100, duration=10)["incident_data"])
        assert data["mic_reportable"] is False

    def test_not_mic_reportable_old_or_rule_false_positive(self):
        # 5,000 subs / 30 min: old OR rule said reportable; corrected paired
        # rule says NOT reportable. Regression guard at the pre-check.
        data = from_json(self._run(subscribers=5000, duration=30)["incident_data"])
        assert data["mic_reportable"] is False

    def test_service_category_derived(self):
        data = from_json(self._run(subscribers=48200, duration=202)["incident_data"])
        assert data["service_category"] == "voice"

    def test_missing_incident_data_returns_error(self):
        result = self.node({"caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.ERROR.value

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS


# ── GenerateReportSectionsNode (inner domain node 3, ANONYMOUS) ────────────────


class TestGenerateReportSectionsNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.generate_report_sections_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.generate_report_sections_node import GenerateReportSectionsNode

        self.node = GenerateReportSectionsNode()

    def test_generates_all_seven_sections(self):
        state = {
            "incident_data": to_json(_incident_data(mic_reportable=True)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        result = self.node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        sections = from_json(result["report_sections"])
        assert set(sections.keys()) == {
            "incident_summary",
            "affected_services",
            "timeline",
            "root_cause_analysis",
            "customer_impact",
            "remediation_actions",
            "mic_notification_status",
        }

    def test_summary_reflects_incident_fields(self):
        state = {
            "incident_data": to_json(_incident_data(mic_reportable=True)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        sections = from_json(self.node(state)["report_sections"])
        assert "TEL-INC-20260712-001" in sections["incident_summary"]
        assert "5G NR" in sections["affected_services"]

    def test_root_cause_placeholder_when_missing(self):
        data = _incident_data()
        data["root_cause"] = None
        sections = from_json(
            self.node({"incident_data": to_json(data), "caller_trust_level": TrustLevel.ANONYMOUS.value})[
                "report_sections"
            ]
        )
        assert "under investigation" in sections["root_cause_analysis"].lower()

    def test_missing_incident_data_returns_error(self):
        result = self.node({"caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.ERROR.value

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS


# ── ComplianceCheckNode (inner domain node 4, ANONYMOUS) ───────────────────────


class TestComplianceCheckNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.compliance_check_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.compliance_check_node import ComplianceCheckNode

        self.node = ComplianceCheckNode()

    # MIC Art. 58(2) corrected rule: reportable only
    # when a service-category pair is FULLY met — BOTH the affected-user count
    # AND the outage duration. Typical voice/internet pairs: (30,000 users, 2h)
    # OR (100,000 users, 1h). The _incident_data fixture uses voice services.

    def test_reportable_voice_30k_2h_pair(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=30000, duration=120)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        result = self.node(state)
        assert result["mic_required"] is True
        flags = from_json(result["compliance_flags"])
        assert {"min_subscribers": 30000, "min_duration_minutes": 120} in flags["met_threshold_pairs"]

    def test_reportable_100k_1h_pair(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=100000, duration=60)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        result = self.node(state)
        assert result["mic_required"] is True
        flags = from_json(result["compliance_flags"])
        assert {"min_subscribers": 100000, "min_duration_minutes": 60} in flags["met_threshold_pairs"]

    def test_reportable_large_incident(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=48200, duration=202)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is True

    def test_not_reportable_old_or_rule_subscriber_false_positive(self):
        # 5,000 subs / 30 min: reportable under the OLD (>=3,000 OR) rule,
        # NOT reportable under the corrected paired rule. Regression guard.
        state = {
            "incident_data": to_json(_incident_data(subscribers=5000, duration=30)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is False

    def test_not_reportable_old_or_rule_duration_false_positive(self):
        # 100 subs / 120 min: reportable under the OLD (>=120 OR) rule,
        # NOT reportable under the corrected paired rule. Regression guard.
        state = {
            "incident_data": to_json(_incident_data(subscribers=100, duration=120)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is False

    def test_boundary_subscribers_just_below_30k(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=29999, duration=180)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is False

    def test_boundary_duration_just_below_2h(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=50000, duration=119)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is False

    def test_boundary_100k_just_below_1h(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=100000, duration=59)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        assert self.node(state)["mic_required"] is False

    def test_not_reportable_under_all_thresholds(self):
        state = {
            "incident_data": to_json(_incident_data(subscribers=100, duration=10)),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }
        result = self.node(state)
        assert result["mic_required"] is False
        flags = from_json(result["compliance_flags"])
        assert flags["mic_required"] is False
        assert flags["met_threshold_pairs"] == []

    def test_compliance_flags_carry_policy_and_thresholds(self):
        state = {"incident_data": to_json(_incident_data()), "caller_trust_level": TrustLevel.ANONYMOUS.value}
        flags = from_json(self.node(state)["compliance_flags"])
        assert flags["service_category"] == "voice"
        assert flags["policy_version"]  # non-empty version string
        assert "Art. 58(2)" in flags["regulatory_basis"]
        assert {"min_subscribers": 30000, "min_duration_minutes": 120} in flags["thresholds_applied"]
        assert {"min_subscribers": 100000, "min_duration_minutes": 60} in flags["thresholds_applied"]

    def test_missing_incident_data_returns_error(self):
        result = self.node({"caller_trust_level": TrustLevel.ANONYMOUS.value})
        assert result["status"] == AgentStatus.ERROR.value

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS


# ── OutputFormatNode (inner domain node 5, ANONYMOUS) ──────────────────────────


class TestOutputFormatNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.output_format_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.output_format_node import OutputFormatNode

        self.node = OutputFormatNode()

    def _state(self, mic_required=True):
        sections = {
            "incident_summary": "Incident ID: TEL-INC-20260712-001",
            "affected_services": "  - 5G NR",
            "timeline": "  detected ...",
            "root_cause_analysis": "BGP flap.",
            "customer_impact": "  Affected Subscribers: 48,200",
            "remediation_actions": "  1. Failover.",
            "mic_notification_status": "  Notification Status: PENDING",
        }
        compliance = {
            "mic_required": mic_required,
            "reason": "Affected subscribers (48,200) >= 30,000 AND duration (202 min) >= 120 min",
            "regulatory_basis": "電気通信事業法施行規則 第58条第2項 (Telecommunications Business Act Enforcement Regulations Art. 58(2))",
            "notification_deadline_hours": 24,
        }
        return {
            "report_sections": to_json(sections),
            "compliance_flags": to_json(compliance),
            "incident_data": to_json(_incident_data()),
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
        }

    def test_assembles_full_report(self):
        result = self.node(self._state())
        assert result["status"] == AgentStatus.SUCCESS.value
        report = result["incident_report"]
        assert result["result"] == report
        assert "NETWORK INCIDENT REPORT" in report
        for header in (
            "1. Incident Summary",
            "2. Affected Services",
            "3. Timeline of Events",
            "4. Root Cause Analysis",
            "5. Customer Impact",
            "6. Remediation Actions",
            "7. MIC Notification Status",
            "REGULATORY COMPLIANCE NOTE",
        ):
            assert header in report, f"missing section header: {header}"

    def test_mic_required_note_present(self):
        report = self.node(self._state(mic_required=True))["incident_report"]
        assert "MIC Notification Required: YES" in report

    def test_mic_not_required_note(self):
        report = self.node(self._state(mic_required=False))["incident_report"]
        assert "MIC Notification Required: NO" in report

    def test_missing_sections_returns_error(self):
        result = self.node(
            {"incident_data": to_json(_incident_data()), "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.ERROR.value

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS


# ── PostProcessNode (outer post_process, output boundary, ANONYMOUS) ───────────


class TestPostProcessNode:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.post_process_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.post_process_node import PostProcessNode

        self.node = PostProcessNode()

    def test_clean_report_passes_gate(self):
        report = "NETWORK INCIDENT REPORT\nIncident ID: TEL-INC-1\nAll clear."
        result = self.node(
            {"incident_report": report, "mic_required": True, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"] == report
        assert result["result"] == report

    def test_empty_report_uses_fallback(self):
        result = self.node(
            {"incident_report": "", "mic_required": False, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "No report content generated" in result["formatted_output"]

    def test_output_gate_redacts_credential_leak(self):
        leaky = "NETWORK INCIDENT REPORT\ntoken=sk-abcdefghij0123456789ABCDEF"
        result = self.node(
            {"incident_report": leaky, "mic_required": True, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.ERROR.value
        assert "REDACTED" in result["formatted_output"]
        assert result["formatted_output"] == result["result"]
        assert any("credential" in e for e in result["error_log"])

    def test_output_gate_helper_detects_and_clears(self):
        from src.nodes.post_process_node import _security_gate_output

        assert _security_gate_output("sk-abcdefghij0123456789ABCDEF") is not None
        assert _security_gate_output("Bearer abcdefgh12345678") is not None
        assert _security_gate_output("password = supersecret123") is not None
        assert _security_gate_output("A perfectly clean incident report.") is None

    def test_trust_level_anonymous(self):
        assert self.node.required_trust_level == TrustLevel.ANONYMOUS

    # ── Layer 2: personal-identifier redaction on the final report ────────────

    def test_contact_pii_redacted_from_report_with_audit(self, monkeypatch):
        events = []
        monkeypatch.setattr(
            "src.nodes.post_process_node.emit_trace_event",
            lambda name, payload, state: events.append((name, payload)),
        )
        report = (
            "NETWORK INCIDENT REPORT\n"
            "Contact taro.yamada@example.com or 03-1234-5678 for details.\n"
            "SSN 123-45-6789 appeared in an attached note."
        )
        result = self.node(
            {"incident_report": report, "mic_required": False, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        out = result["formatted_output"]
        assert "taro.yamada@example.com" not in out
        assert "03-1234-5678" not in out
        assert "123-45-6789" not in out
        assert "[MASKED]" in out
        redact_events = [p for (n, p) in events if n == "post_process_pii_redacted"]
        assert redact_events and set(redact_events[0]["types"]) >= {"email", "phone_jp", "ssn_us"}

    def test_name_heuristic_not_redacted_in_report(self):
        # Canonical service names are consecutive Title Case words — the
        # report layer must not rewrite them (masking them would corrupt the
        # filing). Person names were already masked at intake.
        report = "NETWORK INCIDENT REPORT\n  - Wi-Fi Calling\n  - Fixed Line"
        result = self.node(
            {"incident_report": report, "mic_required": False, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "Wi-Fi Calling" in result["formatted_output"]
        assert "Fixed Line" in result["formatted_output"]
        assert "[MASKED]" not in result["formatted_output"]

    def test_credential_scan_runs_before_pii_redaction(self):
        # Layer order: the credential scan must see the untouched text. A JWT
        # containing an email-like token must be caught by layer 1 even though
        # layer 2 would have rewritten part of it.
        leaky = "Bearer abc.def1234@ghi-not-quite\ntoken=sk-abcdefghij0123456789ABCDEF"
        result = self.node(
            {"incident_report": leaky, "mic_required": False, "caller_trust_level": TrustLevel.ANONYMOUS.value}
        )
        assert result["status"] == AgentStatus.ERROR.value
        assert "REDACTED" in result["formatted_output"]


# ── Graph wiring: outer AgentBaseGraph + inner BaseGraph (Cat 2 nested) ─────────


class TestOuterGraphComposition:
    def test_registers_five_backbone_slots(self):
        from src.graph.graph import (
            IncidentReportGraphNode,
            NetworkIncidentReportGeneratorAgent,
        )
        from src.nodes.post_process_node import PostProcessNode
        from src.nodes.pre_process_node import PreProcessNode

        agent = NetworkIncidentReportGeneratorAgent()
        agent.compile()
        assert set(agent._nodes.keys()) == {
            "initialize",
            "pre_process",
            "main",
            "post_process",
            "finalize",
        }
        assert isinstance(agent._nodes["pre_process"], PreProcessNode)
        assert isinstance(agent._nodes["main"], IncidentReportGraphNode)
        assert isinstance(agent._nodes["post_process"], PostProcessNode)

    def test_name_and_state_schema(self):
        from src.schemas.state import State
        from src.graph.graph import NetworkIncidentReportGeneratorAgent

        agent = NetworkIncidentReportGeneratorAgent()
        assert agent.name == "NetworkIncidentReportGeneratorAgent"
        assert agent.state_schema is State

    def test_graph_alias_matches_real_class(self):
        from src.graph.graph import Graph, NetworkIncidentReportGeneratorAgent

        assert Graph is NetworkIncidentReportGeneratorAgent

    def test_main_slot_graphnode_contracts(self):
        from src.graph.context_bridge import pop_incident_payload
        from src.graph.graph import _INNER_INPUT_TOKEN, IncidentReportGraphNode

        node = IncidentReportGraphNode()
        assert node.error_strategy == "propagate"
        assert node.propagate_hitl is False
        # extract_input stashes the validated payload on the context bridge and
        # hands the inner graph a neutral token (the masked string channel must
        # never carry the record).
        assert node.extract_input({"validated_input": "V", "user_input": "U"}) == _INNER_INPUT_TOKEN
        assert pop_incident_payload() == "V"
        # pop-on-read: a second pop yields nothing (no stale payload).
        assert pop_incident_payload() is None
        # Without validated_input the bridge carries None (upstream error path).
        assert node.extract_input({"user_input": "U"}) == _INNER_INPUT_TOKEN
        assert pop_incident_payload() is None

    def test_merge_output_maps_subresult_keys(self):
        from src.graph.graph import IncidentReportGraphNode

        node = IncidentReportGraphNode()
        sub_result = {
            "incident_report": "REPORT",
            "report_sections": "{}",
            "compliance_flags": "{}",
            "mic_required": True,
            "status": AgentStatus.SUCCESS.value,
            "node_history": ["x"],  # not forwarded by merge_output
        }
        delta = node.merge_output({}, sub_result)
        assert delta["incident_report"] == "REPORT"
        assert delta["mic_required"] is True
        assert delta["status"] == AgentStatus.SUCCESS.value
        assert set(delta.keys()) == {
            "incident_report",
            "report_sections",
            "compliance_flags",
            "mic_required",
            "status",
            # The boundary now also carries the degraded-completion marker; on a
            # run that produced a report neither side set one, so it crosses empty.
            "error_code",
        }
        assert delta["error_code"] == ""


class TestInnerDomainGraph:
    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        for mod in (
            "input_validate_node",
            "parse_incident_data_node",
            "generate_report_sections_node",
            "compliance_check_node",
            "output_format_node",
        ):
            monkeypatch.setattr(f"src.nodes.{mod}.emit_trace_event", lambda *a, **k: None)

    def test_registers_five_domain_nodes(self):
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        g = DomainWorkflowGraph()
        g.register_nodes()
        assert set(g._nodes.keys()) == {
            "input_validate",
            "parse_incident_data",
            "generate_report_sections",
            "compliance_check",
            "output_format",
        }

    def test_name_and_state_schema(self):
        from src.schemas.state import State
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        g = DomainWorkflowGraph()
        assert g.name == "tel_c2_007_network_incident_report_workflow"
        assert g.state_schema is State

    def test_inner_graph_invoke_produces_report_via_bridge(self):
        """Standalone inner-graph invoke seeded through the context bridge (the
        canonical path): _extra_initial_state() pops the stashed record into
        incident_payload and the pipeline computes from it."""
        from framework.schemas.invocation_context import InvocationContext, TrustLevel
        from src.graph.context_bridge import stash_incident_payload
        from src.graph.domain_workflow_graph import DomainWorkflowGraph
        from src.graph.graph import _INNER_INPUT_TOKEN

        g = DomainWorkflowGraph()
        g.compile()
        ctx = InvocationContext(caller_trust_level=TrustLevel.ANONYMOUS)
        stash_incident_payload(VALID_PAYLOAD)
        result = g.invoke(_INNER_INPUT_TOKEN, ctx=ctx)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["incident_report"] is not None
        assert result["mic_required"] is True
        assert "NETWORK INCIDENT REPORT" in result["incident_report"]

    def test_inner_graph_invoke_falls_back_to_user_input(self):
        """Direct-drive fallback: with nothing on the bridge, the payload may
        ride user_input (this string channel is masked by the framework, so
        the canonical path is the bridge — see context_bridge.py)."""
        from framework.schemas.invocation_context import InvocationContext, TrustLevel
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        g = DomainWorkflowGraph()
        g.compile()
        ctx = InvocationContext(caller_trust_level=TrustLevel.ANONYMOUS)
        result = g.invoke(VALID_PAYLOAD, ctx=ctx)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["mic_required"] is True


# ── Trust gate (PreProcessNode — the only VERIFIED_EXTERNAL node) ──────────────


class TestTrustGate:
    """Trust-gate coverage for the outer pre_process slot.

    PreProcessNode is the only node in this template requiring VERIFIED_EXTERNAL
    trust. These tests invoke it through __call__ (the real BaseNode entry
    point) so the trust gate actually runs — a direct execute() call bypasses
    it. On denial the framework RETURNS an error dict; it never raises.
    """

    @pytest.fixture(autouse=True)
    def patch_emit(self, monkeypatch):
        monkeypatch.setattr("src.nodes.pre_process_node.emit_trace_event", lambda *a, **k: None)

    def setup_method(self):
        from src.nodes.pre_process_node import PreProcessNode

        self.node = PreProcessNode()

    def test_trust_gate_rejects_untrusted_caller_before_execute(self):
        # ANONYMOUS < required VERIFIED_EXTERNAL: the trust gate in __call__ denies
        # BEFORE execute() runs and RETURNS an error dict (no exception raised).
        result = self.node(
            {
                "user_input": VALID_PAYLOAD,
                "input_context": {},
                "caller_trust_level": TrustLevel.ANONYMOUS.value,
            }
        )
        assert result["status"] == AgentStatus.ERROR.value
        assert "trust gate denied" in " ".join(result["error_log"])
        # execute() never ran, so its output key is absent.
        assert "validated_input" not in result

    def test_trust_gate_admits_trusted_caller(self):
        # VERIFIED_EXTERNAL caller clears the gate; execute() runs and succeeds.
        # VALID_PAYLOAD is PII-free, so input masking rewrites no asserted field.
        result = self.node(
            {
                "user_input": VALID_PAYLOAD,
                "input_context": {},
                "caller_trust_level": TrustLevel.VERIFIED_EXTERNAL.value,
            }
        )
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["validated_input"] is not None
