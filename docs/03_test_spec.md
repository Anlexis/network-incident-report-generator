# Test Specification — TEL-C2-007 Network Incident Report Generator

## 1. Test Strategy

- **Agent:** TEL-C2-007 — Network Incident Report Generator (Cat 2, document-
  generation pattern, two-layer nested graph: outer `AgentBaseGraph` backbone +
  inner `DomainWorkflowGraph` `BaseGraph`).
- **Coverage target:** ≥ 90% of `src/nodes/` + `src/graph/` + `src/services/` branches.
- **Test types:** Unit (per node, field contract, runtime config, graph wiring)
  · Proof-of-Boundary (framework security/serialization contracts) · End-to-end
  (full HTTP `POST /invoke` through the real ASGI adapter).
- **Framework provisioning:** `framework` (agenticstar-agentcore) is installed
  from the package registry. Tests import the real modules; there are no stub
  nodes.
- **Audit events:** `emit_trace_event` is patched at the node module level in
  unit tests to avoid audit-backend calls, never via a `sys.modules` stub (which
  would break the real `shared` package the framework loads at import time).

### Test file map

| File | Scope |
|------|-------|
| `tests/unit/test_nodes.py` | All domain/backbone nodes + outer & inner graph wiring + output boundary layers |
| `tests/unit/test_caller_contract.py` | The full caller-data contract: strict numeric typing (non-finite matrix per field), identifier/vocabulary locks, structural caps, PII screen (refusal + name-heuristic exclusion), injection screen (both directions), channel selection, and the two stop paths asserted on BOTH validating nodes — a refusal terminates with no reason code, a correctable value completes carrying `INVALID_REQUEST` |
| `tests/unit/test_runtime_config.py` | config/config.yaml liveness: loader, declared values reaching the inner graph, ConfigError on malformed declarations |
| `tests/unit/test_main_node.py` | `MainNode` Cat 1 reference node — pins the `execute(self, state) -> dict` contract |
| `tests/proof_of_boundary/test_pb_invoke_order.py` | PB-6 per-node + backbone invoke order (VERIFIED_EXTERNAL) + trust gate + payload alignment |
| `tests/proof_of_boundary/test_pb_e2e_invoke.py` | PB-8 end-to-end through the real ASGI `/invoke` (bearer auth): real outputs from caller data, Title Case survival, rejection paths, auth boundary, adapter caps |
| `tests/proof_of_boundary/test_import_isolation.py` | PB-4 platform-internal import isolation (AST scan) |
| `tests/proof_of_boundary/test_state_safety.py` | PB-2/PB-5 State msgpack/credential safety (AST scan) |
| `tests/proof_of_boundary/test_pb7_hitl_interrupt_propagation.py` | PB-7 HITL interrupt-propagation (skip stub — no cross-boundary HITL) |

### Canonical valid payload (PB-6 `_VALID_PAYLOAD`)

The MIC Art. 58(2)-reportable incident used by the backbone invoke test and by
`deploy/invoke_payload.json` (the two MUST stay identical — asserted by
`test_invoke_payload_matches_pb6`):

```json
{
  "incident_id": "TEL-INC-20260712-001",
  "severity": "high",
  "affected_services": ["5G", "VoLTE", "SMS"],
  "timeline": {
    "detected_at": "2026-07-12T02:14:00+09:00",
    "resolved_at": "2026-07-12T05:36:00+09:00",
    "duration_minutes": 202
  },
  "root_cause": "Core router BGP session flap in the Tokyo metro ring ...",
  "customer_impact": {
    "affected_subscribers": 48200,
    "impact_description": "Voice call setup failures across the Kanto region."
  },
  "remediation_actions": ["Failed over to standby.", "Cleared BGP sessions.", "Opened vendor RCA."],
  "mic_notification_status": "pending"
}
```

Reportability (MIC Art. 58(2), voice category): affected_subscribers (48,200) ≥
**30,000 AND** duration (202 min) ≥ **120 min** — the `(30,000 users, 2h)`
threshold pair is fully met ⇒ `mic_required = True`. (Both the count and the
duration must be met; see `src/services/mic_policy.py` for the corrected
paired rule and its correction history.)

## 2. Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Where |
|-------|------|----------------|-------|
| TC-01 | State contract: flat `TypedDict`, domain fields `NotRequired`, no Pydantic/dataclass | AST scan: 0 violations | `test_state_safety.py` |
| TC-02 | Invalid/empty/non-JSON input stopped at PreProcessNode | run completes carrying the reason: `status=success` + `error_code`, `error_log` populated, nothing validated carried forward | `TestPreProcessNode` |
| TC-03 | No JWT/credential in State | credential scan: 0 violations | CI + `test_state_safety.py` |
| TC-04 | `execute(self, state)` contract — no `_invoke_impl` | Signature `(self, state)`, `_invoke_impl` absent | `test_execute_signature_is_state_first`, `test_main_node.py` |
| TC-05 | Audit: `emit_trace_event()` called inside each node `execute()` | ≥1 domain event per node (positional form) | asserted structurally by the audit patches in every node test |
| TC-06/07 | Default input/output gates are final — subclass override raises | TypeError at class definition | `test_framework_compliance_tc06_tc07.py` |
| TC-08 | Trust: `required_trust_level` enforced in `__call__` before `execute()` | ANONYMOUS caller → refused; VERIFIED_EXTERNAL → admitted | `TestTrustGate` |
| TC-08a | Outer `PreProcessNode` = VERIFIED_EXTERNAL; inner nodes + post_process = ANONYMOUS | trust levels asserted per node | `test_trust_level_*` |
| TC-11 | Output boundary on post_process | credential pattern → redacted + `status=error`; contact PII → masked + audit; clean → pass | `TestPostProcessNode` |

## 3. Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Where |
|-------|----------|------|----------------|-------|
| PB-2 | State serialization | AST scan of `src/schemas/state.py` | primitives only; no Pydantic/dataclass | `test_state_safety.py` |
| PB-4 | Import isolation | AST scan of `src/` | 0 platform-internal imports | `test_import_isolation.py` |
| PB-5 | Checkpoint safety | no credential-named fields / prohibited types in State | inspection pass | `test_state_safety.py` |
| PB-6 | Invoke execution order (per node) | `__call__`: node_start → trust gate → input gate → `execute()` → output gate → node_complete | order verified for every `src/nodes/` class | `TestInvokeOrder` |
| PB-6b | Backbone invoke order | full `Graph(config=load_runtime_config()).invoke(_VALID_PAYLOAD, ctx=VERIFIED_EXTERNAL)` | `status=success`; node_history = `[Initialize, PreProcess, IncidentReportGraphNode, PostProcess, Finalize]` | `TestBackboneInvokeOrder` |
| PB-6c | Real external caller | `InvocationContext(caller_trust_level=VERIFIED_EXTERNAL)` — **never** `for_internal()` | inner ANONYMOUS nodes accept the passthrough trust; SUCCESS end-to-end | `TestBackboneInvokeOrder` |
| PB-6d | Payload alignment | `deploy/invoke_payload.json["input"] == _VALID_PAYLOAD` | the deployment smoke invoke exercises the PB-6 payload | `test_invoke_payload_matches_pb6` |
| PB-7 | HITL interrupt propagation | skip stub — `propagate_hitl=False`, no cross-boundary interrupt() checkpoint | skipped with reason (real assertion when HITL wired) | `test_pb7_hitl_interrupt_propagation.py` |
| PB-8 | End-to-end HTTP boundary | real ASGI `POST /invoke`, bearer auth | real report from caller data; Title Case service names intact; exact figures; both stop paths over the wire (a correctable value returns success with the reason sentence as the body and no report; narrative PII returns error with no body); auth/cap paths | `test_pb_e2e_invoke.py` |

## 4. Business Logic Tests

| BL-ID | Test | Input | Expected Result | Where |
|-------|------|-------|----------------|-------|
| BL-01 | Happy-path report generation | `_VALID_PAYLOAD` / structured record | 7-section MIC report; `NETWORK INCIDENT REPORT` + incident_id present | `TestBackboneInvokeOrder`, `TestInnerDomainGraph`, `TestRealOutputFromCallerData` |
| BL-02 | Service-name normalisation | `["5g","volte","4g","5G NR"]` | `["5G NR","VoLTE","LTE"]` (canonicalised + deduped) | `test_service_aliases_are_normalised` |
| BL-03 | Severity classification | subscriber/duration matrix | critical / high / medium / low per thresholds | `TestParseIncidentDataNode`, `test_critical_severity_path_surfaces` |
| BL-04 | MIC Art. 58(2) reportability — voice `(30k, 2h)` pair | subscribers = 30,000, duration = 120 | `mic_required=True`; met pair `(30000,120)` | `test_reportable_voice_30k_2h_pair` |
| BL-05 | MIC Art. 58(2) reportability — `(100k, 1h)` pair | subscribers = 100,000, duration = 60 | `mic_required=True`; met pair `(100000,60)` | `test_reportable_100k_1h_pair` |
| BL-06 | MIC not reportable — corrected paired rule (regression vs old OR rule) | 5,000/30 min AND 100/120 min (both were false-positives under the old rule) + boundary cases (29,999/180; 50,000/119; 100,000/59) | `mic_required=False` | `test_not_reportable_old_or_rule_*`, `test_boundary_*`, `test_not_reportable_under_all_thresholds` |
| BL-06a | MIC compliance flags — policy + thresholds traceability | `_incident_data()` | `service_category`, `policy_version`, `regulatory_basis` (Art. 58(2)), `thresholds_applied` present | `test_compliance_flags_carry_policy_and_thresholds` |
| BL-07 | Report section assembly | 7 rendered sections + compliance flags | all 7 headers + `REGULATORY COMPLIANCE NOTE`; MIC YES/NO reflects flag | `TestOutputFormatNode` |
| BL-08 | Root-cause placeholder | `root_cause=None` | "under investigation" placeholder text | `test_root_cause_placeholder_when_missing` |
| BL-09 | Graph key coupling | inner `get_output` ↔ outer `merge_output` | 5 coupled keys mapped; `merge_output` returns changed keys only | `TestOuterGraphComposition`, `TestInnerDomainGraph` |
| BL-10 | Caller-field contract (full matrix) | non-finite/bool/float/string counts, bad identifiers, oversize structures, PII, injection | correctable values → `status=success` + `error_code=INVALID_REQUEST`; PII / injection → `status=error` with no `error_code`; both name the field and never echo the value | `test_caller_contract.py` |
| BL-11 | Context-bridge hand-off | stash → inner `_extra_initial_state` | validated record reaches inner pipeline; pop-on-read (no stale reuse) | `test_main_slot_graphnode_contracts`, `test_inner_graph_invoke_produces_report_via_bridge` |
| BL-12 | Runtime-config liveness | shipped config/config.yaml + garbage variants | declared values reach the inner graph; ConfigError on garbage | `test_runtime_config.py` |

### Negative / boundary cases

| Case | Layer | Expected |
|------|------|----------|
| no record on either channel | PreProcessNode | completes: `status=success` + `error_code`, `error_log` "incident record" |
| invalid JSON on legacy channel | PreProcessNode | completes: `status=success` + `error_code`, `error_log` "not valid JSON" |
| JSON root not an object | PreProcessNode | completes: `status=success` + `error_code`, `error_log` "object" |
| missing `timeline` | PreProcessNode | completes: `status=success` + `error_code`, `error_log` "timeline" |
| malformed `incident_id` (empty / spaces / >64 / non-string) | field contract | completes: `status=success` + `error_code`, `error_log` "incident_id" |
| empty `affected_services` after normalisation | InputValidateNode | completes: `status=success` + `error_code`, `error_log` "affected_services" |
| missing `timeline.detected_at` / non-ISO timestamp | field contract | completes: `status=success` + `error_code`, `error_log` "detected_at" |
| negative / over-magnitude / non-int / non-finite counts | field contract (both nodes) | completes: `status=success` + `error_code`, field named, value not echoed |
| contact/government PII in narrative | field contract (both nodes) | terminates: `status=error`, no `error_code`, finding type named, match not echoed |
| high-confidence injection phrasing in narrative | field contract (both nodes) | terminates: `status=error`, no `error_code`; realistic NOC prose passes |
| Title Case service names ("Wi-Fi Calling") | whole stack | accepted; render intact end-to-end |
| oversized `input_context` / `input` | HTTP adapter | 413 |
| missing / wrong / non-ASCII bearer token | HTTP adapter | 401, generic body |
| missing `incident_data` | Parse / Generate / Compliance | `status=error` |
| missing `report_sections` | OutputFormatNode | `status=error` |
| a reason settled upstream (through the full stack) | main slot → PostProcessNode | the reason's sentence is the whole body; `status=success`, no report — asserted end to end in `TestValidationRejection` |
| empty `incident_report` | PostProcessNode | fallback message, `status=success` |
| credential leak in output | PostProcessNode | whole report replaced, `status=error` |
| contact PII in output | PostProcessNode | masked in place + audit, `status=success` |

## 5. Test Execution Summary

- Execution: `pytest tests/` with the published framework wheel installed.
- Total: **215 tests — 214 passed, 1 skipped** (PB-7 skip stub, by design).
- Coverage: node, graph, contract and adapter modules exercised on both
  success and stop paths; every refusal family is probed in both directions
  (attack forms refused, realistic operational input accepted), and the two
  stop paths are asserted separately so neither can quietly become the other.
