# Template Design Specification — TEL-C2-007 Network Incident Report Generator

## Position in AgentCore Architecture

| Item | Value |
|------|-------|
| Agent Class | NetworkIncidentReportGeneratorAgent |
| L1 Base (framework base class) | AgentBaseGraph — direct framework inheritance |
| Pattern | Cat 2 — document-generation pipeline (two-layer nested workflow) |
- **Three-Layer Separation**:
  - State: flat TypedDict composition (no Pydantic — msgpack incompatible); JSON-serialised strings for all dict/list fields
  - Node: framework inheritance (Template Method: `execute(self, state: dict) -> dict` override only)
  - Graph: composition (`register_nodes()` for node substitution; Cat 2 nested via `GraphNode`)

## Domain Context

NOC incident report generator for Japanese telecommunications operators. Generates structured, MIC-compliant network incident reports from the incident record submitted by NOC engineers.

**Regulatory basis**: 電気通信事業法施行規則 第58条第2項 (Telecommunications Business Act Enforcement Regulations Art. 58(2)) — the statutory basis for the MIC (総務省) 重大な事故 / "Report of Significant Accidents" duty. The reporting threshold is **service-category specific** and requires **BOTH** an affected-user count **AND** an outage duration (not either/or). For typical voice / internet-access categories: **30,000 affected users for ≥ 2 hours, OR 100,000 for ≥ 1 hour**. When any threshold pair is fully met the operator must notify MIC within 24 hours. See "MIC Art. 58(2) threshold policy" below.

> **Correction history:** an earlier revision used a universal `affected_subscribers ≥ 3,000 OR duration ≥ 120 min` rule, which was materially incorrect (it produced false "notification required" verdicts). The corrected service-category paired rule is encoded in a single versioned source of truth, `src/services/mic_policy.py`.

## Architecture Overview

### Backbone (outer AgentBaseGraph — fixed 5-node pipeline)

```
START → initialize → pre_process → main(GraphNode) → post_process → finalize → END
                                         ↓ (retry, max 3)
                                       pre_process
```

### Inner Domain Workflow (DomainWorkflowGraph — linear 5-node pipeline)

```
START → input_validate → parse_incident_data → generate_report_sections
          → compliance_check → output_format → END
```

### Node Configuration

| Node | Class | File | Trust | Responsibility | Input Keys | Output Keys |
|------|-------|------|-------|---------------|------------|-------------|
| initialize | InitializeNode | framework | — | session init | — | session_id, schema_version |
| pre_process | PreProcessNode | src/nodes/pre_process_node.py | VERIFIED_EXTERNAL | trust gate + caller-data contract | input_context, user_input | validated_input, enriched_context |
| main | IncidentReportGraphNode | src/graph/graph.py | — | delegates to DomainWorkflowGraph via the context bridge | validated_input | incident_report, report_sections, compliance_flags, mic_required |
| post_process | PostProcessNode | src/nodes/post_process_node.py | ANONYMOUS | output boundary + set formatted_output | incident_report | formatted_output, result |
| finalize | FinalizeNode | framework | — | response metadata | — | response_metadata, total_time_ms |
| input_validate (inner) | InputValidateNode | src/nodes/input_validate_node.py | ANONYMOUS | contract re-application + service normalisation | incident_payload | incident_data |
| parse_incident_data (inner) | ParseIncidentDataNode | src/nodes/parse_incident_data_node.py | ANONYMOUS | severity classification + service category + MIC Art. 58(2) pre-check | incident_data | incident_data (enriched) |
| generate_report_sections (inner) | GenerateReportSectionsNode | src/nodes/generate_report_sections_node.py | ANONYMOUS | generate 7 MIC report sections (deterministic v1 — see LLM note) | incident_data | report_sections |
| compliance_check (inner) | ComplianceCheckNode | src/nodes/compliance_check_node.py | ANONYMOUS | MIC Art. 58(2) reportability determination (via src/services/mic_policy.py) | incident_data | compliance_flags, mic_required |
| output_format (inner) | OutputFormatNode | src/nodes/output_format_node.py | ANONYMOUS | assemble final report document | report_sections, compliance_flags | incident_report, result |

### Caller-data contract (input channels)

The incident record enters on one of two channels:

1. **`input_context["incident"]` (canonical, structured).** The HTTP adapter
   accepts `input_context` on `POST /invoke` (size-capped at 256 KB) and the
   framework seeds it into the outer graph's initial state. This channel is
   NOT one of the framework's masked string channels — which matters, because
   the framework's input masking rewrites consecutive Title Case words
   (a personal-name heuristic), and canonical telecom service names
   ("Wi-Fi Calling", "Fixed Line") are exactly that shape. Records carrying
   proper nouns only arrive intact on this channel.
2. **`input` / `user_input` (legacy, JSON string).** Still accepted and fully
   validated, but the string channel is subject to the framework's input
   masking and injection policy at every node boundary; Title Case tokens in
   the record may be rewritten before the template sees them. New callers
   should use the structured channel.

`PreProcessNode` applies the whole field contract
(`src/services/field_validation.py`) to whichever channel supplied the record:

- **Strict numeric typing, fail closed.** Counts (`affected_subscribers`,
  `duration_minutes`) are accepted only as integers within explicit bounds
  (0–200,000,000 subscribers; 0–525,600 minutes). Bools, floats — including
  `NaN` / `Infinity`, which arrive as raw JSON and silently fail every
  comparison — numeric strings, and out-of-range magnitudes are rejected with
  an error that names the field and never echoes the value. These are values
  the caller can correct, so the run stops carrying the reason rather than
  terminating (see "Two stop paths").
- **Inert identifiers.** `incident_id` is locked to `[A-Za-z0-9_-]{1,64}`,
  `mic_notification_status` to a lowercase token vocabulary, `severity` to a
  closed set, timestamps to an ISO-8601 shape, service names to a bounded
  label alphabet with an entry cap.
- **Screened narrative fields.** `impact_description`, `root_cause` and each
  remediation action are length-capped, control-stripped, and screened:
  contact and government/financial identifiers (emails, phone numbers,
  SSN / My Number / card patterns) REFUSE the request — it terminates;
  high-confidence prompt-injection phrasing REFUSES the request the same way;
  person-name findings are
  MASKED in place rather than refused — the name heuristic intentionally does
  not refuse, because it matches legitimate Title Case telecom labels
  (documented exclusion), and refusal would block real incident records.
- **Whitelist projection.** Unknown keys are dropped; only contract fields
  reach the pipeline.

`InputValidateNode` re-applies the same contract inside the inner graph
(defense in depth: the inner pipeline holds its own guarantee when driven
directly), then normalises service names to the canonical vocabulary. It
reports each outcome exactly as `PreProcessNode` does — otherwise driving the
pipeline directly would terminate on a value the outer boundary lets the caller
correct, or soften a refusal the outer boundary terminates on.

### Two stop paths

Nothing validated is carried forward on either path — no report is produced.
The paths differ only in how the stop is REPORTED back.

| Path | What takes it | How the run ends | What the caller reads |
|---|---|---|---|
| completes carrying a reason | a value the caller can correct: no record on either channel, a payload that is not valid JSON or not an object, a missing required field, a wrong-typed / out-of-range / non-finite count, a malformed identifier or timestamp, a severity or status outside its vocabulary, an `affected_services` list that normalises to empty | `status = success`, a reason code held in State | the sentence for that reason, as the whole body |
| terminates | content this agent refuses: a contact or government/financial identifier in a narrative field, high-confidence instruction-override phrasing | `status = error`, nothing carried forward | no body |

A correctable value completes rather than terminating because terminating ends
the calling surface's turn and surfaces only a status, leaving the reason
reachable solely from the audit trail; completing with a sentence lets the
caller fix the value and resubmit on the same conversation. Refused content has
no corrected form to send, and reporting it the same way would read as an
invitation to reword the request until it gets through.

The split is carried by the exception TYPE, never by the wording of a message:
the field contract raises `ContentRefusedError` for refused content and
`FieldContractError` for everything else, and both validating nodes catch the
subclass FIRST. A rewording of any message therefore cannot reclassify a
refusal — and because `ContentRefusedError` subclasses `FieldContractError`,
callers that do not need the split still have one exception surface.

| Reason code | The sentence names |
|---|---|
| `EMPTY_INPUT` | that nothing was received to work on |
| `INVALID_REQUEST` | that a value could not be accepted and should be checked against the documented format |

The code itself never leaves the process. It is a State marker: `PostProcessNode`
reads it to pick the sentence, and the caller envelope carries the sentence as
the body and no reason code — so neither a field path nor an internal log
reaches the caller. A code with no entry in that table falls back to the generic
sentence rather than leaking the code.

Once a reason is settled, `IncidentReportGraphNode.execute()` does not run the
inner graph, and each inner node passes the marker through untouched — so a
second, vaguer reason can never overwrite the specific one.

### The context bridge (outer → inner)

The framework's `GraphNode` forwards only the extracted input STRING to
`subgraph.invoke()` — the outer `input_context` does not cross the boundary —
and every string travelling as `user_input` / `validated_input` is rewritten
by input masking at each node boundary. The validated record therefore
crosses out-of-band: `IncidentReportGraphNode.extract_input()` stashes it on a
ContextVar (`src/graph/context_bridge.py`) and hands the inner graph a neutral
token; `DomainWorkflowGraph._extra_initial_state()` pops it into the
template-owned state key `incident_payload`. Pop-on-read semantics prevent a
stale payload from leaking into a later invocation, and ContextVar scoping
keeps concurrent invocations isolated.

### Data Flow

```
input_context["incident"] (structured record)      user_input (legacy JSON)
    │                                                  │
    ▼ PreProcessNode (VERIFIED_EXTERNAL — trust gate + field contract)
validated_input (normalised JSON string)
enriched_context (JSON string)
    │
    ▼ IncidentReportGraphNode — stashes record on the context bridge,
    │                            hands the inner graph a neutral token
    │   DomainWorkflowGraph._extra_initial_state ← pops → incident_payload
    │   InputValidateNode          → incident_data (JSON string)
    │   ParseIncidentDataNode      → incident_data (enriched)
    │   GenerateReportSectionsNode → report_sections (JSON string)
    │   ComplianceCheckNode        → compliance_flags (JSON string), mic_required (bool)
    │   OutputFormatNode           → incident_report (str), result (str)
    ▼ merge_output
incident_report, report_sections, compliance_flags, mic_required → outer state
    │
    ▼ PostProcessNode (ANONYMOUS — output boundary; for a run stopped upstream
    │                   on a correctable value, renders that reason's sentence
    │                   as the whole body and publishes no report)
formatted_output (boundary-checked incident_report), result
```

### State Definition

| Field | Type | Purpose | Producer |
|-------|------|---------|----------|
| validated_input | NotRequired[Optional[str]] | Normalised incident JSON string | PreProcessNode |
| enriched_context | NotRequired[Optional[str]] | JSON: {source, channel, incident_id} | PreProcessNode |
| incident_payload | NotRequired[Optional[str]] | Validated record seeded into the INNER graph from the context bridge | DomainWorkflowGraph._extra_initial_state |
| incident_data | NotRequired[Optional[str]] | JSON: parsed+enriched incident payload | InputValidateNode / ParseIncidentDataNode |
| report_sections | NotRequired[Optional[str]] | JSON: {section_name: text, ...} × 7 sections | GenerateReportSectionsNode |
| compliance_flags | NotRequired[Optional[str]] | JSON: MIC Art. 58(2) check result | ComplianceCheckNode |
| mic_required | NotRequired[Optional[bool]] | True if MIC notification required | ComplianceCheckNode |
| incident_report | NotRequired[Optional[str]] | Final formatted incident report text | OutputFormatNode |
| result | NotRequired[Optional[str]] | Same as incident_report (backbone convention) | OutputFormatNode / PostProcessNode |
| error_code | NotRequired[Optional[str]] | Reason marker for a run stopped on a correctable value; read by PostProcessNode to pick the sentence, never published in the caller envelope | PreProcessNode / InputValidateNode |

**Serialization constraint**: all dict/list-valued fields use JSON-serialised `Optional[str]` (msgpack checkpoint safety). `to_json()` / `from_json()` helpers are defined in `src/schemas/state.py` and used at every producer/consumer boundary — one contract end-to-end.

**Prohibited**: re-declaring `formatted_output` (inherited from AgentState), credentials in State, Pydantic models.

### Input Payload Schema (`input_context["incident"]`)

```json
{
  "incident_id": "INC-2026-001234",
  "affected_services": ["LTE", "5G NR", "VoLTE"],
  "timeline": {
    "detected_at": "2026-07-13T10:30:00Z",
    "resolved_at": "2026-07-13T13:45:00Z",
    "duration_minutes": 195
  },
  "root_cause": "Hardware failure in core router at the metropolitan exchange",
  "customer_impact": {
    "affected_subscribers": 45000,
    "impact_description": "Voice and data service degraded in the metropolitan area"
  },
  "remediation_actions": [
    "Failover to backup router",
    "Hardware replacement",
    "Configuration restore"
  ],
  "mic_notification_status": "pending",
  "severity": "high"
}
```

The same object may ride the legacy channel as a JSON string in `input`.

### Output Report Sections (MIC report format)

1. **Incident Summary** — ID, severity, detection/resolution times, duration
2. **Affected Services** — normalised list of impacted services
3. **Timeline of Events** — chronological event log
4. **Root Cause Analysis** — identified/suspected root cause
5. **Customer Impact** — subscriber count, regions, degradation type
6. **Remediation Actions** — steps taken to resolve
7. **MIC Notification Status** — Art. 58(2) reportability verdict, service category + applied threshold pairs

### MIC Art. 58(2) threshold policy

The reporting rule lives in a **single versioned source of truth**,
`src/services/mic_policy.py` (consumed by both `ParseIncidentDataNode` and
`ComplianceCheckNode`), so it is encoded in exactly one place.

- **Rule**: reportable when **any** service-category threshold *pair* is fully
  met — a pair requires **BOTH** the affected-user count **AND** the outage
  duration. Typical voice / internet-access categories: `(30,000 users, 120 min)`
  **OR** `(100,000 users, 60 min)`.
- **Service classification**: derived from `affected_services` (voice/messaging
  services → `voice`; other non-empty lists → `internet`; empty → `other`).
- **Versioning**: `MIC_POLICY_VERSION` is stamped into every `compliance_flags`
  payload for auditability; bump it when the threshold table changes.
- **Traceability**: `compliance_flags` records `service_category`,
  `thresholds_applied`, `met_threshold_pairs`, `policy_version`, and
  `regulatory_basis`.

> ⚠️ **Regulatory scope flag (v1):** the cited thresholds are the *typical*
> voice / internet-access pairs; other service classes differ. Art. 58(2)
> defines further classes (e.g. emergency-call / 緊急通報 voice, and
> leased-line / data-transmission services) with distinct thresholds. Pending
> confirmation of the full per-class table, v1 applies the typical voice /
> internet thresholds to every category. **This is flagged for regulatory
> review before production sign-off.**

## Runtime configuration

`config/agent.yaml` is the flat static manifest (registry identity: id, name,
namespace, class, trust level, compile-time requirements). Every runtime value
lives in **`config/config.yaml`**:

```yaml
max_retry: 3
timeout_s: 30
llm:
  system_prompt_template: "prompts/network_incident.j2"
  temperature: 0.0
  max_tokens: 4000
security:
  s3_gate_enabled: true
```

The file is live end-to-end, by construction:

- the standalone server builds the agent as
  `Graph(config=load_runtime_config())`, so `max_retry` (backbone retry
  routing), `hitl` and `memory_enabled` govern the compiled graph — a bare
  `Graph()` would silently run on hard-coded defaults;
- `IncidentReportGraphNode._parent_config()` loads the same file and forwards
  the declared `llm.*` values (under `configurable`) plus `timeout_s` /
  `max_retry` to the inner graph's constructor;
- `DomainWorkflowGraph._validate_config()` type-checks every declared value at
  compile time and raises `ConfigError` on garbage — a malformed declaration
  fails the invocation instead of silently degrading to defaults;
- `load_runtime_config()` itself fails loudly when the file is missing or
  malformed.

The declared-value chain (file → outer graph → inner graph) is pinned by
`tests/unit/test_runtime_config.py`.

### v1 Implementation Note — LLM synthesis

`GenerateReportSectionsNode` produces the seven report sections via
**deterministic template-based synthesis** in v1. The installed framework
wheel ships no LLM client, so v1 does **not** invoke any model — the `llm.*`
configuration is validated and delivered to the inner graph (see above) as
the wiring seam for a future revision, which will render
`prompts/network_incident.j2` and invoke the platform LLM in place of the
deterministic templates. No fake/stub LLM is wired in v1.

## Security gates

| Concern | Gate | Implementation |
|-------|------|---------------|
| Caller trust | Trust enforcement | PreProcessNode `required_trust_level = VERIFIED_EXTERNAL`; the standalone adapter raises authenticated bearer callers to that level (`INVOKE_AUTH_TOKEN`) |
| Input validation | Caller-data contract | PreProcessNode + field contract (strict types, bounds, inert identifiers, PII / injection screens); re-applied by InputValidateNode. Refused content terminates the run; a value the caller can correct stops it carrying a reason code, and nothing validated is carried forward either way |
| Output boundary | Credential scan + PII redaction | PostProcessNode — module-level `_security_gate_output()` (API keys, JWTs, Bearer tokens, credential assignments → fail closed) then contact-identifier redaction (see below) |
| Audit logging | `emit_trace_event()` | at least one domain-specific event per node `execute()`; every refusal and redaction emits its own event |
| Credential handling | No credentials in State | secrets via the platform secret provider only; `requires.secrets: []` — this agent needs none |

**The template owns its guarantees.** Every screen above runs inside the
template's own `execute()` methods and is tested by calling them directly —
no framework wrapper in front. The framework's own input masking and
credential scan remain as additional layers, not the ones relied upon.

### Output boundary — what invariant, and why not a rounding grid

Some agents in this family publish monetary aggregates and snap them onto a
coarse grid so individual figures cannot be recovered. That is deliberately
**not** done here, and the grid does not apply: this template renders **no
monetary aggregates at all**, and its figures — subscriber counts, outage
durations, statutory thresholds — are the substance of a regulatory filing
whose own rules demand precision ("subscriber counts must be precise; no
rounding unless estimated"). Snapping `48,200 affected subscribers` to
`48,000` would falsify the filing and flip no privacy property: the count is
an operator-supplied operational figure, not an aggregate over private
records. The invariant this boundary enforces instead:

1. **Credential patterns never ship** — scan on the untouched text, whole
   report replaced with a sanitised stub on a hit (fail closed, audit event).
2. **Contact/government identifiers never ship** — email, phone, SSN /
   My Number / card patterns masked in place (audit event). The person-name
   heuristic is excluded at this layer too: it matches Title Case service
   names, and masking those would corrupt the filing. Person names in
   narrative fields were already masked at intake.
3. **Figures and identifiers render byte-exactly** — nothing rewrites report
   numbers; pinned end-to-end (`test_pb_e2e_invoke.py`: exact `52,000` count,
   exact incident id, intact `Wi-Fi Calling`).

Layer 1 runs before layer 2 on purpose: a pattern scan must see the text
before anything rewrites it, or an earlier redaction can split a credential
into pieces the scanner no longer recognises.

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (session_id, trust_level)
- [x] `framework.security.detect_pii` / `mask_pii` — caller-field screens and the output redaction layer
- [x] `framework.security.injection_detector.detect_injection` — narrative-field injection screen (high-confidence refusal)
- [x] `emit_trace_event()` — at least one domain-specific event per node `execute()`
- [x] `to_json()` / `from_json()` helpers in `src/schemas/state.py` — serialisation contract

### Composition Pattern

- **Pattern**: Cat 2 nested two-layer — GraphNode wrapping inner BaseGraph
- **Outer graph**: `NetworkIncidentReportGeneratorAgent(AgentBaseGraph)` — fixed 5-node backbone
- **Inner graph**: `DomainWorkflowGraph(BaseGraph)` — 5-node linear domain pipeline
- **Error propagation**: propagate (SubgraphError on inner failure; outer backbone retries pre_process)

## Import Isolation Confirmation
- [x] Template does not import the platform-internal SDK
- [x] Import targets: `framework/` and `shared/` only

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Base type | AgentBaseGraph | AutonomousBaseGraph | AgentBaseGraph | Fixed sequential pipeline; no LLM reasoning loop required |
| Composition pattern | Cat 1 (flat) | Cat 2 (nested GraphNode) | Cat 2 nested | 5 sequential domain steps; document-generation pattern |
| Caller-data channel | user_input JSON only | structured input_context + legacy fallback | input_context canonical | The masked string channels rewrite Title Case tokens (service names); the structured channel arrives intact |
| Record hand-off to inner graph | inner user_input string | ContextVar bridge + `_extra_initial_state` | bridge | GraphNode forwards no input_context, and the inner string channel is masked at every node boundary |
| Numeric fields | permissive `int()` coercion | strict typed + bounded parser | strict parser | coercion admits bools/floats and `int(inf)` raises OverflowError uncaught; non-finite floats fail every comparison (silent fail-open) |
| Output invariant | monetary rounding grid | credential scan + identifier redaction + exact figures | scan + redaction + exactness | No monetary aggregates rendered; filing precision is statutory — rounding would falsify the report (see "Output boundary") |
| MIC compliance | Inline in generate | Separate ComplianceCheckNode | Separate node | Single-responsibility |
| MIC threshold rule | Inline constants per node | Versioned `mic_policy.py` source of truth | `mic_policy.py` | Art. 58(2) service-category paired rule encoded once; both parse + compliance import it |
| State dict fields | bare dict | JSON-serialised str | JSON-serialised str | msgpack serialisation safety |
| Runtime config | best-effort defaults | loud loader + compile-time validation | loud + validated | silent defaults ran the agent with every declared value ignored; garbage must fail, not degrade |
| LLM integration | Real LLM | Deterministic v1 (config delivered, not invoked) | Deterministic v1 | No LLM client in the installed framework wheel; `llm.*` validated + forwarded for the next revision |
| Service normalisation | InnerValidate | Separate normalise node | In InputValidateNode | Reduces node count; normalisation is still validation scope |
| Reporting a stop | one error status for every stop | complete on a correctable value, terminate on refused content | split by exception type | an error status ends the caller's turn and leaves the reason only in the audit trail; reporting refused content as correctable reads as an invitation to reword until it gets through |
