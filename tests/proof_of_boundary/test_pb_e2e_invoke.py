# PB-8: End-to-end boundary proof through the real ASGI adapter.
#
# Everything here drives the REAL stack: FastAPI app in src/api/server.py →
# bearer-token auth → compiled outer graph (constructed with the shipped
# config/config.yaml) → context bridge → inner domain pipeline → output
# boundary. No node is called in isolation and nothing is stubbed.
#
# Proven here:
#   - the structured input_context channel produces a REAL report with the
#     caller's own numbers (non-zero path; MIC-reportable and non-reportable
#     outcomes; severity surfaced)
#   - Title Case service names survive end-to-end (the reason the record
#     rides input_context + the context bridge instead of the masked string
#     channels)
#   - identifier/number fidelity: the incident id and the exact subscriber
#     count render byte-identically — nothing rewrites report figures
#   - validation rejection through the full stack, including non-finite
#     numerics driven over the wire as raw JSON
#   - auth boundary: missing/wrong bearer token → 401, generic body
#   - adapter size caps → 413
#   - the legacy user_input JSON channel still works (deployment payload
#     contract)

import json

import pytest

pytest.importorskip("fastapi")
import warnings  # noqa: E402

with warnings.catch_warnings():
    # The test-runner venv pairs starlette with an httpx it deprecates
    # (StarletteDeprecationWarning subclasses UserWarning); the warning is
    # environment-side, not a property of this repository. Scoped to this
    # one import only.
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", message=".*httpx.*", category=UserWarning)
    from fastapi.testclient import TestClient  # noqa: E402

from src.services.failure_message import INVALID_VALUE  # noqa: E402

_TOKEN = "pb-e2e-test-token-0001"


@pytest.fixture(scope="module")
def client():
    import os

    os.environ["INVOKE_AUTH_TOKEN"] = _TOKEN
    from src.api import server

    with TestClient(server.app) as tc:
        yield tc
    os.environ.pop("INVOKE_AUTH_TOKEN", None)


def _auth() -> dict:
    return {"Authorization": f"Bearer {_TOKEN}"}


def _record(**overrides) -> dict:
    record = {
        "incident_id": "TEL-INC-20260805-042",
        "severity": "high",
        "affected_services": ["Wi-Fi Calling", "volte"],
        "timeline": {
            "detected_at": "2026-08-05T21:40:00+09:00",
            "resolved_at": "2026-08-06T01:55:00+09:00",
            "duration_minutes": 255,
        },
        "root_cause": "IMS core overload after a failed capacity augmentation.",
        "customer_impact": {
            "affected_subscribers": 52000,
            "impact_description": "Voice registration failures in the western region.",
        },
        "remediation_actions": [
            "Rolled back the capacity change.",
            "Rebalanced registrations across the IMS pool.",
        ],
        "mic_notification_status": "pending",
    }
    record.update(overrides)
    return record


def _invoke(client, record=None, *, input_text="Generate the incident report.", headers=None, **body_extra):
    body = {"input": input_text, "session_id": "pb-e2e", **body_extra}
    if record is not None:
        body["input_context"] = {"channel": "e2e", "incident": record}
    return client.post("/invoke", json=body, headers=headers if headers is not None else _auth())


# ── Real output from caller data ──────────────────────────────────────────────


class TestRealOutputFromCallerData:
    def test_reportable_incident_produces_full_report(self, client):
        resp = _invoke(client, _record())
        assert resp.status_code == 200
        result = resp.json()
        assert result["status"] == "success", result
        report = result["output"]
        assert "NETWORK INCIDENT REPORT" in report
        # The caller's own numbers — not a stub baseline.
        assert "TEL-INC-20260805-042" in report
        assert "52,000" in report
        assert "255 minutes" in report
        # 52,000 users AND 255 min meets the (30,000 users, 120 min) voice pair.
        assert "MIC Notification Required: YES" in report
        assert "MIC Reportable: YES" in report

    def test_title_case_service_names_survive_end_to_end(self, client):
        resp = _invoke(client, _record())
        report = resp.json()["output"]
        # The proof the bridge exists: consecutive Title Case words are what
        # the framework's name-masking heuristic rewrites on the string
        # channels. The canonical service name must render intact.
        assert "Wi-Fi Calling" in report
        assert "[MASKED]" not in report

    def test_non_reportable_incident_says_no(self, client):
        small = _record(
            incident_id="TEL-INC-20260805-043",
            timeline={"detected_at": "2026-08-05T21:40:00+09:00", "duration_minutes": 45},
            customer_impact={"affected_subscribers": 900, "impact_description": "Localized degradation."},
        )
        resp = _invoke(client, small)
        result = resp.json()
        assert result["status"] == "success"
        assert "MIC Notification Required: NO" in result["output"]
        assert "MIC Reportable: NO" in result["output"]

    def test_critical_severity_path_surfaces(self, client):
        big = _record(
            incident_id="TEL-INC-20260805-044",
            customer_impact={"affected_subscribers": 150000, "impact_description": "Nationwide impact."},
        )
        resp = _invoke(client, big)
        result = resp.json()
        assert result["status"] == "success"
        assert "Severity:    CRITICAL" in result["output"]

    def test_legacy_user_input_channel_still_works(self, client):
        record = _record(incident_id="TEL-INC-20260805-045", affected_services=["5g", "sms"])
        resp = _invoke(client, None, input_text=json.dumps(record))
        result = resp.json()
        assert result["status"] == "success"
        assert "TEL-INC-20260805-045" in result["output"]


# ── Validation rejection through the full stack ───────────────────────────────


class TestValidationRejection:
    def test_missing_required_fields_rejects(self, client):
        resp = _invoke(client, {"incident_id": "X-1"})
        result = resp.json()
        assert result["status"] == "success"
        # Over the HTTP envelope the reason arrives as the response BODY, not
        # as a field — the caller reads it and can correct the record on the
        # same conversation. What must NOT be there is a report.
        assert result["output"] == INVALID_VALUE
        assert "NETWORK INCIDENT REPORT" not in result["output"]

    @pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_numerics_over_the_wire_reject(self, client, literal):
        # Raw JSON body with a bare non-finite literal — exactly what a
        # malicious or broken caller can put on the wire. Whether the JSON
        # layer or the field contract catches it, the invocation must FAIL
        # CLOSED: never a success verdict computed from a non-finite count.
        record = json.dumps(_record()).replace("52000", literal)
        body = (
            '{"input": "Generate.", "session_id": "pb-e2e-nonfinite", ' '"input_context": {"incident": ' + record + "}}"
        )
        resp = client.post("/invoke", content=body, headers={**_auth(), "Content-Type": "application/json"})
        if resp.status_code == 200:
            result = resp.json()
            assert result["status"] == "success"
            # The body is the reason, not a verdict: the run completed WITHOUT
            # computing anything from the non-finite count.
            assert result["output"] == INVALID_VALUE
            joined = " ".join(result.get("error_log") or []) + str(result.get("output"))
            assert "MIC Notification Required" not in joined
        else:
            assert resp.status_code == 422

    def test_string_nan_in_count_rejects_with_field_name(self, client):
        record = _record()
        record["customer_impact"]["affected_subscribers"] = "NaN"
        resp = _invoke(client, record)
        result = resp.json()
        assert result["status"] == "success"
        # The body is the reason; no report was assembled from a string count.
        assert result["output"] == INVALID_VALUE
        assert "NETWORK INCIDENT REPORT" not in result["output"]

    def test_contact_pii_in_narrative_rejects(self, client):
        record = _record()
        record["customer_impact"]["impact_description"] = "Subscriber taro.yamada@example.com reported failures."
        resp = _invoke(client, record)
        result = resp.json()
        assert result["status"] == "error"
        # The address itself is never echoed back.
        assert "example.com" not in json.dumps(result)


# ── Auth boundary ─────────────────────────────────────────────────────────────


class TestAuthBoundary:
    def test_missing_token_is_401_generic(self, client):
        resp = _invoke(client, _record(), headers={})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Token is invalid or expired."

    def test_wrong_token_is_401(self, client):
        resp = _invoke(client, _record(), headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

    def test_non_ascii_token_is_401_not_500(self, client):
        # HTTP header bytes decode as latin-1 on the server; a non-ASCII token
        # must produce the generic 401, never a 500. Sent as bytes because the
        # client library refuses to encode non-ASCII header strings itself.
        resp = _invoke(
            client,
            _record(),
            headers={"Authorization": "Bearer tökén".encode("latin-1")},
        )
        assert resp.status_code == 401


# ── Adapter caps ──────────────────────────────────────────────────────────────


class TestAdapterCaps:
    def test_oversized_input_context_is_413(self, client):
        record = _record()
        record["root_cause"] = "x" * (300 * 1024)
        resp = _invoke(client, record)
        assert resp.status_code == 413
        assert "input_context" in resp.json()["detail"]

    def test_oversized_input_is_413(self, client):
        resp = _invoke(client, None, input_text="y" * (300 * 1024))
        assert resp.status_code == 413


# ── Health ────────────────────────────────────────────────────────────────────


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
