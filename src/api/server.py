"""AgentCore Platform v1.0"""

# Standalone HTTP entry point for the agent.
# Entry points are adapters only — no business logic here.
# For platform-level routing, AgentGateway calls agent.invoke() directly.

import json
import os
import secrets
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory
from src.graph.graph import Graph, load_runtime_config

app = FastAPI(title="Agent")

# The declared runtime values (max_retry, hitl, memory) only govern the
# backbone when the graph is constructed WITH them — a bare Graph() silently
# runs on hard-coded defaults with config/config.yaml ignored.
agent = Graph(config=load_runtime_config())
agent.compile()
# namespace/agent_name match the manifest (config/agent.yaml: namespace / class).
agent.provision_secrets(secrets_factory(namespace="tel", agent_name="NetworkIncidentReportGeneratorAgent"))

# Adapter-level size cap for the caller-data channel. input_context carries the
# structured incident record; a serialized payload larger than this is rejected
# before it reaches the graph.
_INPUT_CONTEXT_MAX_BYTES = 256 * 1024
_INPUT_MAX_BYTES = 256 * 1024


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""
    # Structured caller data. The incident record rides here as
    # input_context["incident"] (see docs/02_design.md — caller-data contract):
    # unlike the free-text `input` field, this channel is not rewritten by the
    # framework's input masking, so proper-noun service names ("Wi-Fi Calling")
    # and other Title Case tokens reach the pipeline intact.
    input_context: dict[str, Any] = {}


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> dict[str, Any]:
    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Standalone caller auth: when INVOKE_AUTH_TOKEN is set on the server
    # environment, callers that no upstream middleware vouched for (still
    # ANONYMOUS) must present it as a Bearer token and run at VERIFIED_EXTERNAL.
    # Middleware-established trust is never demoted. This adapter is the
    # entry-point auth boundary (standalone equivalent of platform
    # AuthMiddleware) — a deployment-level caller credential, not an agent
    # secret, so ctx.secrets does not apply (no InvocationContext exists
    # before auth).
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        trust = TrustLevel.VERIFIED_EXTERNAL

    # Size caps run before any processing; the error names the field, never the value.
    if len(req.input.encode("utf-8", errors="replace")) > _INPUT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="input exceeds the size limit.")
    try:
        context_bytes = len(json.dumps(req.input_context, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="input_context is not JSON-serializable.")
    if context_bytes > _INPUT_CONTEXT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="input_context exceeds the size limit.")

    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        result: dict[str, Any] = agent.invoke(req.input, ctx=ctx, input_context=req.input_context)
        return result


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "NetworkIncidentReportGeneratorAgent"}
