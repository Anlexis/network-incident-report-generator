# Network Incident Report Generation Agent

AI agent for generating network incident reports, built with Agentic Star.

> **Category**: Cat 2 (domain-specific multi-step pipeline)
> **Industry**: Telecommunications
> **Template ID**: TEL-C2-007

## Overview

Turns a network operations centre's raw incident record — affected services, outage
timeline, subscriber impact, remediation notes — into a structured, filing-ready network
incident report for a Japanese telecommunications operator. The pipeline validates and
normalises the submitted record, classifies severity and service category, evaluates the
reportability duty under the Telecommunications Business Act Enforcement Regulations
Art. 58(2) (the MIC "serious accident" notification rule, with its paired
subscriber-count AND outage-duration thresholds), and renders a seven-section report
with a regulatory compliance note. Report synthesis is deterministic and template-based
in this version; the configuration seam for LLM-backed synthesis is already wired.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform's runtime services (secret provisioning, audit backend) are unavailable or
the SDK version does not match, start-up fails during graph compile / secret provisioning rather
than starting in a partially working state. This is intentional — a half-running agent is worse
than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/` for the design and the test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.

