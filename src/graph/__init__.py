"""AgentCore Platform v1.0"""

# AgentRegistry entry-point export. config/agent.yaml declares the dotted
# entry point `src.graph.graph.NetworkIncidentReportGeneratorAgent`; this
# package re-export keeps `import src.graph` resolvable to the class as well
# (and exposes the `Graph` alias server.py imports).
from .graph import Graph, NetworkIncidentReportGeneratorAgent

__all__ = ["NetworkIncidentReportGeneratorAgent", "Graph"]
