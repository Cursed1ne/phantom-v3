"""PHANTOM AI v3 — Agent package."""
from .base     import BaseAgent
from .planner  import PlannerAgent
from .recon    import ReconAgent
from .web      import WebAgent
from .identity import IdentityAgent
from .network  import NetworkAgent
from .cloud    import CloudAgent
from .exploit  import ExploitAgent

AGENT_REGISTRY = {
    "planner":  PlannerAgent,
    "recon":    ReconAgent,
    "web":      WebAgent,
    "identity": IdentityAgent,
    "network":  NetworkAgent,
    "cloud":    CloudAgent,
    "exploit":  ExploitAgent,
}

__all__ = [
    "BaseAgent", "PlannerAgent", "ReconAgent", "WebAgent",
    "IdentityAgent", "NetworkAgent", "CloudAgent", "ExploitAgent",
    "AGENT_REGISTRY",
]
