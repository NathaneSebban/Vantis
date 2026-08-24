"""
Base class every scanning module must implement.

Design goal: adding a new capability to Vantis should mean writing
one small class, never touching the engine.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from vantis.core.report import Finding
from vantis.core.target import Target


@dataclass
class ModuleContext:
    """Everything a module needs to run, injected by the engine."""

    target: Target
    http_timeout: float = 10.0
    rate_limit_delay: float = 0.3          # seconds between requests, be a good citizen
    extra_hosts: list[str] | None = None    # e.g. subdomains found by recon, for later modules
    verbose: bool = False


class ScanModule(ABC):
    """Contract for a scanning module.

    category: "recon" | "web" | "cve"  (used for CLI --modules filtering)
    """

    name: str = "unnamed-module"
    category: str = "generic"
    description: str = ""

    def __init__(self, ctx: ModuleContext):
        self.ctx = ctx

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute the module and return a list of Finding objects.

        Must never raise on expected network errors (timeouts, DNS
        failures, connection refused) — catch those and either skip
        silently or emit an 'info' finding. Let the engine handle
        genuinely unexpected exceptions so they surface in logs.
        """
        raise NotImplementedError

    def log(self, message: str) -> None:
        if self.ctx.verbose:
            print(f"[{self.name}] {message}")
