"""
Scan engine: loads modules, enforces the authorization gate, runs
modules in dependency order (recon -> web/cve), and aggregates results
into a Report.
"""
from __future__ import annotations

import importlib
import pkgutil
import traceback
from pathlib import Path

from vantis.core.plugin_base import ModuleContext, ScanModule
from vantis.core.report import Finding, Report, Severity
from vantis.core.target import Target


class AuthorizationError(RuntimeError):
    """Raised when a scan is attempted without explicit authorization."""


class Engine:
    def __init__(
        self,
        target: Target,
        categories: list[str] | None = None,
        verbose: bool = False,
        http_timeout: float = 10.0,
        rate_limit_delay: float = 0.3,
    ):
        self.target = target
        self.categories = categories or ["recon", "web", "cve"]
        self.verbose = verbose
        self.ctx = ModuleContext(
            target=target,
            http_timeout=http_timeout,
            rate_limit_delay=rate_limit_delay,
            verbose=verbose,
        )
        self.report = Report(target=str(target))
        self._modules: list[type[ScanModule]] = []

    # -- Module discovery ---------------------------------------------

    def discover_modules(self) -> None:
        """Auto-import every module under vantis.modules.* and collect
        ScanModule subclasses. This is what makes the tool 'plugin-based':
        dropping a new file in modules/<category>/ is enough."""
        import vantis.modules as modules_pkg

        for _, name, _ in pkgutil.walk_packages(modules_pkg.__path__, prefix="vantis.modules."):
            try:
                mod = importlib.import_module(name)
            except Exception as e:  # noqa: BLE001 - a broken plugin shouldn't kill the engine
                print(f"[!] Failed to import {name}: {e}")
                continue

            for attr in vars(mod).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, ScanModule)
                    and attr is not ScanModule
                    and attr.category in self.categories
                    and attr not in self._modules
                ):
                    self._modules.append(attr)

    # -- Authorization gate ---------------------------------------------

    @staticmethod
    def confirm_authorization(target: Target, assume_yes: bool = False) -> None:
        """Hard stop unless the user explicitly confirms they are authorized
        to test this target (bug bounty scope, pentest contract, own asset,
        etc). This is deliberately not skippable via a config file — it
        must come from an interactive human or an explicit --yes-i-am-authorized
        flag the user typed themselves."""
        banner = (
            "\n" + "=" * 70 +
            f"\n Vantis is about to actively probe: {target}\n"
            " This is only lawful if you have EXPLICIT authorization\n"
            " (a bug bounty program scope, signed pentest agreement, or\n"
            " ownership of the asset). Unauthorized scanning of systems\n"
            " you don't own or have permission to test is illegal in most\n"
            " jurisdictions.\n" + "=" * 70
        )
        print(banner)

        if assume_yes:
            return

        answer = input(f"Do you confirm you are authorized to test '{target}'? [yes/NO]: ")
        if answer.strip().lower() not in {"yes", "y"}:
            raise AuthorizationError("Scan aborted: authorization not confirmed.")

    # -- Run ---------------------------------------------------

    def run(self) -> Report:
        if not self._modules:
            self.discover_modules()

        # Run in a stable order: recon first (it can populate ctx.extra_hosts
        # for later web/cve modules), then web, then cve.
        order = {"recon": 0, "web": 1, "cve": 2}
        modules = sorted(self._modules, key=lambda m: order.get(m.category, 99))

        for module_cls in modules:
            print(f"[*] Running {module_cls.name} ({module_cls.category})...")
            try:
                instance = module_cls(self.ctx)
                findings = instance.run() or []
                for f in findings:
                    self.report.add(f)
                print(f"    -> {len(findings)} finding(s)")
            except Exception as e:  # noqa: BLE001
                print(f"    -> module crashed: {e}")
                if self.verbose:
                    traceback.print_exc()
                self.report.add(
                    Finding(
                        module=module_cls.name,
                        title="Module execution error",
                        severity=Severity.INFO,
                        target=str(self.target),
                        description=str(e),
                    )
                )

        return self.report
