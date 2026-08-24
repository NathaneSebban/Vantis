"""
Scan engine: loads modules, enforces the authorization gate, runs
modules in dependency order (recon -> web/cve), and aggregates results
into a Report.
"""
from __future__ import annotations

import importlib
import pkgutil
import traceback
from typing import Any, Callable, Optional
from pathlib import Path

from vantis.core.plugin_base import ModuleContext, ScanModule
from vantis.core.report import Finding, Report, Severity
from vantis.core.target import Target


class AuthorizationError(RuntimeError):
    """Raised when a scan is attempted without explicit authorization."""


class ScanControlSignal(Exception):
    """Raised *by a progress callback* to intentionally interrupt a running
    scan (e.g. the API cancelling a job). Unlike ordinary observer errors —
    which are swallowed so a broken observer can never abort a scan — this
    signal is allowed to propagate out of Engine.run()."""


# A progress callback receives (event_type, payload) at orchestration
# boundaries. event_type is one of:
#   "module_start" -> {"module", "category", "index", "total"}
#   "finding"      -> {"module", "finding": Finding}
#   "module_end"   -> {"module", "count", "index", "total"}
#   "scan_end"     -> {"total_findings"}
ProgressCallback = Callable[[str, dict[str, Any]], None]


class Engine:
    def __init__(
        self,
        target: Target,
        categories: list[str] | None = None,
        verbose: bool = False,
        http_timeout: float = 10.0,
        rate_limit_delay: float = 0.3,
        auth_headers: dict | None = None,
        auth_cookies: dict | None = None,
    ):
        self.target = target
        self.categories = categories or ["recon", "web", "cve"]
        self.verbose = verbose
        self.ctx = ModuleContext(
            target=target,
            http_timeout=http_timeout,
            rate_limit_delay=rate_limit_delay,
            verbose=verbose,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
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

    def _emit(self, callback: Optional[ProgressCallback], event: str, payload: dict) -> None:
        """Notify an optional observer of a progress event.

        Observer errors are swallowed so a broken observer can never abort a
        scan — the one exception is ScanControlSignal, which is a deliberate
        request (e.g. cancellation) and is allowed to propagate."""
        if callback is None:
            return
        try:
            callback(event, payload)
        except ScanControlSignal:
            raise
        except Exception as e:  # noqa: BLE001
            if self.verbose:
                print(f"[!] progress callback error: {e}")

    def run(self, progress_callback: Optional[ProgressCallback] = None) -> Report:
        """Run all discovered modules and aggregate their findings.

        progress_callback is optional and purely observational: when omitted
        (the CLI's path) behaviour is identical to before. When provided (the
        API's path) it receives orchestration events, enabling live progress
        and WebSocket streaming without duplicating this loop elsewhere."""
        if not self._modules:
            self.discover_modules()

        # Run in a stable order: recon first (it can populate ctx.extra_hosts
        # for later web/cve modules), then web, then cve.
        order = {"recon": 0, "web": 1, "cve": 2}
        modules = sorted(self._modules, key=lambda m: order.get(m.category, 99))
        total = len(modules)

        for index, module_cls in enumerate(modules, start=1):
            print(f"[*] Running {module_cls.name} ({module_cls.category})...")
            self._emit(progress_callback, "module_start", {
                "module": module_cls.name,
                "category": module_cls.category,
                "index": index,
                "total": total,
            })
            try:
                instance = module_cls(self.ctx)
                findings = instance.run() or []
                for f in findings:
                    self.report.add(f)
                    self._emit(progress_callback, "finding", {"module": module_cls.name, "finding": f})
                print(f"    -> {len(findings)} finding(s)")
                self._emit(progress_callback, "module_end", {
                    "module": module_cls.name,
                    "count": len(findings),
                    "index": index,
                    "total": total,
                })
            except ScanControlSignal:
                raise
            except Exception as e:  # noqa: BLE001
                print(f"    -> module crashed: {e}")
                if self.verbose:
                    traceback.print_exc()
                crash = Finding(
                    module=module_cls.name,
                    title="Module execution error",
                    severity=Severity.INFO,
                    target=str(self.target),
                    description=str(e),
                )
                self.report.add(crash)
                self._emit(progress_callback, "finding", {"module": module_cls.name, "finding": crash})
                self._emit(progress_callback, "module_end", {
                    "module": module_cls.name,
                    "count": 1,
                    "index": index,
                    "total": total,
                })

        self._emit(progress_callback, "scan_end", {"total_findings": len(self.report.findings)})
        return self.report
