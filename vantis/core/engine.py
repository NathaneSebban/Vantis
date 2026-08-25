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
from vantis.core.report import Confidence, Finding, Report, Severity
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


def discover_all_modules() -> list[type["ScanModule"]]:
    """Return every ScanModule subclass under vantis.modules.* — used to list
    the scanner's capabilities (e.g. the API's /api/modules) without running
    anything or needing a target."""
    import vantis.modules as modules_pkg

    found: list[type[ScanModule]] = []
    for _, name, _ in pkgutil.walk_packages(modules_pkg.__path__, prefix="vantis.modules."):
        try:
            mod = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - a broken plugin shouldn't break listing
            continue
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, ScanModule)
                and attr is not ScanModule
                and attr not in found
            ):
                found.append(attr)
    return found


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
        secondary_auth_headers: dict | None = None,
        secondary_auth_cookies: dict | None = None,
        max_workers: int = 1,
        enabled_modules: list[str] | None = None,
        browser_crawl: bool = False,
        login_url: str | None = None,
        login_username: str | None = None,
        login_password: str | None = None,
    ):
        self.target = target
        # When specific module names are requested, discover across all
        # categories and filter down to those names; otherwise run by category.
        self.enabled_modules = set(enabled_modules) if enabled_modules else None
        self.categories = ["recon", "web", "cve"] if self.enabled_modules else (categories or ["recon", "web", "cve"])
        self.verbose = verbose
        self.max_workers = max_workers

        # Automated form-based login: if a login URL + credentials were
        # supplied, submit the target's own login form up front and use the
        # resulting session cookies as this scan's authentication, in
        # addition to (never overwriting) any explicitly-provided
        # auth_headers/auth_cookies. Two-stage cascade: try the fast,
        # dependency-free HTML parser first (covers server-rendered login
        # pages); only if THAT finds no form, fall back to driving a real
        # headless browser (covers SPA login forms that only exist in the
        # DOM after client-side JS renders them). Most sites resolve in the
        # fast stage; only SPAs pay the much heavier browser cost. The
        # outcome (success/failure + reason + which method worked) is
        # recorded here and surfaced as a Finding at the start of run(), so
        # it's visible in the live feed and the final report — not just in a
        # server log the operator would otherwise never see.
        self._login_result: dict | None = None
        if login_url and login_username and login_password:
            from vantis.utils.auth_login import perform_login
            from vantis.utils.http_client import HttpClient

            login_client = HttpClient(timeout=http_timeout, delay=rate_limit_delay, headers=auth_headers)
            login_messages: list[str] = []

            def _login_log(m: str) -> None:
                login_messages.append(m)
                if verbose:
                    print(f"[login] {m}")

            cookies = perform_login(login_client, login_url, login_username, login_password, log=_login_log)
            method = "html-form"

            if not cookies:
                from vantis.utils.browser_crawler import browser_login

                cookies = browser_login(login_url, login_username, login_password, log=_login_log)
                if cookies:
                    method = "headless-browser"

            self._login_result = {
                "success": bool(cookies),
                "cookie_count": len(cookies) if cookies else 0,
                "reason": login_messages[-1] if login_messages else "",
                "login_url": login_url,
                "method": method if cookies else None,
            }
            if cookies:
                auth_cookies = {**cookies, **(auth_cookies or {})}

        self.ctx = ModuleContext(
            target=target,
            http_timeout=http_timeout,
            rate_limit_delay=rate_limit_delay,
            verbose=verbose,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            secondary_auth_headers=secondary_auth_headers,
            secondary_auth_cookies=secondary_auth_cookies,
            browser_crawl=browser_crawl,
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
                    and (self.enabled_modules is None or attr.name in self.enabled_modules)
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

    def _run_module(self, module_cls, index, total, callback, lock) -> None:
        """Execute one module. The module's own work (network I/O) runs outside
        the lock — that's where concurrency pays off — while report mutation and
        observer emission happen under `lock`, so the DB/WebSocket observer stays
        single-threaded and safe even when modules run in parallel."""
        with lock:
            print(f"[*] Running {module_cls.name} ({module_cls.category})...")
            self._emit(callback, "module_start", {
                "module": module_cls.name, "category": module_cls.category,
                "index": index, "total": total,
            })
        try:
            findings = module_cls(self.ctx).run() or []
        except ScanControlSignal:
            raise
        except Exception as e:  # noqa: BLE001
            print(f"    -> module crashed: {e}")
            if self.verbose:
                traceback.print_exc()
            findings = [Finding(
                module=module_cls.name, title="Module execution error",
                severity=Severity.INFO, target=str(self.target), description=str(e),
            )]
        with lock:
            for f in findings:
                self.report.add(f)
                self._emit(callback, "finding", {"module": module_cls.name, "finding": f})
            print(f"    -> {len(findings)} finding(s)")
            # Monotonic completed count — with concurrency, modules finish out of
            # index order, so 'done' (not 'index') is the true progress value.
            self._done += 1
            self._emit(callback, "module_end", {
                "module": module_cls.name, "count": len(findings),
                "index": index, "done": self._done, "total": total,
            })

    def run(self, progress_callback: Optional[ProgressCallback] = None,
            max_workers: Optional[int] = None) -> Report:
        """Run all discovered modules and aggregate their findings.

        progress_callback is optional and purely observational: when omitted
        (the CLI's path) behaviour is identical to before.

        max_workers > 1 runs the modules WITHIN the web and cve categories
        concurrently for speed. recon stays sequential because its modules have
        an ordering dependency (subdomain-takeover consumes subdomain-enum's
        results via ctx.extra_hosts). Categories always run in order
        (recon -> web -> cve). Default (1) is fully sequential."""
        import threading
        from concurrent.futures import ThreadPoolExecutor

        if not self._modules:
            self.discover_modules()

        # Surface the automated-login outcome as an ordinary finding, first —
        # so it shows up at the top of the live feed and in every report
        # export, instead of being visible only in a server log.
        if self._login_result is not None:
            lr = self._login_result
            if lr["success"]:
                method_note = ("via its rendered HTML form" if lr["method"] == "html-form"
                                else "via a headless browser, after its login form only appeared post-render (SPA)")
                login_finding = Finding(
                    module="auth-login", confidence=Confidence.HIGH,
                    title="Automated login succeeded",
                    severity=Severity.INFO,
                    target=str(self.target),
                    matched_at=lr["login_url"],
                    description=f"Vantis logged in {method_note} at {lr['login_url']} and obtained "
                                f"{lr['cookie_count']} session cookie(s); every module below ran authenticated.",
                )
            else:
                login_finding = Finding(
                    module="auth-login", confidence=Confidence.HIGH,
                    title="Automated login failed",
                    severity=Severity.LOW,
                    target=str(self.target),
                    matched_at=lr["login_url"],
                    description=f"Vantis could not log in via {lr['login_url']} (tried both the HTML form "
                                f"parser and a headless browser)"
                                + (f": {lr['reason']}." if lr["reason"] else "."),
                    remediation="Double-check the login URL and credentials. If the form needs a CAPTCHA, "
                                "2FA, or a non-standard submission flow, log in manually and pass the "
                                "resulting session via --cookie/secondary_cookies instead. "
                                "Modules below ran UNAUTHENTICATED.",
                )
            self.report.add(login_finding)
            self._emit(progress_callback, "finding", {"module": login_finding.module, "finding": login_finding})

        workers = max_workers or self.max_workers
        order = {"recon": 0, "web": 1, "cve": 2}
        modules = sorted(self._modules, key=lambda m: order.get(m.category, 99))
        total = len(modules)
        lock = threading.Lock()
        counter = iter(range(1, total + 1))
        self._done = 0  # monotonic completed-module counter (for progress)

        # Preserve category order; parallelize only within web/cve.
        for category in sorted({m.category for m in modules}, key=lambda c: order.get(c, 99)):
            cat_modules = [m for m in modules if m.category == category]
            indexed = [(next(counter), m) for m in cat_modules]

            if workers > 1 and category != "recon" and len(indexed) > 1:
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futures = [ex.submit(self._run_module, m, idx, total, progress_callback, lock)
                               for idx, m in indexed]
                    for fut in futures:
                        fut.result()  # propagates ScanControlSignal / unexpected errors
            else:
                for idx, m in indexed:
                    self._run_module(m, idx, total, progress_callback, lock)

        # Cross-finding correlation: run once, after every module has
        # finished, over the complete finding set. Emitted as ordinary
        # "finding" events so the API/CLI persist and display them exactly
        # like any other finding.
        from vantis.core.correlator import correlate

        for f in correlate(self.report.findings):
            self.report.add(f)
            self._emit(progress_callback, "finding", {"module": f.module, "finding": f})

        self._emit(progress_callback, "scan_end", {"total_findings": len(self.report.findings)})
        return self.report
