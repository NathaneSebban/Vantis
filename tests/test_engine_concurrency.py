"""Engine concurrency: web/cve modules run in parallel, safely."""
import threading
import time

from vantis.core.engine import Engine
from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.core.target import Target


def _make_module(module_name, order_log):
    class _M(ScanModule):
        name = module_name
        category = "web"

        def run(self):
            order_log.append((module_name, "start", time.monotonic()))
            time.sleep(0.15)  # force overlap when run concurrently
            order_log.append((module_name, "end", time.monotonic()))
            return [Finding(module=self.name, title=f"finding-{self.name}",
                            severity=Severity.INFO, target=str(self.ctx.target))]
    return _M


def _engine(modules, max_workers):
    eng = Engine(target=Target("http://example.com"), categories=["web"], max_workers=max_workers)
    eng._modules = modules  # skip discovery; inject fakes
    return eng


def test_sequential_runs_all_modules():
    log = []
    report = _engine([_make_module("a", log), _make_module("b", log)], max_workers=1).run()
    assert {f.title for f in report.findings} == {"finding-a", "finding-b"}


def test_concurrent_modules_overlap_and_all_findings_collected():
    log = []
    modules = [_make_module(n, log) for n in ("a", "b", "c")]
    dones = []

    def cb(evt, payload):
        if evt == "module_end":
            dones.append(payload.get("done"))

    report = _engine(modules, max_workers=3).run(progress_callback=cb)

    # All three findings collected (thread-safe report mutation).
    assert {f.title for f in report.findings} == {"finding-a", "finding-b", "finding-c"}

    # They actually overlapped: at least one module started before another ended.
    starts = sorted(t for _n, ev, t in log if ev == "start")
    ends = sorted(t for _n, ev, t in log if ev == "end")
    assert starts[1] < ends[0], "modules did not run concurrently"

    # 'done' is a monotonic completed-count reaching the total (progress never
    # regresses to total-1, even when modules finish out of index order).
    assert dones == [1, 2, 3]


def test_progress_callback_is_serialized():
    # Under concurrency, emissions must not interleave/corrupt: every module_end
    # count matches the number of findings emitted for that module.
    events = []
    lock_seen = threading.Lock()

    def cb(evt, payload):
        with lock_seen:
            events.append((evt, payload.get("module"), payload.get("count")))

    modules = [_make_module(n, []) for n in ("a", "b")]
    _engine(modules, max_workers=2).run(progress_callback=cb)

    ends = [(m, c) for evt, m, c in events if evt == "module_end"]
    assert sorted(ends) == [("a", 1), ("b", 1)]
    assert ("scan_end", None, None) in events
