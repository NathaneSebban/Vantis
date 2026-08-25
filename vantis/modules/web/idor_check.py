"""
IDOR / broken access control detection.

Insecure Direct Object Reference: a resource identifier (an id, order number,
invoice, etc.) that any authenticated user can access by simply changing the
value in the URL, regardless of who actually owns it. This is one of the
highest-value, most commonly rewarded bug classes in bug bounty programs, and
one that no single-identity scanner can detect by construction: proving it
requires observing the SAME request succeed for two DIFFERENT users.

Requires two distinct authenticated identities (see ModuleContext.
secondary_auth_*) — a real second test account the operator provides. Without
one, this module has nothing to compare against and reports nothing; it never
guesses or fabricates a second identity.

Method (non-destructive, read-only):
1. Crawl as identity A to find URLs containing what look like resource-owner
   identifiers (numeric ids, UUIDs) in id-ish parameter names.
2. For each candidate, establish identity B's baseline: a request for a
   resource B almost certainly cannot own (a random id), fingerprinting what
   B's "denied/not found" response looks like.
3. Request A's exact resource, but authenticated as B. If B's response is
   clearly NOT the denied/not-found shape (materially different status or
   size), B likely just read A's resource: an access-control finding.

Only ever issues GET requests. Never writes, deletes, or modifies anything.
"""
from __future__ import annotations

import random
import re
import uuid
from urllib.parse import parse_qs, urlparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Confidence, Finding, Severity
from vantis.utils.crawler import discover_injection_points, set_param

# Parameter names that plausibly reference a specific owned resource.
ID_PARAM_RE = re.compile(
    r"^(id|.*_id|.*id|uid|uuid|guid|account|user|profile|order|invoice|doc(ument)?|"
    r"file|ticket|record|ref(erence)?|customer|member)$",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"^\d{1,12}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def looks_like_resource_id(param_name: str, value: str) -> bool:
    """Pure heuristic: does this (name, value) pair look like an owned-resource
    identifier worth IDOR-testing? Unit-tested independent of any network call."""
    if not ID_PARAM_RE.match(param_name):
        return False
    return bool(_NUMERIC_RE.match(value) or _UUID_RE.match(value))


def _random_id_like(value: str) -> str:
    """Produce a random value of the same shape as `value` (numeric or UUID),
    for probing identity B's baseline 'not mine' response."""
    if _UUID_RE.match(value):
        return str(uuid.uuid4())
    # Numeric: same digit count, random digits (never the real value).
    return "".join(random.choice("0123456789") for _ in range(len(value))) or "999999"


class IdorCheckModule(ScanModule):
    name = "idor-check"
    category = "web"
    description = "Detect broken object-level access control (IDOR) using two authenticated identities"

    def run(self) -> list[Finding]:
        if not self.ctx.has_secondary_identity():
            self.log("no secondary identity configured, skipping (IDOR testing needs a second test account)")
            return []

        client_a = self.ctx.new_http_client()
        client_b = self.ctx.new_secondary_http_client()
        target = self.ctx.target

        points = discover_injection_points(client_a, target, self.log, use_browser=self.ctx.browser_crawl)
        candidates = []
        seen_params: set[str] = set()
        for p in points:
            qs = parse_qs(urlparse(p.url).query)
            values = qs.get(p.param) or []
            if not values:
                continue
            if looks_like_resource_id(p.param, values[0]) and p.param not in seen_params:
                seen_params.add(p.param)
                candidates.append((p, values[0]))

        findings: list[Finding] = []

        for point, real_value in candidates[:15]:
            # Confirm identity A can actually read this resource (baseline).
            resp_a = client_a.get(point.url)
            if resp_a is None or resp_a.status_code != 200 or not resp_a.text:
                continue

            # Identity B's baseline: a resource B almost certainly doesn't own.
            probe_url = set_param(point.url, point.param, _random_id_like(real_value))
            b_denied = client_b.get(probe_url)
            if b_denied is None:
                continue
            denied_status = b_denied.status_code
            denied_len = len(b_denied.text or "")

            # Identity B requesting A's real resource.
            b_real = client_b.get(point.url)
            if b_real is None:
                continue

            same_status_as_denial = b_real.status_code == denied_status
            similar_size_to_denial = (
                denied_len > 0 and abs(len(b_real.text or "") - denied_len) <= max(40, 0.05 * denied_len)
            )
            looks_denied = (b_real.status_code in (401, 403, 404)) or (same_status_as_denial and similar_size_to_denial)

            if b_real.status_code == 200 and not looks_denied:
                findings.append(Finding(
                    module=self.name, confidence=Confidence.MEDIUM, owasp="A01:2021", cwe="CWE-639",
                    title=f"Possible IDOR via parameter '{point.param}'",
                    severity=Severity.HIGH,
                    target=str(target),
                    matched_at=point.url,
                    evidence=(
                        f"Identity B fetched {point.param}={real_value} (owned by identity A) and got "
                        f"HTTP {b_real.status_code}/{len(b_real.text or '')}B, distinct from B's own "
                        f"denied/not-found baseline (HTTP {denied_status}/{denied_len}B)"
                    ),
                    description=(
                        f"A second authenticated identity was able to fetch a resource referenced by "
                        f"'{point.param}' that appears to belong to a different user, without receiving the "
                        "access-denied/not-found response it gets for resources it doesn't own. This suggests "
                        "the object reference is not authorization-checked server-side. Verify manually — "
                        "confirm the resource genuinely belongs to identity A before reporting."
                    ),
                    remediation="Verify server-side that the authenticated user is authorized to access the "
                                "specific object referenced, not just that they are authenticated.",
                    references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
                ))

        return findings
