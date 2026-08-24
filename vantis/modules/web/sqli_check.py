"""
Non-destructive SQL injection detection.

Two techniques, both read-only / side-effect-free:

1. Error-based: append a single quote and look for a database error
   signature in the response (MySQL/Postgres/MSSQL/Oracle/SQLite).
2. Boolean-based differential: compare response to a "always true"
   vs "always false" condition appended to the parameter, and flag a
   meaningful difference in response length/status.

This intentionally stops at DETECTION. It never attempts UNION-based
data extraction, time-based blind techniques that hammer the DB, or
any write/stacked-query payloads — that crosses from "confirm a bug
exists" into "exploit it", which isn't something this tool does.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

DEFAULT_PARAMS = ["id", "search", "q", "category", "product", "user", "page"]

ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"pg_query\(\)|postgresql.*error|syntax error at or near", "PostgreSQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"sqlite3?\.OperationalError|sqlite_error", "SQLite"),
    (r"sqlstate\[", "Generic SQL (PDO)"),
]

ERROR_RE = [re.compile(p, re.IGNORECASE) for p, _ in ERROR_SIGNATURES]


class SqliCheckModule(ScanModule):
    name = "sqli-detect"
    category = "web"
    description = "Non-destructive SQL injection detection (error-based + boolean differential)"

    def _url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        base_url = str(self.ctx.target)
        parsed = urlparse(base_url)
        existing_params = list(parse_qs(parsed.query).keys())
        params_to_test = existing_params or DEFAULT_PARAMS

        findings: list[Finding] = []

        for param in params_to_test[:15]:
            # -- Error-based check --
            probe_url = self._url_with_param(base_url, param, "'")
            resp = client.get(probe_url)
            if resp and resp.text:
                for (raw_pattern, dbms), regex in zip(ERROR_SIGNATURES, ERROR_RE):
                    if regex.search(resp.text):
                        findings.append(
                            Finding(
                                module=self.name,
                                title=f"Possible SQL injection in parameter '{param}' ({dbms} error)",
                                severity=Severity.HIGH,
                                target=base_url,
                                matched_at=probe_url,
                                evidence=f"Database error signature matched: {raw_pattern}",
                                description=(
                                    f"Injecting a single quote into '{param}' triggered a {dbms} "
                                    "error message in the response, suggesting unsanitized input "
                                    "reaches a SQL query. Verify manually before reporting — some "
                                    "WAFs/frameworks echo generic error pages that can look similar."
                                ),
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            )
                        )
                        break  # one match per param is enough signal

            # -- Boolean-based differential check --
            true_url = self._url_with_param(base_url, param, "1 OR 1=1")
            false_url = self._url_with_param(base_url, param, "1 AND 1=2")
            resp_true = client.get(true_url)
            resp_false = client.get(false_url)

            if resp_true and resp_false and resp_true.status_code == 200 and resp_false.status_code == 200:
                len_true, len_false = len(resp_true.text or ""), len(resp_false.text or "")
                if len_true and len_false and abs(len_true - len_false) > max(50, 0.15 * len_true):
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Possible boolean-based blind SQLi in parameter '{param}'",
                            severity=Severity.MEDIUM,
                            target=base_url,
                            matched_at=true_url,
                            evidence=f"Response length differs significantly: true={len_true} bytes vs false={len_false} bytes",
                            description=(
                                "A response-length difference between an always-true and "
                                "always-false condition can indicate blind SQL injection, but "
                                "can also be caused by unrelated dynamic content. Manual "
                                "confirmation strongly recommended before reporting."
                            ),
                            remediation="Use parameterized queries / prepared statements.",
                        )
                    )

        return findings
