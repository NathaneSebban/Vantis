"""
Command-line entry point.

    vantis --target https://example.com --modules recon,web,cve
    vantis --target example.com --scope example.com,api.example.com --output report.json
"""
from __future__ import annotations

import argparse
import sys

from vantis.core.engine import AuthorizationError, Engine
from vantis.core.target import Target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vantis",
        description="Modular vulnerability scanner (recon + web + CVE templates) for AUTHORIZED security testing only.",
    )
    parser.add_argument("--target", "-t", required=True, help="Target URL, domain or IP (e.g. https://example.com)")
    parser.add_argument(
        "--scope",
        help="Comma-separated list of additional in-scope hosts/domains/CIDRs (defaults to the target's own domain)",
    )
    parser.add_argument(
        "--modules", "-m",
        default="recon,web,cve",
        help="Comma-separated categories to run: recon,web,cve (default: all)",
    )
    parser.add_argument("--output", "-o", help="Output file. Extension picks the format: .json/.md/.html/.pdf")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.3, help="Minimum delay between requests in seconds (default 0.3, be polite)")
    parser.add_argument(
        "--header", "-H", action="append", default=[], metavar="'Name: value'",
        help="Extra request header for authenticated scanning (repeatable), e.g. -H 'Authorization: Bearer xxx'",
    )
    parser.add_argument(
        "--cookie", "-C", action="append", default=[], metavar="'name=value'",
        help="Session cookie for authenticated scanning (repeatable), e.g. -C 'session=abc123'",
    )
    parser.add_argument(
        "--secondary-header", action="append", default=[], metavar="'Name: value'",
        help="Header for a SECOND authenticated identity (repeatable). Enables IDOR testing (idor-check "
             "compares what this identity can access against the primary identity's resources).",
    )
    parser.add_argument(
        "--secondary-cookie", action="append", default=[], metavar="'name=value'",
        help="Cookie for a SECOND authenticated identity (repeatable). See --secondary-header.",
    )
    parser.add_argument(
        "--login-url", metavar="URL",
        help="URL of the target's own login page. Combined with --login-username/--login-password, Vantis "
             "submits that form itself and uses the resulting session cookies for the whole scan, instead of "
             "requiring you to already have a session cookie.",
    )
    parser.add_argument("--login-username", metavar="USER", help="Username/email to submit at --login-url")
    parser.add_argument("--login-password", metavar="PASS", help="Password to submit at --login-url")
    parser.add_argument("--workers", type=int, default=1,
                        help="Concurrent workers for web/cve modules (default 1 = sequential). Higher is faster.")
    parser.add_argument(
        "--browser-crawl", action="store_true",
        help="Render the target in headless Chromium to discover JS-rendered links/forms and real "
             "XHR/fetch API calls (requires: pip install vantis[browser] && playwright install chromium). "
             "Slower; off by default.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose module logging")
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Skip the interactive authorization prompt (use in CI/automation where you have already confirmed scope).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    scope = [s.strip() for s in args.scope.split(",")] if args.scope else []
    try:
        target = Target(raw=args.target, scope=scope)
    except ValueError as e:
        print(f"[!] Invalid target: {e}")
        return 2

    try:
        Engine.confirm_authorization(target, assume_yes=args.yes_i_am_authorized)
    except AuthorizationError as e:
        print(f"[!] {e}")
        return 1

    categories = [c.strip() for c in args.modules.split(",") if c.strip()]

    def _parse_pairs(items: list[str], sep: str, kind: str) -> dict:
        out = {}
        for item in items:
            if sep in item:
                k, v = item.split(sep, 1)
                out[k.strip()] = v.strip()
            else:
                print(f"[!] Ignoring malformed {kind} (expected '{'Name: value' if sep == ':' else 'name=value'}'): {item}")
        return out

    auth_headers = _parse_pairs(args.header, ":", "header")
    auth_cookies = _parse_pairs(args.cookie, "=", "cookie")
    secondary_auth_headers = _parse_pairs(args.secondary_header, ":", "secondary header")
    secondary_auth_cookies = _parse_pairs(args.secondary_cookie, "=", "secondary cookie")

    engine = Engine(
        target=target,
        categories=categories,
        verbose=args.verbose,
        http_timeout=args.timeout,
        rate_limit_delay=args.delay,
        auth_headers=auth_headers or None,
        auth_cookies=auth_cookies or None,
        secondary_auth_headers=secondary_auth_headers or None,
        secondary_auth_cookies=secondary_auth_cookies or None,
        max_workers=args.workers,
        browser_crawl=args.browser_crawl,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
    )
    report = engine.run()

    print("\n" + "=" * 70)
    counts = {sev: len(items) for sev, items in report.by_severity().items()}
    print(f" Scan complete: {len(report.findings)} finding(s)")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            print(f"   {sev.upper():<9} {counts[sev]}")
    print("=" * 70)

    if args.output:
        if args.output.endswith(".json"):
            report.to_json(args.output)
        elif args.output.endswith(".md"):
            report.to_markdown(args.output)
        elif args.output.endswith(".html"):
            report.to_html(args.output)
        elif args.output.endswith(".pdf"):
            report.to_pdf(args.output)
        elif args.output.endswith(".sarif"):
            report.to_sarif(args.output)
        else:
            print(f"[!] Unknown output extension for '{args.output}', defaulting to JSON")
            report.to_json(args.output + ".json")
        print(f"[*] Report written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
