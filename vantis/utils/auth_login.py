"""
Automated form-based login.

Instead of requiring the operator to already have a valid session
cookie/token, this fills in and submits the target's own login form: it reads
the form's fields (preserving hidden ones — CSRF tokens, etc. — unchanged),
puts the given credentials in the right fields, and submits. The resulting
session cookies are what modules then authenticate with.

Detection scope note: this is the one place in Vantis that intentionally
performs a real state-changing action (a login) — but only the login the
operator explicitly requested with credentials they explicitly provided. It
never guesses credentials or attempts more than the one submission asked for.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin

_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?([a-zA-Z]+)""", re.IGNORECASE)
_INPUT_RE = re.compile(
    r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE
)
_TYPE_RE = re.compile(r"""\btype\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_VALUE_RE = re.compile(r"""\bvalue\s*=\s*["']([^"']*)["']""", re.IGNORECASE)

_USERNAME_HINTS = ("user", "email", "login", "identifiant", "account")
_PASSWORD_HINTS = ("pass", "pwd")


@dataclass
class LoginForm:
    action: str
    method: str
    fields: dict[str, str]        # name -> current/default value (hidden fields, CSRF tokens...)
    username_field: str | None
    password_field: str | None


def parse_login_form(html: str, page_url: str) -> LoginForm | None:
    """Find the first form containing a password field and figure out which
    field is the username. Pure and side-effect free — unit-tested
    independent of any network access. Returns None if no password field is
    found on the page (nothing to log into)."""
    for form_html in _FORM_RE.findall(html):
        fields: dict[str, str] = {}
        username_field: str | None = None
        password_field: str | None = None

        for input_tag in re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE):
            name_m = re.search(r"""\bname\s*=\s*["']([^"']+)["']""", input_tag, re.IGNORECASE)
            if not name_m:
                continue
            name = name_m.group(1)
            type_m = _TYPE_RE.search(input_tag)
            input_type = (type_m.group(1).lower() if type_m else "text")
            value_m = _VALUE_RE.search(input_tag)
            fields[name] = value_m.group(1) if value_m else ""

            if input_type == "password" and password_field is None:
                password_field = name
            elif input_type in ("text", "email") and username_field is None:
                lname = name.lower()
                if input_type == "email" or any(h in lname for h in _USERNAME_HINTS):
                    username_field = name

        if password_field is None:
            continue  # not a login form

        # Fallback: if we found a password field but no obvious username
        # field, use the first non-password text-ish input.
        if username_field is None:
            for input_tag in re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE):
                name_m = re.search(r"""\bname\s*=\s*["']([^"']+)["']""", input_tag, re.IGNORECASE)
                type_m = _TYPE_RE.search(input_tag)
                if not name_m:
                    continue
                itype = (type_m.group(1).lower() if type_m else "text")
                if itype in ("text", "email") and name_m.group(1) != password_field:
                    username_field = name_m.group(1)
                    break

        action_m = _ACTION_RE.search(form_html)
        action = urljoin(page_url, action_m.group(1)) if action_m and action_m.group(1) else page_url
        method_m = _METHOD_RE.search(form_html)
        method = (method_m.group(1).upper() if method_m else "POST")

        return LoginForm(action=action, method=method, fields=fields,
                         username_field=username_field, password_field=password_field)

    return None


def perform_login(client, login_url: str, username: str, password: str, log=None) -> dict[str, str] | None:
    """Fetch the login page, fill and submit its form, return the resulting
    session cookies. Returns None on any failure (page unreachable, no login
    form found, submission failed) — never raises, mirroring every other
    best-effort network helper in this codebase."""
    log = log or (lambda _m: None)
    resp = client.get(login_url)
    if resp is None or not resp.text:
        log(f"login page unreachable: {login_url}")
        return None

    form = parse_login_form(resp.text, login_url)
    if form is None or form.username_field is None:
        log(f"no login form found at {login_url}")
        return None

    payload = dict(form.fields)
    payload[form.username_field] = username
    payload[form.password_field] = password

    if form.method == "GET":
        submit = client.get(form.action, params=payload)
    else:
        submit = client.post(form.action, data=payload)

    if submit is None:
        log("login submission failed (network error)")
        return None

    cookies = dict(client.session.cookies)
    if not cookies:
        log("login submitted but no session cookie was set — credentials may be wrong")
        return None

    log(f"login succeeded, {len(cookies)} cookie(s) obtained")
    return cookies
