"""Tests for automated form-based login."""
import responses

from vantis.utils.auth_login import parse_login_form, perform_login
from vantis.utils.http_client import HttpClient

LOGIN_PAGE = """
<html><body>
<form action="/do-login" method="post">
  <input type="hidden" name="csrf_token" value="abc123xyz">
  <input type="text" name="email" placeholder="Email">
  <input type="password" name="password">
  <button type="submit">Log in</button>
</form>
</body></html>
"""

NO_LOGIN_PAGE = "<html><body><form><input type='text' name='q'></form></body></html>"


def test_parse_login_form_finds_fields_and_preserves_csrf():
    form = parse_login_form(LOGIN_PAGE, "http://example.com/login")
    assert form is not None
    assert form.action == "http://example.com/do-login"
    assert form.method == "POST"
    assert form.username_field == "email"
    assert form.password_field == "password"
    assert form.fields["csrf_token"] == "abc123xyz"  # preserved unchanged


def test_parse_login_form_returns_none_without_password_field():
    assert parse_login_form(NO_LOGIN_PAGE, "http://example.com") is None


def test_parse_login_form_falls_back_to_first_text_field_as_username():
    html = '<form method="post"><input name="identifier"><input type="password" name="pwd"></form>'
    form = parse_login_form(html, "http://example.com")
    assert form.username_field == "identifier"
    assert form.password_field == "pwd"


@responses.activate
def test_perform_login_submits_credentials_and_returns_cookies():
    responses.add(responses.GET, "http://example.com/login", body=LOGIN_PAGE, status=200)

    def cb(request):
        # The CSRF token must be preserved, and our credentials injected.
        assert "csrf_token=abc123xyz" in request.body
        assert "email=alice%40example.com" in request.body
        assert "password=hunter2" in request.body
        return (200, {"Set-Cookie": "session=live123; Path=/"}, "logged in")

    responses.add_callback(responses.POST, "http://example.com/do-login", callback=cb)

    client = HttpClient(delay=0)
    cookies = perform_login(client, "http://example.com/login", "alice@example.com", "hunter2")
    assert cookies == {"session": "live123"}


@responses.activate
def test_perform_login_returns_none_when_no_form():
    responses.add(responses.GET, "http://example.com/login", body=NO_LOGIN_PAGE, status=200)
    client = HttpClient(delay=0)
    assert perform_login(client, "http://example.com/login", "a", "b") is None


@responses.activate
def test_perform_login_returns_none_when_no_cookie_set():
    responses.add(responses.GET, "http://example.com/login", body=LOGIN_PAGE, status=200)
    responses.add(responses.POST, "http://example.com/do-login", body="invalid credentials", status=200)
    client = HttpClient(delay=0)
    assert perform_login(client, "http://example.com/login", "alice@example.com", "wrong") is None
