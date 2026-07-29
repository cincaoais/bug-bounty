"""Truth table for the redactor. Security-critical: this is what keeps secrets
and NDA-bound program data out of stored evidence and out of prompts.

TWO failure directions, both real:

  UNDER-redaction leaks a session token, an API key, or another user's personal
  data into a file on disk or into a report draft.

  OVER-redaction destroys the evidence. If it scrubs the URL, the parameter
  name, or the vulnerability detail, the user cannot write a report from it and
  will stop using the feature — which leaks everything, because they will go
  back to pasting raw traffic into a chat window.

Both directions are tested. The false-positive tests are not padding; they are
what makes the redactor safe to actually use.
"""
import importlib

import pytest


@pytest.fixture()
def red():
    import redact
    importlib.reload(redact)
    return redact


def _r(red, text):
    out, log = red.redact(text)
    return out


def _kinds(red, text):
    _, log = red.redact(text)
    return {e["kind"] for e in log}


# ---- must redact: auth material ---------------------------------------------

def test_bearer_token(red):
    out = _r(red, "Authorization: Bearer abc123DEFghi456JKLmno789PQR")
    assert "abc123DEFghi456JKLmno789PQR" not in out
    assert "REDACTED" in out


def test_basic_auth(red):
    out = _r(red, "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==")
    assert "dXNlcjpwYXNzd29yZDEyMw==" not in out


def test_cookie_header(red):
    out = _r(red, "Cookie: sessionid=9f8e7d6c5b4a3210fedcba9876543210; theme=dark")
    assert "9f8e7d6c5b4a3210fedcba9876543210" not in out


def test_set_cookie_header(red):
    out = _r(red, "Set-Cookie: JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2; Path=/; HttpOnly")
    assert "A1B2C3D4E5F6A7B8C9D0E1F2" not in out


def test_jwt(red):
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
           "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    out = _r(red, f"token={jwt}")
    assert jwt not in out


def test_aws_access_key(red):
    out = _r(red, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_aws_secret_key(red):
    out = _r(red, "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out


@pytest.mark.parametrize("line", [
    "api_key=sk_live_51H8xQ2eZvKYlo2C0abcdefghij",
    "apikey: 7d4f8e2a9c1b6503f8e2a9c1b6503f8e",
    "X-Api-Key: 3f2b8c9d0e1a4756b8c9d0e1a4756b8c",
    'password="hunter2correcthorsebattery"',
    "client_secret=GOCSPX-abcdefghijklmnopqrstuvwx",
])
def test_keyed_secrets(red, line):
    out = _r(red, line)
    assert "REDACTED" in out, f"no redaction applied to: {line}"


def test_private_key_block(red):
    pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEAvSomeKeyMaterialHere1234567890abcdef\n"
           "-----END RSA PRIVATE KEY-----")
    out = _r(red, pem)
    assert "MIIEowIBAAKCAQEA" not in out


# ---- must redact: personal data ---------------------------------------------

def test_email_address(red):
    out = _r(red, "victim account: alice.smith@example.com placed the order")
    assert "alice.smith@example.com" not in out


def test_card_like_number(red):
    out = _r(red, "card on file 4111 1111 1111 1111 expires soon")
    assert "4111 1111 1111 1111" not in out


# ---- must NOT redact: the evidence itself -----------------------------------
# Over-redaction makes the tool useless, which is its own security failure.

@pytest.mark.parametrize("text", [
    "GET /api/v1/orders/1042?include=items HTTP/1.1",
    "Host: api.acme.test",
    "HTTP/1.1 403 Forbidden",
    "Content-Type: application/json",
    "the order_id parameter accepts any integer",
    "response time was 240ms and the body was 1834 bytes",
    "changing role=user to role=admin returned 200",
    "https://api.acme.test/v1/profile?user_id=12",
    "User-Agent: Mozilla/5.0",
    "X-Request-Id header is reflected in the error page",
])
def test_does_not_redact_ordinary_evidence(red, text):
    out = _r(red, text)
    assert out == text, f"over-redacted: {text!r} -> {out!r}"


def test_preserves_surrounding_text(red):
    out = _r(red, "sent Authorization: Bearer abc123DEFghi456JKLmno789 and got 200 OK")
    assert out.startswith("sent ")
    assert out.endswith("and got 200 OK")


def test_short_hex_not_treated_as_secret(red):
    """Colour codes, short ids, and status values must survive."""
    for text in ["color: #ff8800", "id=42", "sha=a1b2c3", "port 8443"]:
        assert _r(red, text) == text, text


@pytest.mark.parametrize("pair", [
    "theme=dark", "role=user", "lang=en-US", "consent=1", "step=2", "tz=UTC",
])
def test_benign_cookie_values_survive(red, pair):
    """'the cookie says role=user, change it to role=admin' is a textbook authz
    finding. Blanket-redacting cookie values would scrub the evidence the report
    is built from."""
    out = _r(red, f"Cookie: {pair}")
    assert pair in out, f"over-redacted benign cookie: {pair} -> {out}"


@pytest.mark.parametrize("secret", [
    "session=deadbeefcafebabe0123456789abcdef",
    "JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2",
    "auth=8f14e45fceea167a5a36dedd4bea2543",
])
def test_session_cookie_values_still_redacted(red, secret):
    """The benign-value exemption must not open a hole for real session tokens."""
    name, value = secret.split("=", 1)
    out = _r(red, f"Cookie: {secret}")
    assert value not in out, f"session token leaked: {secret}"


def test_mixed_cookie_line_redacts_only_the_secret(red):
    out = _r(red, "Cookie: session=deadbeefcafebabe0123456789abcdef; theme=dark; role=user")
    assert "deadbeefcafebabe0123456789abcdef" not in out
    assert "theme=dark" in out and "role=user" in out


def test_empty_and_none_safe(red):
    assert _r(red, "") == ""
    out, log = red.redact("")
    assert log == []


# ---- reporting ---------------------------------------------------------------

def test_log_reports_kind_not_value(red):
    """The log must never echo the secret it just removed — it gets shown to the
    user and may be written to disk."""
    secret = "abc123DEFghi456JKLmno789PQR"
    out, log = red.redact(f"Authorization: Bearer {secret}")
    assert log, "redaction happened but was not logged"
    for entry in log:
        assert secret not in str(entry)
        assert "kind" in entry and "count" in entry


def test_log_counts_multiple(red):
    out, log = red.redact(
        "Cookie: a=1111111111111111111111111111\n"
        "Cookie: b=2222222222222222222222222222"
    )
    total = sum(e["count"] for e in log)
    assert total >= 2


def test_idempotent(red):
    """Redacting already-redacted text must not corrupt the placeholders."""
    once = _r(red, "Authorization: Bearer abc123DEFghi456JKLmno789PQR")
    twice = _r(red, once)
    assert once == twice


# ---- the property that matters most -----------------------------------------

def test_no_known_secret_survives_a_mixed_blob(red):
    """A realistic captured request/response containing several secret shapes at
    once. Every one must be gone; the HTTP structure must remain readable."""
    blob = (
        "POST /api/v1/profile HTTP/1.1\n"
        "Host: api.acme.test\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop\n"
        "Cookie: session=deadbeefcafebabe0123456789abcdef\n"
        "X-Api-Key: 9a8b7c6d5e4f30219a8b7c6d5e4f3021\n"
        "\n"
        '{"email":"alice.smith@example.com","role":"user"}\n'
    )
    out, log = red.redact(blob)
    for secret in ["eyJhbGciOiJIUzI1NiJ9", "deadbeefcafebabe0123456789abcdef",
                   "9a8b7c6d5e4f30219a8b7c6d5e4f3021", "alice.smith@example.com"]:
        assert secret not in out, f"leaked: {secret}"
    # structure survives so the evidence is still usable
    assert "POST /api/v1/profile HTTP/1.1" in out
    assert "Host: api.acme.test" in out
    assert '"role":"user"' in out
