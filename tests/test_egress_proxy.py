import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROXY = Path(__file__).resolve().parent.parent / "plugin" / "tools" / "egress_proxy.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _OK(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _http_server(port, handler):
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_proxy(allow, rate=100, refill=100.0, audit=None):
    args = [sys.executable, str(PROXY), "--port", "0", "--rate", str(rate), "--refill", str(refill)]
    for a in allow:
        args += ["--allow", a]
    if audit:
        args += ["--audit", str(audit)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = proc.stdout.readline()
    assert line.startswith("LISTENING"), f"unexpected startup line: {line!r}"
    port = int(line.strip().rsplit(":", 1)[1])
    return proc, port


def test_http_absolute_form_allowed_forwards_to_origin():
    _OK.hits = 0
    origin = _free_port()
    _http_server(origin, _OK)
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{origin}"])
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        resp = opener.open(f"http://127.0.0.1:{origin}/", timeout=5)
        assert resp.read() == b"ok"
        assert _OK.hits == 1
    finally:
        proc.terminate()


def test_connect_denied_returns_403():
    proc, pport = _start_proxy(allow=["127.0.0.1:9"])  # non-empty allowlist, different port
    try:
        s = socket.create_connection(("127.0.0.1", pport), timeout=5)
        s.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
        resp = s.recv(1024).decode("latin-1")
        s.close()
        assert "403" in resp
    finally:
        proc.terminate()


import base64
import json


def test_out_of_scope_blocked_regardless_of_command_obfuscation(tmp_path):
    # (crit a) the proxy decides on the destination it RECEIVES, not on any
    # command string — so a base64-assembled host is still seen and blocked.
    audit = tmp_path / "audit.jsonl"
    proc, pport = _start_proxy(allow=["127.0.0.1:9"], audit=audit)
    try:
        host = base64.b64decode(b"ZXZpbC5leGFtcGxl").decode()  # "evil.example"
        s = socket.create_connection(("127.0.0.1", pport), timeout=5)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        resp = s.recv(1024).decode("latin-1")
        s.close()
        assert "403" in resp
    finally:
        proc.terminate()
    records = [json.loads(x) for x in audit.read_text().splitlines() if x.strip()]
    assert any(r["host"] == "evil.example" and r["decision"] == "deny"
               and r["gate"] == "destination" for r in records)


def test_redirect_to_out_of_scope_blocked_and_origin_never_contacted():
    # (crit b) allowed origin 302-redirects to an out-of-scope port; the
    # redirect-follow is refused at the proxy; the spy server gets 0 hits.
    allowed = _free_port()
    spy = _free_port()

    class _Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{spy}/")
            self.end_headers()

        def log_message(self, *a):
            pass

    _OK.hits = 0
    _http_server(allowed, _Redirect)
    _http_server(spy, _OK)   # out-of-scope: different port -> not on allowlist
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{allowed}"])
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        try:
            opener.open(f"http://127.0.0.1:{allowed}/", timeout=5)
            assert False, "expected the out-of-scope redirect target to be blocked"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        proc.terminate()
    assert _OK.hits == 0  # spy (out-of-scope) never contacted


def test_per_host_rate_limit_returns_429():
    # (crit c) capacity 3, no refill -> 4th request over the ceiling is 429.
    allowed = _free_port()
    _OK.hits = 0
    _http_server(allowed, _OK)
    proc, pport = _start_proxy(allow=[f"127.0.0.1:{allowed}"], rate=3, refill=0.0)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"127.0.0.1:{pport}"}))
        codes = []
        for _ in range(4):
            try:
                codes.append(opener.open(f"http://127.0.0.1:{allowed}/", timeout=5).status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429
    finally:
        proc.terminate()
