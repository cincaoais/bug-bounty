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
