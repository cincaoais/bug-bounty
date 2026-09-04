#!/usr/bin/env python3
"""Active-lab egress chokepoint (milestone 1): a deny-by-default forward proxy.

Standalone; NOT wired into the live plugin. All allow/deny/rate decisions come
from egress.py. Refuse-before-resolve: an out-of-scope destination is rejected
before any DNS lookup or upstream socket.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp"))
import egress  # noqa: E402


class Proxy:
    def __init__(self, allowlist, buckets, audit_path=None, clock=time.time):
        self.allowlist = allowlist
        self.buckets = buckets
        self.audit_path = audit_path
        self.clock = clock

    def _audit(self, kind, decision):
        rec = egress.AuditRecord.from_decision(kind, decision, ts=self.clock())
        if self.audit_path:
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json_line())

    async def handle(self, reader, writer):
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            parts = request_line.decode("latin-1").rstrip("\r\n").split(" ")
            if len(parts) < 3:
                await self._refuse(writer, 400, "bad request line")
                return
            method, target = parts[0], parts[1]
            if method.upper() == "CONNECT":
                await self._connect(reader, writer, target)
            else:
                await self._http(reader, writer, method, target)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass

    async def _connect(self, reader, writer, target):
        host, _, port_s = target.rpartition(":")
        if not host:
            host, port = target, 443
        else:
            port = int(port_s) if port_s.isdigit() else 443
        while True:  # drain remaining CONNECT headers
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        d = egress.decide(host, port, self.clock(), self.allowlist, self.buckets)
        self._audit("CONNECT", d)
        if not d.allow:
            await self._refuse(writer, d.code, d.reason)
            return
        try:
            up_r, up_w = await asyncio.open_connection(host, port)
        except OSError as e:
            await self._refuse(writer, 502, f"upstream connect failed: {e}")
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._pipe(reader, writer, up_r, up_w)

    async def _http(self, reader, writer, method, target):
        if "://" not in target:
            await self._refuse(writer, 400, "non-absolute-form request")
            return
        rest = target.split("://", 1)[1]
        hostport, _, path = rest.partition("/")
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else 80
        d = egress.decide(host, port, self.clock(), self.allowlist, self.buckets)
        self._audit(method.upper(), d)
        if not d.allow:
            await self._refuse(writer, d.code, d.reason)
            return
        try:
            up_r, up_w = await asyncio.open_connection(host, port)
        except OSError as e:
            await self._refuse(writer, 502, f"upstream connect failed: {e}")
            return
        up_w.write(f"{method} /{path} HTTP/1.1\r\n".encode("latin-1"))
        while True:  # copy request headers (incl. Host) verbatim
            line = await reader.readline()
            up_w.write(line)
            if line in (b"\r\n", b"\n", b""):
                break
        await up_w.drain()
        await self._pipe(reader, writer, up_r, up_w)

    async def _refuse(self, writer, code, reason):
        body = f"{code} {reason}".encode("utf-8")
        writer.write(
            f"HTTP/1.1 {code} Blocked\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode("latin-1") + body)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()

    async def _pipe(self, c_r, c_w, u_r, u_w):
        async def copy(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass
        await asyncio.gather(copy(c_r, u_w), copy(u_r, c_w))


def _rules_from_allow(allow_list):
    rules = []
    for a in allow_list:
        host, _, port_s = a.rpartition(":")
        if host and port_s.isdigit():
            rules.append(egress.Rule(host, int(port_s)))
        else:
            rules.append(egress.Rule(a, None))
    return rules


async def _serve(args):
    allowlist = egress.Allowlist(_rules_from_allow(args.allow))
    buckets = egress.TokenBucket(args.rate, args.refill)
    proxy = Proxy(allowlist, buckets, audit_path=args.audit)
    server = await asyncio.start_server(proxy.handle, args.host, args.port)
    addr = server.sockets[0].getsockname()
    print(f"LISTENING {addr[0]}:{addr[1]}", flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--allow", action="append", default=[], help="host[:port]; repeatable")
    p.add_argument("--rate", type=int, default=100, help="token-bucket capacity")
    p.add_argument("--refill", type=float, default=100.0, help="tokens per second")
    p.add_argument("--audit", default=None)
    args = p.parse_args(argv)
    try:
        asyncio.run(_serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
