#!/usr/bin/env python3
"""Plaintext-to-TLS shim for running Http11Probe through the tunnel.

Http11Probe speaks raw HTTP/1.1 over TCP to ``--host:--port`` and cannot set
TLS or a custom ``Host`` header. The relay edge, by design, refuses any
request whose ``Host`` does not match the TLS SNI (421). So this shim:

* listens on a local plaintext port,
* opens a TLS connection to the edge with the tunnel hostname as SNI,
* rewrites *only* the ``Host:`` header of each request head to the tunnel
  hostname, byte-for-byte otherwise (bare LF, folded headers, smuggling
  vectors and malformed input all pass through untouched — that is what the
  probe is testing),
* splices bytes in both directions until either side closes.

Head detection is deliberately tolerant: the head ends at the first blank
line, whether it is ``\\r\\n\\r\\n`` or ``\\n\\n``; if a request never sends a
blank line the bytes are forwarded unmodified as they arrive. Requests
without a ``Host`` header are left alone (the edge answers those itself).

Usage: h1_shim.py <listen_port> <tunnel_host> [<edge_host>] [<ca_pem>]
"""

import re
import socket
import ssl
import sys
import threading

HOST_RE = re.compile(rb"(?im)^host:[^\r\n]*")


def rewrite_head(buf: bytes, tunnel_host: bytes):
    """Return (rewritten_head_plus_rest, done) once a blank line is seen."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = buf.find(sep)
        if idx != -1:
            head, rest = buf[: idx + len(sep)], buf[idx + len(sep) :]
            head = HOST_RE.sub(b"Host: " + tunnel_host, head, count=1)
            return head + rest, True
    return buf, False


def pump(src, dst, transform=None):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if transform is not None:
                data = transform(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, tunnel_host: str, edge_host: str, ctx: ssl.SSLContext):
    try:
        raw = socket.create_connection((edge_host, 443), timeout=15)
        edge = ctx.wrap_socket(raw, server_hostname=tunnel_host)
    except OSError:
        client.close()
        return

    state = {"buf": b"", "done": False}
    thost = tunnel_host.encode()

    def to_edge(data: bytes) -> bytes:
        if state["done"]:
            return data
        state["buf"] += data
        out, done = rewrite_head(state["buf"], thost)
        if done:
            state["done"] = True
            state["buf"] = b""
            return out
        # Head not complete yet: hold bytes back until we can patch Host,
        # but never buffer more than a sane head size.
        if len(state["buf"]) > 64 * 1024:
            state["done"] = True
            out, state["buf"] = state["buf"], b""
            return out
        return b""

    t = threading.Thread(target=pump, args=(edge, client), daemon=True)
    t.start()
    pump(client, edge, to_edge)
    t.join(timeout=5)
    for s in (client, edge):
        try:
            s.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1])
    tunnel_host = sys.argv[2]
    edge_host = sys.argv[3] if len(sys.argv) > 3 else tunnel_host
    ca = sys.argv[4] if len(sys.argv) > 4 else None

    ctx = ssl.create_default_context(cafile=ca)
    ctx.set_alpn_protocols(["http/1.1"])

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"h1_shim: 127.0.0.1:{port} -> https://{edge_host} (SNI/Host {tunnel_host})", flush=True)
    while True:
        client, _ = srv.accept()
        client.settimeout(30)
        threading.Thread(target=handle, args=(client, tunnel_host, edge_host, ctx), daemon=True).start()


if __name__ == "__main__":
    main()
