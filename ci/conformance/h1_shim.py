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
    """Copy bytes src → dst until EOF or error, then half-close dst.

    Connection state is part of what the probe measures (`Connection:
    close` must actually close; a smuggled request must not get an extra
    response), so EOF must propagate exactly: when the edge closes, the
    probe's socket must see EOF too, and vice versa. Only the write side
    of `dst` is shut here; the other pump thread still owns its read side.
    """
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if transform is not None:
                data = transform(data)
            if data:
                dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, tunnel_host: str, edge_host: str, ctx: ssl.SSLContext):
    try:
        raw = socket.create_connection((edge_host, 443), timeout=15)
        edge = ctx.wrap_socket(raw, server_hostname=tunnel_host)
    except OSError:
        client.close()
        return

    # Keep-alive and pipelining: several requests share one connection, so
    # every head on it needs its Host patched, not just the first. Bytes
    # after a head (a body) cannot be told apart from the next head without
    # parsing framing — which the probe deliberately makes ambiguous — so
    # the heuristic is: patch any `Host:` line we see at the start of a
    # header block; a body containing a literal `Host:` line at line start
    # is exactly the smuggling shape the edge is meant to catch, and
    # rewriting it does not change the verdict.
    state = {"buf": b"", "pipe": False}
    thost = tunnel_host.encode()
    method_re = re.compile(rb"^[A-Za-z]{1,20} \S+ HTTP/\d")
    is_upgrade = re.compile(rb"(?im)^upgrade:")

    def to_edge(data: bytes) -> bytes:
        # After a WebSocket upgrade the connection carries masked binary
        # frames, not HTTP heads: become a pure pipe.
        if state["pipe"]:
            return data
        state["buf"] += data
        out = b""
        while state["buf"]:
            # Only hold bytes back while they look like the start of a
            # request head; anything else (a body, garbage the probe sends on
            # purpose) goes straight through.
            first_line_end = state["buf"].find(b"\n")
            probe = state["buf"] if first_line_end == -1 else state["buf"][:first_line_end]
            looks_like_head = method_re.match(probe.lstrip(b"\r\n")) is not None
            if not looks_like_head and first_line_end != -1:
                out += state["buf"]
                state["buf"] = b""
                break
            patched, done = rewrite_head(state["buf"], thost)
            if not done:
                if len(state["buf"]) > 64 * 1024:
                    out, state["buf"] = out + state["buf"], b""
                break
            cut = None
            for sep in (b"\r\n\r\n", b"\n\n"):
                idx = patched.find(sep)
                if idx != -1 and (cut is None or idx + len(sep) < cut):
                    cut = idx + len(sep)
            head = patched[:cut]
            out += head
            state["buf"] = patched[cut:]
            if is_upgrade.search(head):
                # Whatever follows the upgrade request (and the 101 the
                # other direction) is opaque from here on.
                state["pipe"] = True
                out += state["buf"]
                state["buf"] = b""
                break
        return out

    # Two independent half-duplex pumps; each half-closes its destination
    # on EOF, so the probe sees exactly the connection lifecycle the edge
    # produced. Both directions must end before the sockets are dropped, or
    # a late FIN from the edge would be lost.
    down = threading.Thread(target=pump, args=(edge, client), daemon=True)
    up = threading.Thread(target=pump, args=(client, edge, to_edge), daemon=True)
    down.start()
    up.start()
    down.join(timeout=60)
    up.join(timeout=60)
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
