#!/usr/bin/env python3
"""RFC 6455 echo origin for the Autobahn conformance run.

Echoes text and binary messages, answers pings, performs the closing
handshake, and negotiates permessage-deflate, so Autobahn's §12/§13 cases
exercise compression end to end. Uses Python ``websockets`` because it gets
the close handshake right; a mirror that drops TCP on Close scores UNCLEAN
on every case and would hide real tunnel faults.

Usage: ws_echo.py <port>
"""

import asyncio
import sys

import websockets


async def echo(ws):
    try:
        async for msg in ws:
            await ws.send(msg)
    except websockets.ConnectionClosed:
        pass


async def main(port: int):
    async with websockets.serve(
        echo,
        "127.0.0.1",
        port,
        max_size=64 * 1024 * 1024,
        compression="deflate",
    ):
        print(f"ws echo on 127.0.0.1:{port}", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1])))
