#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import time


def receive(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise OSError("unexpected close")
        result += chunk
    return result


def bridge(client, allowed, authorization):
    with client:
        client.settimeout(12)
        request = b""
        while not request.endswith(b"\r\n\r\n") and len(request) < 8192:
            request += receive(client, 1)
        lines = request.decode("ascii").split("\r\n")
        method, target, _ = lines[0].split()
        headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
        headers = {key.lower(): value.strip() for key, value in headers.items()}
        if method != "CONNECT" or target not in allowed or headers.get("proxy-authorization") != authorization:
            client.sendall(b"HTTP/1.0 403 Forbidden\r\n\r\n")
            return
        with socket.create_connection(allowed[target], timeout=8) as upstream:
            upstream.sendall(bytes.fromhex("030000130ee000000000000100080003000000"))
            header = receive(upstream, 4)
            length = int.from_bytes(header[2:], "big")
            if header[:2] != b"\x03\x00" or not 11 <= length <= 1024:
                raise ValueError("invalid RDP negotiation response")
            reply = receive(upstream, length - 4)
            if len(reply) < 15 or reply[-8] != 2 or int.from_bytes(reply[-4:], "little") not in (1, 2):
                raise ValueError("RDP TLS negotiation not accepted")
            client.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
            peers = {client: upstream, upstream: client}
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                ready, _, _ = select.select(list(peers), [], [], 0.25)
                for source in ready:
                    packet = source.recv(65536)
                    if not packet:
                        return
                    peers[source].sendall(packet)


def main():
    parser = argparse.ArgumentParser(description="Authenticated CONNECT bridge for RDP TLS negotiation; does not invoke TLS tools.")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--completed", type=Path, required=True)
    parser.add_argument("--done", type=Path, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--advertise")
    parser.add_argument("--timeout", type=int, default=7200)
    args = parser.parse_args()
    allowed = {}
    for row in json.loads(args.targets.read_text()):
        address, port = str(ipaddress.ip_address(row["ip"])), int(row["port"])
        if not ipaddress.ip_address(address).is_global or port != 3389:
            raise ValueError("bridge targets must be public RDP endpoints")
        target = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        allowed[target] = (address, port)
    args.completed.parent.mkdir(parents=True, exist_ok=True)
    args.completed.unlink(missing_ok=True)
    if not allowed:
        args.completed.touch()
        return
    advertise = args.advertise
    if not advertise:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(("192.0.2.1", 9))
            advertise = route.getsockname()[0]
    token = secrets.token_hex(32)
    authorization = "Basic " + base64.b64encode(("rdp:" + token).encode()).decode()
    args.ready.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        listener.bind((args.bind, 0))
        listener.listen(8)
        listener.settimeout(0.5)
        temporary = args.ready.with_suffix(".tmp")
        with temporary.open("w") as output:
            os.chmod(temporary, 0o600)
            output.write(f"{advertise}:{listener.getsockname()[1]}\t{token}\n")
        temporary.replace(args.ready)
        pending = set()
        deadline = time.monotonic() + args.timeout
        try:
            while not args.done.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("TLS consumer did not finish before bridge timeout")
                pending = {future for future in pending if not future.done()}
                if len(pending) >= 8:
                    time.sleep(0.1)
                    continue
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                pending.add(pool.submit(bridge, client, allowed, authorization))
        finally:
            args.ready.unlink(missing_ok=True)
    args.completed.touch()


if __name__ == "__main__":
    main()
