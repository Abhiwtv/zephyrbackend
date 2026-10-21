#!/usr/bin/env python3
"""
port_scan.py -- read-only reconnaissance utility for the Zephyr lab LAN.

Pure-Python TCP connect scanner, with an optional SYN scan mode if `scapy`
is installed (falls back to connect mode otherwise). No external tools or
credentials are used -- this only tells you whether a port answers.

Usage:
    python port_scan.py TARGET_IP [--ports PORT_SPEC] [--mode connect|syn]
                         [--timeout SEC] [--json] [--target-port PORT]

Examples:
    python port_scan.py 172.28.0.14
    python port_scan.py 172.28.0.14 --ports 1-1024 --json
    python port_scan.py 172.28.0.14 --target-port 22          # scan one port
    python port_scan.py 172.28.0.14 --ports 22,80,443,8080
    python port_scan.py 172.28.0.14 --mode syn --ports 1-1024  # needs root + scapy

Output (--json) is shaped like this project's NIDSAlert.flow_metrics so it
drops straight into the existing dashboard/pipeline:
    {
      "source_ip": "...", "target_ip": "...", "timestamp": "...Z",
      "packet_count_2s": N, "unique_dest_ports": [open ports...],
      "scan_duration_s": T, "results": [{port, state, latency_ms}, ...]
    }
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                  443, 445, 3306, 3389, 5432, 5900, 8000, 8080, 8443]


def parse_port_spec(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or a mix '22,1000-1010' into a sorted
    list of unique ints. Raises ValueError on anything out of range."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    if not ports:
        raise ValueError("empty port spec")
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"port {p} out of range 1-65535")
    return sorted(ports)


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid IP address: {ip}") from e


def connect_scan_port(target_ip: str, port: int, timeout: float) -> dict:
    start = time.monotonic()
    state = "closed"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((target_ip, port))
            state = "open" if rc == 0 else "closed"
    except socket.timeout:
        state = "filtered"
    except OSError:
        state = "filtered"
    latency_ms = round((time.monotonic() - start) * 1000, 2)
    return {"port": port, "state": state, "latency_ms": latency_ms}


def syn_scan_port(target_ip: str, port: int, timeout: float) -> dict:
    """SYN (half-open) scan via scapy. Requires scapy installed and raw-socket
    privileges (root / NET_ADMIN inside the container). Sends one SYN, reads
    the reply, and -- if the port is open -- sends a RST to avoid completing
    the handshake, so no application-level connection is ever made."""
    from scapy.all import IP, TCP, sr1  # type: ignore  # imported lazily

    start = time.monotonic()
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    reply = sr1(pkt, timeout=timeout, verbose=0)
    latency_ms = round((time.monotonic() - start) * 1000, 2)

    if reply is None:
        return {"port": port, "state": "filtered", "latency_ms": latency_ms}
    if reply.haslayer(TCP):
        flags = reply.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            rst = IP(dst=target_ip) / TCP(dport=port, flags="R")
            sr1(rst, timeout=timeout, verbose=0)
            return {"port": port, "state": "open", "latency_ms": latency_ms}
        if flags == 0x14:  # RST-ACK
            return {"port": port, "state": "closed", "latency_ms": latency_ms}
    return {"port": port, "state": "filtered", "latency_ms": latency_ms}


def run_scan(target_ip: str, ports: list[int], mode: str, timeout: float) -> dict:
    scan_fn = connect_scan_port
    actual_mode = "connect"

    if mode == "syn":
        try:
            import scapy.all  # noqa: F401
            scan_fn = syn_scan_port
            actual_mode = "syn"
        except ImportError:
            print("[warn] scapy not installed -- falling back to connect scan. "
                  "Install with `pip install scapy` and run as root for SYN mode.",
                  file=sys.stderr)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    results = []
    for port in ports:
        try:
            results.append(scan_fn(target_ip, port, timeout))
        except PermissionError:
            print(f"[warn] SYN scan needs raw-socket privileges (root/NET_ADMIN); "
                  f"falling back to connect scan for port {port}.", file=sys.stderr)
            results.append(connect_scan_port(target_ip, port, timeout))
            actual_mode = "connect (fallback)"
    duration = round(time.monotonic() - t0, 3)

    open_ports = sorted(r["port"] for r in results if r["state"] == "open")

    return {
        "source_ip": "scanner-host",
        "target_ip": target_ip,
        "timestamp": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": actual_mode,
        "packet_count_2s": len(results),
        "unique_dest_ports": open_ports,
        "scan_duration_s": duration,
        "results": results,
    }


def print_human(report: dict) -> None:
    print(f"Scan of {report['target_ip']}  "
          f"({report['mode']} mode, {len(report['results'])} ports, "
          f"{report['scan_duration_s']}s)")
    print("-" * 48)
    for r in report["results"]:
        marker = {"open": "OPEN", "closed": "closed", "filtered": "filtered"}[r["state"]]
        print(f"  {r['port']:>5}/tcp  {marker:<9} {r['latency_ms']:>7.2f} ms")
    print("-" * 48)
    if report["unique_dest_ports"]:
        print(f"Open ports: {', '.join(str(p) for p in report['unique_dest_ports'])}")
    else:
        print("Open ports: none")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Read-only TCP reconnaissance scanner for the lab LAN. "
                    "Reports open/closed/filtered state per port; does not "
                    "exploit, authenticate against, or send payloads to any port.")
    ap.add_argument("target_ip", type=validate_ip, help="Target IP, e.g. 172.28.0.14")
    ap.add_argument("--target-port", type=int, default=None,
                     help="Scan a single port (shorthand for --ports PORT)")
    ap.add_argument("--ports", default=None,
                     help="Port spec, e.g. '22,80,443' or '1-1024' "
                          "(default: 20 common ports)")
    ap.add_argument("--mode", choices=["connect", "syn"], default="connect",
                     help="connect = full TCP handshake (default, no privileges needed). "
                          "syn = half-open scan via scapy (needs scapy + root/NET_ADMIN).")
    ap.add_argument("--timeout", type=float, default=0.75, help="Per-port timeout in seconds")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = ap.parse_args()

    if args.target_port is not None:
        ports = [args.target_port]
    elif args.ports:
        try:
            ports = parse_port_spec(args.ports)
        except ValueError as e:
            ap.error(str(e))
            return 2
    else:
        ports = DEFAULT_PORTS

    report = run_scan(args.target_ip, ports, args.mode, args.timeout)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
