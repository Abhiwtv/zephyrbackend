#!/usr/bin/env python3
"""
attack_runner.py -- orchestration wrapper for the Zephyr live-demo LAN.

This script contains NO attack, exploit, flood, or brute-force logic of its
own. It only builds a command line for an ALREADY-INSTALLED external tool,
runs it inside the target container via `docker exec`, captures the output,
and writes a result JSON that the FastAPI controller / dashboard can ingest.

Supported TOOL values map to external binaries that must be pre-installed
in the attacker container (default: pc-2). This script does not install,
configure, or vendor any of them -- see README.md for setup.

    hydra_ssh     -> hydra          (SSH credential testing)
    sqlmap_scan   -> sqlmap         (SQL injection testing)
    hping3_flood  -> hping3         (traffic generation / flood testing)
    log4j_probe   -> log4j-poc      (expects a wrapper script/binary named
                                      `log4j-poc` already present in the
                                      container; this project does not ship
                                      or generate that PoC)

Usage:
    python attack_runner.py TOOL TARGET_IP TARGET_PORT
                             [--container NAME] [--extra-args "..."]
                             [--duration SEC] [--json] [--dry-run]

Examples:
    python attack_runner.py hydra_ssh 172.28.0.14 22 --dry-run
    python attack_runner.py sqlmap_scan 172.28.0.14 80 --json
    python attack_runner.py hping3_flood 172.28.0.14 80 --duration 10 --json
    python attack_runner.py log4j_probe 172.28.0.14 8080 --json

Results are written under demo_scripts/results/ as:
    results/<tool>_<target_ip>_<port>_<timestamp>.json   (summary)
    results/<tool>_<target_ip>_<port>_<timestamp>.raw.log (raw stdout/stderr)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# ---------------------------------------------------------------------------
# Tool registry: each entry only describes HOW TO INVOKE a pre-installed
# external binary. None of these build attack payloads -- the real work
# happens entirely inside the external tool, which this project does not
# author, vendor, or modify.
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    binary: str                     # external executable this wraps
    build_args: callable            # (target_ip, target_port, extra) -> argv
    install_hint: str
    requires_wordlist: bool = False


def _hydra_args(target_ip: str, target_port: int, extra: list[str]) -> list[str]:
    # Wordlists are external files the operator supplies; this script does
    # not generate or embed any credential list.
    wordlist_user = "/usr/share/wordlists/common-users.txt"
    wordlist_pass = "/usr/share/wordlists/common-passwords.txt"
    return ["hydra", "-L", wordlist_user, "-P", wordlist_pass,
            "-s", str(target_port), *extra, f"ssh://{target_ip}"]


def _sqlmap_args(target_ip: str, target_port: int, extra: list[str]) -> list[str]:
    url = f"http://{target_ip}:{target_port}/"
    return ["sqlmap", "-u", url, "--batch", *extra]


def _hping3_args(target_ip: str, target_port: int, extra: list[str]) -> list[str]:
    return ["hping3", "-S", "-p", str(target_port), *extra, target_ip]


def _log4j_probe_args(target_ip: str, target_port: int, extra: list[str]) -> list[str]:
    # Delegates entirely to an externally supplied `log4j-poc` tool/script
    # that the operator has placed in the container. This project neither
    # ships nor generates that PoC.
    return ["log4j-poc", "--target", f"{target_ip}:{target_port}", *extra]


TOOLS: dict[str, ToolSpec] = {
    "hydra_ssh": ToolSpec(
        binary="hydra", build_args=_hydra_args,
        install_hint="apt-get install hydra  (and supply your own wordlists "
                      "at /usr/share/wordlists/ inside the container)",
        requires_wordlist=True,
    ),
    "sqlmap_scan": ToolSpec(
        binary="sqlmap", build_args=_sqlmap_args,
        install_hint="apt-get install sqlmap  (or `pip install sqlmap`)",
    ),
    "hping3_flood": ToolSpec(
        binary="hping3", build_args=_hping3_args,
        install_hint="apt-get install hping3",
    ),
    "log4j_probe": ToolSpec(
        binary="log4j-poc", build_args=_log4j_probe_args,
        install_hint="place a `log4j-poc` executable on PATH inside the "
                      "container (not provided by this project)",
    ),
}


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid IP address: {ip}") from e


def binary_exists_in_container(container: str, binary: str) -> bool:
    probe = subprocess.run(
        ["docker", "exec", container, "which", binary],
        capture_output=True, text=True,
    )
    return probe.returncode == 0


def run_in_container(container: str, argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec", container, *argv]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Invoke a pre-installed external security tool inside the "
                    "attacker container and log the result. Contains no "
                    "attack logic of its own -- see module docstring.")
    ap.add_argument("tool", choices=sorted(TOOLS.keys()))
    ap.add_argument("target_ip", type=validate_ip)
    ap.add_argument("target_port", type=int)
    ap.add_argument("--container", default="pc-2",
                     help="Container name/ID the tool runs inside (default: pc-2)")
    ap.add_argument("--extra-args", default="",
                     help="Extra args passed through to the external tool, "
                          "e.g. --extra-args '-t 4 -V'")
    ap.add_argument("--duration", type=int, default=15,
                     help="Max seconds to let the external tool run before timeout")
    ap.add_argument("--dry-run", action="store_true",
                     help="Print the command that would run, without executing it")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a summary line")
    args = ap.parse_args()

    if not (1 <= args.target_port <= 65535):
        ap.error("target_port must be 1-65535")

    spec = TOOLS[args.tool]
    extra = shlex.split(args.extra_args) if args.extra_args else []
    argv = spec.build_args(args.target_ip, args.target_port, extra)

    if args.dry_run:
        print("[dry-run] would execute inside container "
              f"'{args.container}': {' '.join(shlex.quote(a) for a in argv)}")
        if spec.requires_wordlist:
            print("[dry-run] note: hydra needs wordlist files present at the "
                  "paths above -- this script does not supply them.")
        return 0

    if shutil.which("docker") is None:
        print("[error] docker CLI not found on this host.", file=sys.stderr)
        return 1

    if not binary_exists_in_container(args.container, spec.binary):
        print(f"[error] '{spec.binary}' not found in container "
              f"'{args.container}'.\n        Install hint: {spec.install_hint}",
              file=sys.stderr)
        return 1

    started = datetime.now(timezone.utc)
    try:
        proc = run_in_container(args.container, argv, timeout=args.duration)
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        exit_code = -1
        stdout = (e.stdout or "")
        stderr = f"timed out after {args.duration}s"
    finished = datetime.now(timezone.utc)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    base = f"{args.tool}_{args.target_ip}_{args.target_port}_{stamp}"
    raw_path = RESULTS_DIR / f"{base}.raw.log"
    raw_path.write_text(f"$ {' '.join(argv)}\n\n--- stdout ---\n{stdout}\n"
                        f"--- stderr ---\n{stderr}\n", encoding="utf-8")

    summary_line = (stdout.strip().splitlines() or [""])[-1][:200]
    result = {
        "tool": args.tool,
        "binary": spec.binary,
        "container": args.container,
        "target_ip": args.target_ip,
        "target_port": args.target_port,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_at": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exit_code": exit_code,
        "summary": summary_line or "(no output)",
        "raw_output_path": str(raw_path),
    }

    json_path = RESULTS_DIR / f"{base}.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "ok" if exit_code == 0 else f"exit {exit_code}"
        print(f"[{args.tool}] {args.target_ip}:{args.target_port} -> {status}  "
              f"(result: {json_path.name})")

    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
