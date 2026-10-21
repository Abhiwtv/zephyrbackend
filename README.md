# demo_scripts/

Standalone tooling for the live Docker LAN demo interface. Everything the
demo needs lives in this folder; nothing outside it is touched.

```
demo_scripts/
├── port_scan.py       read-only TCP reconnaissance scanner (pure Python)
├── attack_runner.py   orchestration wrapper around external security tools
├── results/           JSON + raw-log output from attack_runner.py runs
└── README.md          this file
```

## port_scan.py

Pure-Python TCP connect scanner. No third-party dependencies, no exploit
logic -- it only reports which ports answer.

```
python port_scan.py TARGET_IP [--target-port PORT | --ports PORT_SPEC]
                     [--mode connect|syn] [--timeout SEC] [--json]
```

- `--mode connect` (default): standard TCP handshake, works anywhere, no
  privileges required.
- `--mode syn`: half-open SYN scan. Requires `pip install scapy` and
  root / `NET_ADMIN` inside the container. Falls back to connect mode
  automatically if scapy isn't installed or privileges are missing.
- `--json` output is shaped like this project's `NIDSAlert.flow_metrics`
  (`packet_count_2s`, `unique_dest_ports`, `timestamp`, ...) so it can be
  piped straight into the existing dashboard/pipeline.

Examples:
```
python port_scan.py 172.28.0.14
python port_scan.py 172.28.0.14 --ports 1-1024 --json
python port_scan.py 172.28.0.14 --target-port 22
```

## attack_runner.py

A thin orchestration wrapper. **It contains no attack, exploit, flood, or
brute-force logic of its own.** It only builds a command line for an
already-installed external tool, runs it inside the target container via
`docker exec`, and logs the result.

```
python attack_runner.py TOOL TARGET_IP TARGET_PORT
                         [--container pc-2] [--extra-args "..."]
                         [--duration SEC] [--json] [--dry-run]
```

| TOOL           | Wraps external binary | Must be pre-installed in the container |
|----------------|------------------------|------------------------------------------|
| `hydra_ssh`    | `hydra`                | `apt-get install hydra` + your own wordlists at `/usr/share/wordlists/common-users.txt` and `common-passwords.txt` |
| `sqlmap_scan`  | `sqlmap`                | `apt-get install sqlmap` |
| `hping3_flood` | `hping3`                | `apt-get install hping3` |
| `log4j_probe`  | `log4j-poc`             | an operator-supplied PoC executable named `log4j-poc` on `PATH` inside the container -- **not provided by this project** |

None of these binaries, wordlists, or PoC scripts are installed, generated,
or vendored by this repo. `attack_runner.py` checks whether the binary is
on `PATH` inside the container before running and fails with the install
hint above if it isn't.

Use `--dry-run` to print the exact command that would run without
executing it -- useful for a presentation walkthrough or for checking the
invocation before wiring up the real tools.

Examples:
```
python attack_runner.py hydra_ssh 172.28.0.14 22 --dry-run
python attack_runner.py sqlmap_scan 172.28.0.14 80 --json
python attack_runner.py hping3_flood 172.28.0.14 80 --duration 10 --json
```

Each run writes to `results/`:
- `<tool>_<ip>_<port>_<timestamp>.json` -- structured summary
  (`tool`, `target_ip`, `target_port`, `started_at`, `finished_at`,
  `exit_code`, `summary`, `raw_output_path`)
- `<tool>_<ip>_<port>_<timestamp>.raw.log` -- full stdout/stderr of the
  external tool

## Setup checklist before a live run

1. `docker` CLI available on the host running `attack_runner.py`.
2. Inside the `pc-2` (attacker) container, install whichever of
   `hydra` / `sqlmap` / `hping3` the demo needs, and supply your own
   wordlists for `hydra_ssh`.
3. For `log4j_probe`, place your own PoC executable (named `log4j-poc`) on
   `PATH` inside the container -- this repo does not ship one.
4. `port_scan.py` needs none of the above and works immediately.
