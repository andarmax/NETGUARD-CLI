# NETGUARD-CLI

NETGUARD-CLI is a dependency-free Python command-line tool for **authorized** network exposure auditing. It provides:

- LAN host discovery using the local ARP cache plus bounded TCP probes.
- Concurrent TCP connect scanning with service identification and optional safe banner collection.
- Educational exposure mapping with CVSS v3.1 scores and remediation guidance.
- Evidence-backed HTTP/TLS service fingerprinting with confidence scores.
- SQLite persistence for scan history, asset inventory, evidence hashes, and change monitoring.
- JSON, CSV, and self-contained HTML reports.
- A non-interactive CLI for automation and an interactive menu for guided use.

It does not exploit vulnerabilities, bypass authentication, evade controls, or perform UDP/flooding scans. Scan only systems you own or have explicit permission to test.

## Requirements

Python 3.9 or newer. No third-party packages are required.

## Quick start

```bash
python -m netguard --help
python -m netguard discover --cidr 192.168.1.0/24
python -m netguard scan 192.168.1.10 --ports common --banner --format html --output report.html
python -m netguard audit 192.168.1.10 --ports 22,80,443,3389 --output audit.json
python -m netguard monitor 192.168.1.10 --ports common --db ~/.netguard/netguard.db
python -m netguard history --target 192.168.1.10 --db ~/.netguard/netguard.db --format json
```

Installing locally exposes the `netguard` command:

```bash
python -m pip install .
netguard scan 192.168.1.10 --ports 1-1024 --workers 64
```

Running `python -m netguard` without a subcommand opens the interactive menu. Use `--version` to print the installed version.

## Commands

### `discover`

Discovers responsive hosts in a CIDR range. `--cidr` defaults to the first private local interface network when it can be detected. The scanner limits a range to 4096 addresses to prevent accidental broad scans.

```bash
netguard discover --cidr 10.0.0.0/24 --timeout 0.35 --workers 64 --format json --output hosts.json
```

### `scan`

Scans TCP ports on one host. Ports can be a comma-separated list, ranges, `common`, or `top100`. Use `--banner` for a short, timeout-bounded application banner request.

```bash
netguard scan example.internal --ports common --banner
netguard scan 10.0.0.5 --ports 1-1024 --workers 100 --format csv --output ports.csv
```

### `audit`

Runs a port scan and adds educational exposure findings. Findings indicate that a service is reachable; they are not proof of a vulnerability.

```bash
netguard audit 10.0.0.5 --ports common --format html --output audit.html
```

### `monitor` and `history`

Every scan and audit is stored in SQLite by default at `~/.netguard/netguard.db`.
The database contains the raw JSON report, UTC timestamp, target, open-port inventory,
fingerprints, and a SHA-256 evidence hash. Use `monitor` to compare the current open
ports with the previous stored scan:

```bash
netguard monitor 10.0.0.5 --ports common
netguard history --target 10.0.0.5 --format json
```

Use `--db /path/file.db` for a project-specific database or `--no-store` for an
ephemeral scan. `monitor` reports newly opened and closed TCP ports; an empty change
set is still meaningful because the current evidence hash and timestamp are recorded.

## Output

Without `--output`, results are printed to the terminal. With an output path, JSON, CSV, or HTML is written according to `--format` (or inferred from the file extension). Reports include scan timestamps, target resolution, elapsed time, requested ports, observed states, raw probe errors, open ports, fingerprints, evidence hash, and findings. HTTP fingerprints are taken from live response headers; TLS fingerprints are taken from a live handshake and peer certificate. A `filtered` state means the connection timed out; it must not be interpreted as proof that a port is closed. Findings are reachability-based defensive indicators, not claims that a CVE was exploited or verified.

NETGUARD deliberately does not invent CVE matches from port numbers. Reliable CVE
matching requires a verified product/version or CPE. Future enrichment can be added
without weakening this evidence rule.

## Legal and safety notice

Use NETGUARD-CLI only for systems and networks you are authorized to assess. Keep the worker count and timeout appropriate for the environment. The project is intended for inventory and defensive validation, not exploitation.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall netguard
```
