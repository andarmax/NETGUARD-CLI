# NETGUARD-CLI

> **Evidence-first network visibility for authorized environments.**

NETGUARD-CLI is a lightweight, dependency-free Python tool for discovering LAN assets, measuring real TCP exposure, fingerprinting reachable services, and tracking changes over time.

It is designed to answer practical questions:

- Perangkat apa saja yang merespons di jaringan saya?
- Port TCP apa yang benar-benar terbuka, tertutup, atau ter-filter?
- Service apa yang terlihat dari response live?
- Apa yang berubah sejak scan sebelumnya?
- Di mana bukti mentah dan hash laporan saya?

> **Important:** Scan only systems and networks that you own or are explicitly authorized to assess. NETGUARD does not exploit vulnerabilities, bypass authentication, evade controls, or perform flooding scans.

## Why NETGUARD?

Many scanners produce a list of ports and stop there. NETGUARD focuses on **reproducible evidence**:

| Capability | What you get |
|---|---|
| LAN discovery | Responsive IPv4 hosts from ARP cache and bounded TCP probes |
| TCP scanning | Real connection results with `open`, `closed`, `filtered`, and `error` states |
| Service evidence | Live HTTP headers and TLS handshake/certificate fingerprints |
| History | SQLite records containing raw reports, assets, timestamps, and evidence hashes |
| Monitoring | Newly opened and closed ports compared with the previous scan |
| Reporting | JSON, CSV, and self-contained HTML reports |
| Defensive mapping | Educational exposure findings with CVSS v3.1 context and remediation |

NETGUARD intentionally does **not** claim a CVE from a port number alone. Reliable vulnerability matching requires verified product/version evidence or a CPE.

## Quick start

### Requirements

- Python **3.9+**
- No third-party runtime dependencies
- Permission to assess the target network

### Install

```bash
git clone https://github.com/andarmax/NETGUARD-CLI.git
cd NETGUARD-CLI
python -m pip install .
```

Or run directly from the repository:

```bash
python -m netguard --help
```

### First scan

```bash
# Discover responsive hosts in a private LAN range
netguard discover --cidr 192.168.1.0/24 --format html --output hosts.html

# Scan common TCP ports and collect a short live banner
netguard scan 192.168.1.10 --ports common --banner --format html --output report.html

# Add defensive exposure mapping
netguard audit 192.168.1.10 --ports 22,80,443,445,3389 --output audit.json
```

Every scan is stored by default in:

```text
~/.netguard/netguard.db
```

## Commands at a glance

### Discover assets

```bash
netguard discover \
  --cidr 10.0.0.0/24 \
  --timeout 0.35 \
  --workers 64 \
  --format json \
  --output hosts.json
```

Discovery uses the local ARP cache where available and bounded TCP probes against common service ports. Ranges larger than 4096 IPv4 addresses are rejected to prevent accidental broad scans.

### Scan TCP exposure

```bash
netguard scan example.internal --ports common --banner
netguard scan 10.0.0.5 --ports 1-1024 --workers 100 --format csv --output ports.csv
netguard scan 10.0.0.5 --ports 22,80,443,8000-8010 --timeout 1.2
```

Port expressions support:

- `common` — curated common service ports
- `top100` — common ports plus ports 1–100
- `22,80,443` — comma-separated ports
- `8000-8080` — inclusive ranges

### Audit exposure

```bash
netguard audit 10.0.0.5 \
  --ports common \
  --banner \
  --format html \
  --output audit.html
```

Audit findings are **reachability indicators**, not proof that a vulnerability was exploited or verified.

### Monitor changes

```bash
netguard monitor 10.0.0.5 --ports common
netguard monitor 10.0.0.5 --ports common --db ./evidence.db
```

The monitor compares the current scan with the previous stored scan and reports:

- newly opened TCP ports;
- ports no longer observed as open;
- the current scan timestamp;
- the current SHA-256 evidence hash.

### Review history

```bash
netguard history --target 10.0.0.5 --format json
netguard history --limit 50 --db ./evidence.db
```

Use `--no-store` for an ephemeral scan:

```bash
netguard scan 10.0.0.5 --ports common --no-store
```

## Understanding the evidence

Each report records:

- original target and resolved IP addresses;
- UTC start time and elapsed duration;
- requested ports and probe method;
- observed connection state and latency;
- raw connection errors;
- service name and live fingerprint when available;
- fingerprint confidence;
- educational findings and recommendations;
- SHA-256 hash of the canonical report content.

### Port states

| State | Meaning |
|---|---|
| `open` | TCP connection was accepted |
| `closed` | Target actively refused the connection |
| `filtered` | Probe timed out; a firewall or filtering device may be involved |
| `error` | Another socket or network error occurred |

`filtered` must not be interpreted as `closed`.

### Fingerprinting

- HTTP fingerprints are extracted from live response headers.
- HTTPS fingerprints use a live TLS handshake and SHA-256 hash of the peer certificate where possible. Certificate verification is intentionally disabled for inventory of self-signed services; the result is evidence of what was presented, not proof of trusted identity.
- Fingerprints include a confidence score and are never presented as certainty when evidence is incomplete.

Example evidence fragment:

```json
{
  "port": 18080,
  "state": "open",
  "product": "SimpleHTTP/0.6 Python/3.12.3",
  "fingerprint": "SimpleHTTP/0.6 Python/3.12.3",
  "fingerprint_confidence": 0.8,
  "latency_ms": 1.01
}
```

## Output formats

### JSON

Best for automation, archiving, and evidence processing.

```bash
netguard scan 127.0.0.1 --ports 22,80 --format json --output scan.json
```

### CSV

Best for spreadsheets and quick operational review.

```bash
netguard scan 127.0.0.1 --ports common --format csv --output scan.csv
```

CSV fields derived from network responses are escaped against spreadsheet formula
injection. Treat reports as potentially sensitive because they may contain hostnames,
service banners, and certificate metadata.

### HTML

Best for sharing a self-contained report with a team.

```bash
netguard audit 127.0.0.1 --ports common --format html --output audit.html
```

## Data model

The SQLite database stores:

- scan history and raw JSON reports;
- asset address and hostname observations;
- open-port inventory;
- observed fingerprints;
- report evidence hashes.

This makes results comparable across time instead of being a one-time terminal output.

## Interactive mode

Run without a subcommand for a guided menu:

```bash
python -m netguard
```

For automation and repeatability, prefer explicit subcommands.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q netguard
python -m pip install .
```

The test suite covers port parsing, finding rules, report rendering, evidence metadata, and SQLite persistence.

GitHub Actions runs the unit tests, package compilation, and whitespace checks for
pushes and pull requests.

## Roadmap

Planned improvements that preserve the evidence-first design:

1. richer SSH/SMB/TLS protocol fingerprints;
2. verified product/version and CPE enrichment;
3. optional NVD/OSV advisory cache with source links;
4. scheduled monitoring and webhook notifications;
5. IPv6 discovery and a lightweight local dashboard;
6. signed releases and reproducible CI artifacts.

## License and responsible use

Use NETGUARD-CLI only for defensive work on systems you own or are authorized to test. Keep timeouts, worker counts, and scan ranges appropriate for the environment. The project is intended for inventory, exposure validation, and education—not exploitation.
