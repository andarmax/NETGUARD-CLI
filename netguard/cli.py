import argparse
import ipaddress
import socket
import time
from datetime import datetime, timezone

from . import __version__
from .discovery import discover
from .findings import map_findings
from .models import ScanReport
from .ports import parse_ports
from .reporting import write_report
from .scanner import scan_ports


def _common_arguments(parser):
    parser.add_argument("--timeout", type=float, default=0.8, help="per-connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=64, help="maximum concurrent probes (1-256)")
    parser.add_argument("--format", choices=("auto", "json", "csv", "html"), default="auto")
    parser.add_argument("--output", help="report path; stdout is used when omitted")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="Authorized network exposure auditing (TCP connect scans only).",
        epilog="Scan only hosts and networks you own or are explicitly authorized to assess.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    discover_parser = subparsers.add_parser("discover", help="discover responsive IPv4 hosts")
    discover_parser.add_argument("--cidr", help="IPv4 CIDR range; defaults to the local /24")
    discover_parser.add_argument("--timeout", type=float, default=0.35)
    discover_parser.add_argument("--workers", type=int, default=64)
    discover_parser.add_argument("--format", choices=("auto", "json", "csv", "html"), default="json")
    discover_parser.add_argument("--output")
    scan_parser = subparsers.add_parser("scan", help="scan TCP ports on one host")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--ports", default="common")
    scan_parser.add_argument("--banner", action="store_true", help="collect a short service banner")
    _common_arguments(scan_parser)
    audit_parser = subparsers.add_parser("audit", help="scan and map educational exposure findings")
    audit_parser.add_argument("target")
    audit_parser.add_argument("--ports", default="common")
    audit_parser.add_argument("--banner", action="store_true")
    _common_arguments(audit_parser)
    return parser


def _validate_target(target):
    if not target or len(target) > 253 or any(char.isspace() for char in target):
        raise ValueError("target must be a hostname or IP address without whitespace")
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        addresses = {
            entry[4][0]
            for entry in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        }
        if not addresses:
            raise ValueError(f"target did not resolve: {target}")
        return sorted(addresses)


def _make_report(command, target, ports=None, hosts=None, findings=None, started=None):
    return ScanReport(
        tool="NETGUARD-CLI",
        version=__version__,
        scan_type=command,
        target=target,
        started_at=started or datetime.now(timezone.utc).isoformat(),
        duration_seconds=round(time.monotonic() - _make_report.started, 3),
        ports=ports or [],
        hosts=hosts or [],
        findings=findings or [],
    )


def _run_scan(args, audit=False):
    resolved_addresses = _validate_target(args.target)
    ports = parse_ports(args.ports)
    started_at = datetime.now(timezone.utc).isoformat()
    _make_report.started = time.monotonic()
    results = scan_ports(args.target, ports, args.timeout, args.workers, args.banner)
    report = _make_report("audit" if audit else "scan", args.target, ports=results,
                          findings=map_findings(results) if audit else [], started=started_at)
    report.resolved_addresses = resolved_addresses
    report.ports_requested = ports
    write_report(report, args.format, args.output)


def _run_discover(args):
    _make_report.started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    hosts = discover(args.cidr, args.timeout, args.workers)
    target = args.cidr or "local network"
    report = _make_report("discover", target, hosts=hosts, started=started_at)
    write_report(report, args.format, args.output)


def interactive():
    print("NETGUARD-CLI - authorized network auditing only")
    print("1) Discover LAN hosts  2) Scan a host  3) Audit a host  4) Exit")
    choice = input("Select an option: ").strip()
    if choice == "1":
        cidr = input("CIDR (blank for local /24): ").strip() or None
        timeout = float(input("Timeout seconds [0.35]: ").strip() or "0.35")
        _run_discover(argparse.Namespace(cidr=cidr, timeout=timeout, workers=64, format="json", output=None))
    elif choice in {"2", "3"}:
        target = input("Target hostname/IP: ").strip()
        ports = input("Ports [common]: ").strip() or "common"
        banner = input("Collect banners? [y/N]: ").strip().lower() == "y"
        args = argparse.Namespace(target=target, ports=ports, banner=banner, timeout=0.8,
                                  workers=64, format="json", output=None)
        _run_scan(args, audit=choice == "3")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.command:
            return interactive()
        if args.command == "discover":
            return _run_discover(args)
        return _run_scan(args, audit=args.command == "audit")
    except (ValueError, OSError, socket.gaierror) as exc:
        parser.error(str(exc))
