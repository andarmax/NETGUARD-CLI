import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .models import HostResult

_DISCOVERY_PORTS = (22, 80, 443, 445, 3389)


def local_cidr() -> str:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 80))
        address = probe.getsockname()[0]
        probe.close()
        return str(ipaddress.ip_network(f"{address}/24", strict=False))
    except OSError:
        return "192.168.1.0/24"


def arp_cache() -> set:
    addresses = set()
    try:
        with open("/proc/net/arp", encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r"^\\s*(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+", line)
                if match:
                    addresses.add(match.group(1))
    except (OSError, UnicodeError):
        pass
    return addresses


def _tcp_probe(address: str, timeout: float) -> HostResult:
    started = time.monotonic()
    for port in _DISCOVERY_PORTS:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                latency = round((time.monotonic() - started) * 1000, 2)
                try:
                    hostname = socket.gethostbyaddr(address)[0]
                except OSError:
                    hostname = None
                return HostResult(address, hostname, "tcp", True, latency)
        except OSError:
            continue
    return HostResult(address, method="tcp", responsive=False)


def discover(cidr: Optional[str] = None, timeout: float = 0.35,
             workers: int = 64) -> List[HostResult]:
    network = ipaddress.ip_network(cidr or local_cidr(), strict=False)
    if network.version != 4:
        raise ValueError("discovery currently supports IPv4 CIDR ranges")
    if network.num_addresses > 4096:
        raise ValueError("discovery range cannot exceed 4096 addresses")
    if not 0.05 <= timeout <= 10:
        raise ValueError("timeout must be between 0.05 and 10 seconds")
    addresses = {str(address) for address in network.hosts()}
    cached = arp_cache() & addresses
    results = []
    for address in sorted(cached, key=lambda value: tuple(map(int, value.split(".")))):
        results.append(HostResult(address, method="arp", responsive=True))
    remaining = addresses - cached
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), 256))) as executor:
        futures = [executor.submit(_tcp_probe, address, timeout) for address in remaining]
        for future in as_completed(futures):
            result = future.result()
            if result.responsive:
                results.append(result)
    return sorted(results, key=lambda result: tuple(map(int, result.address.split("."))))
