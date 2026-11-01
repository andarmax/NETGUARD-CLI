import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List

from .models import PortResult
from .ports import service_name


def _clean_banner(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\x00", "").strip()[:256]


def _probe(host: str, port: int, timeout: float, grab_banner: bool) -> PortResult:
    started = time.monotonic()
    result = PortResult(port=port, service=service_name(port))
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.state = "open"
            result.latency_ms = round((time.monotonic() - started) * 1000, 2)
            if grab_banner:
                sock.settimeout(timeout)
                if port in {80, 443, 8000, 8080, 8443}:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                try:
                    result.banner = _clean_banner(sock.recv(512))
                except socket.timeout:
                    pass
    except socket.timeout:
        result.error = "timeout"
    except ConnectionRefusedError:
        result.error = "refused"
    except OSError as exc:
        result.error = str(exc)
    return result


def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.8,
               workers: int = 64, grab_banner: bool = False) -> List[PortResult]:
    if not host.strip():
        raise ValueError("target host cannot be empty")
    if not 0.05 <= timeout <= 30:
        raise ValueError("timeout must be between 0.05 and 30 seconds")
    workers = max(1, min(int(workers), 256))
    port_list = list(ports)
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(port_list)))) as executor:
        futures = {executor.submit(_probe, host, port, timeout, grab_banner): port for port in port_list}
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda result: result.port)
