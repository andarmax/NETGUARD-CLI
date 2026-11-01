import re
import socket
import ssl
import hashlib
from typing import Optional, Tuple

from .models import PortResult


def _http_fingerprint(host: str, port: int, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            data = sock.recv(2048).decode("iso-8859-1", errors="replace")
        server = re.search(r"(?im)^server:\s*(.+)$", data)
        powered = re.search(r"(?im)^x-powered-by:\s*(.+)$", data)
        parts = [value.group(1).strip() for value in (server, powered) if value]
        return (", ".join(parts) or "HTTP", "headers")
    except (OSError, UnicodeError):
        return None, None


def _tls_fingerprint(host: str, port: int, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                certificate_der = tls.getpeercert(binary_form=True)
                certificate = tls.getpeercert()
                subject = certificate.get("subject", ())
                common_name = next(
                    (value for group in subject for key, value in group if key == "commonName"),
                    None,
                )
                cipher = tls.cipher()
                certificate_hash = hashlib.sha256(certificate_der).hexdigest()
                detail = f"TLS {tls.version()}, cert-sha256={certificate_hash}"
                if cipher:
                    detail += f", {cipher[0]}"
                if common_name:
                    detail += f", CN={common_name}"
                return detail, "certificate"
    except (OSError, ssl.SSLError):
        return None, None


def fingerprint_port(host: str, result: PortResult, timeout: float,
                     generic_http: bool = False) -> PortResult:
    if result.state != "open":
        return result
    if result.port == 443:
        detail, source = _tls_fingerprint(host, result.port, timeout)
    elif result.port in {80, 8000, 8080, 8443} or generic_http:
        detail, source = _http_fingerprint(host, result.port, timeout)
    else:
        detail, source = None, None
    if detail:
        result.fingerprint = detail
        result.fingerprint_confidence = 0.9 if source == "certificate" else 0.8
        result.product = detail.split(",", 1)[0]
    return result
