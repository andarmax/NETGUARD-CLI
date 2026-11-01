COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
    5432, 5900, 6379, 6443, 8000, 8080, 8443, 9200, 27017,
)

TOP100_PORTS = tuple(sorted(set(COMMON_PORTS + tuple(range(1, 101)))))

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 6443: "kubernetes-api", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


def parse_ports(value: str):
    value = value.strip().lower()
    if value == "common":
        return list(COMMON_PORTS)
    if value in {"top100", "top-100"}:
        return list(TOP100_PORTS)
    result = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"invalid port range: {item}")
            result.update(range(start, end + 1))
        else:
            result.add(int(item))
    ports = sorted(result)
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    if len(ports) > 4096:
        raise ValueError("at most 4096 ports may be scanned at once")
    return ports


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, "unknown")
