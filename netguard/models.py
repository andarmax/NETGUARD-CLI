from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HostResult:
    address: str
    hostname: Optional[str] = None
    method: str = "tcp"
    responsive: bool = False
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = "unknown"
    product: Optional[str] = None
    banner: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class Finding:
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    evidence: str
    recommendation: str


@dataclass
class ScanReport:
    tool: str
    version: str
    scan_type: str
    target: str
    started_at: str
    duration_seconds: float
    ports: List[PortResult] = field(default_factory=list)
    hosts: List[HostResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
