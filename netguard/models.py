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
    fingerprint: Optional[str] = None
    fingerprint_confidence: Optional[float] = None
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
    resolved_addresses: List[str] = field(default_factory=list)
    probe: str = "TCP connect"
    ports_requested: List[int] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    hosts: List[HostResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
