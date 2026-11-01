import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanReport


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    address TEXT PRIMARY KEY,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    open_ports TEXT NOT NULL,
    fingerprint TEXT
);
"""


def evidence_hash(report: ScanReport) -> str:
    payload = report.to_dict()
    payload.pop("evidence_sha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class Database:
    def __init__(self, path: str):
        self.path = str(Path(path).expanduser())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def save_report(self, report: ScanReport) -> str:
        report.evidence_sha256 = evidence_hash(report)
        serialized = json.dumps(report.to_dict(), sort_keys=True)
        self.connection.execute(
            """INSERT INTO scans
               (started_at, target, scan_type, duration_seconds, evidence_sha256, report_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (report.started_at, report.target, report.scan_type, report.duration_seconds,
             report.evidence_sha256, serialized),
        )
        now = datetime.now(timezone.utc).isoformat()
        for host in report.hosts or [{"address": address, "hostname": None} for address in report.resolved_addresses]:
            open_ports = [port.port for port in report.ports if port.state == "open"]
            self.connection.execute(
                """INSERT INTO assets(address, hostname, first_seen, last_seen, open_ports, fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(address) DO UPDATE SET
                   hostname=excluded.hostname, last_seen=excluded.last_seen,
                   open_ports=excluded.open_ports, fingerprint=excluded.fingerprint""",
                (host["address"] if isinstance(host, dict) else host.address,
                 host.get("hostname") if isinstance(host, dict) else host.hostname,
                 now, now, json.dumps(open_ports),
                 json.dumps([p.fingerprint for p in report.ports if p.fingerprint])),
            )
        self.connection.commit()
        return report.evidence_sha256

    def history(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        query = "SELECT id, started_at, target, scan_type, duration_seconds, evidence_sha256 FROM scans"
        params = []
        if target:
            query += " WHERE target = ?"
            params.append(target)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        return [dict(row) for row in self.connection.execute(query, params)]

    def latest_report(self, target: str) -> Optional[Dict[str, Any]]:
        row = self.connection.execute(
            "SELECT report_json FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def close(self):
        self.connection.close()
