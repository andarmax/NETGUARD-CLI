import csv
import html
import json
import os
import sys
from typing import Any, Dict

from .models import ScanReport


def _spreadsheet_safe(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def _payload(report: ScanReport) -> Dict[str, Any]:
    return report.to_dict()


def infer_format(output: str, requested: str) -> str:
    if requested != "auto":
        return requested
    extension = os.path.splitext(output)[1].lower()
    return {".json": "json", ".csv": "csv", ".html": "html"}.get(extension, "json")


def render(report: ScanReport, format_name: str) -> str:
    payload = _payload(report)
    if format_name == "json":
        return json.dumps(payload, indent=2)
    if format_name == "csv":
        if payload["scan_type"] == "discover":
            rows = [["address", "hostname", "method", "responsive", "latency_ms", "error"]]
            rows.extend([
                [_spreadsheet_safe(host["address"]), _spreadsheet_safe(host["hostname"] or ""),
                 _spreadsheet_safe(host["method"]), host["responsive"],
                 host["latency_ms"] or "", _spreadsheet_safe(host["error"] or "")]
                for host in payload["hosts"]
            ])
            from io import StringIO
            stream = StringIO()
            csv.writer(stream).writerows(rows)
            return stream.getvalue().rstrip()
        rows = [["port", "protocol", "state", "service", "product", "banner",
                 "fingerprint", "fingerprint_confidence", "latency_ms", "error"]]
        rows.extend([
            [p["port"], _spreadsheet_safe(p["protocol"]), _spreadsheet_safe(p["state"]),
             _spreadsheet_safe(p["service"]), _spreadsheet_safe(p["product"] or ""),
             _spreadsheet_safe(p["banner"] or ""), _spreadsheet_safe(p["fingerprint"] or ""),
             p["fingerprint_confidence"] or "", p["latency_ms"] or "",
             _spreadsheet_safe(p["error"] or "")]
            for p in payload["ports"]
        ])
        from io import StringIO
        stream = StringIO()
        csv.writer(stream).writerows(rows)
        return stream.getvalue().rstrip()
    if format_name == "html":
        port_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(p[key] or ''))}</td>"
                              for key in ("port", "protocol", "state", "service", "product",
                                          "fingerprint", "fingerprint_confidence", "banner",
                                          "latency_ms")) + "</tr>"
            for p in payload["ports"]
        )
        host_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(host[key] or ''))}</td>"
                              for key in ("address", "hostname", "method", "responsive", "latency_ms")) + "</tr>"
            for host in payload["hosts"]
        ) or "<tr><td colspan='5'>No responsive hosts.</td></tr>"
        finding_rows = "".join(
            f"<tr><td>{html.escape(f['severity'])}</td><td>{f['cvss_score']:.1f}</td>"
            f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['evidence'])}</td>"
            f"<td>{html.escape(f['recommendation'])}</td></tr>"
            for f in payload["findings"]
        ) or "<tr><td colspan='5'>No mapped exposures.</td></tr>"
        return f"""<!doctype html><meta charset="utf-8"><title>NETGUARD report</title>
<style>body{{font:14px system-ui;margin:2rem;color:#17202a}}table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}td,th{{border:1px solid #ccd;padding:.45rem;text-align:left}}th{{background:#eef}}code{{white-space:pre-wrap}}</style>
<h1>NETGUARD-CLI audit report</h1><p><b>Target:</b> {html.escape(payload['target'])}
<br><b>Resolved:</b> {html.escape(", ".join(payload['resolved_addresses']) or "not applicable")}
<br><b>Probe:</b> {html.escape(payload['probe'])}
<br><b>Started:</b> {html.escape(payload['started_at'])}
<br><b>Duration:</b> {payload['duration_seconds']:.2f}s</p>
<h2>Hosts</h2><table><tr><th>Address</th><th>Hostname</th><th>Method</th><th>Responsive</th><th>Latency ms</th></tr>{host_rows}</table>
<h2>Ports</h2><table><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Fingerprint</th><th>Confidence</th><th>Banner</th><th>Latency ms</th></tr>{port_rows or "<tr><td colspan='9'>No ports scanned.</td></tr>"}</table>
<h2>Educational exposure mapping</h2><table><tr><th>Severity</th><th>CVSS</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>{finding_rows}</table>
<p><small>Reachability is evidence of exposure, not proof of a vulnerability. Scan only authorized systems.</small></p>"""
    raise ValueError(f"unsupported output format: {format_name}")


def write_report(report: ScanReport, format_name: str, output: str = None) -> None:
    content = render(report, infer_format(output, format_name) if output else format_name)
    if output:
        with open(output, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
    else:
        sys.stdout.write(content + ("" if content.endswith("\n") else "\n"))
