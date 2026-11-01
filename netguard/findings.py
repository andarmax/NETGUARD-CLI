from typing import List

from .models import Finding, PortResult

_RULES = {
    21: ("FTP service exposed", "MEDIUM", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "Restrict FTP to trusted networks, prefer SFTP/FTPS, and disable anonymous access."),
    23: ("Telnet service exposed", "HIGH", 7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "Disable Telnet and use SSH with modern authentication and access controls."),
    445: ("SMB service exposed", "HIGH", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Restrict SMB to trusted segments, require signing where appropriate, and keep systems patched."),
    3389: ("RDP service exposed", "HIGH", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
           "Place RDP behind a VPN or gateway, enforce MFA, and restrict source addresses."),
    2375: ("Unauthenticated Docker API exposure", "CRITICAL", 9.8,
           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
           "Never expose the unauthenticated Docker API; use TLS and firewall rules."),
    6379: ("Redis service exposed", "HIGH", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
           "Bind Redis to private interfaces, require authentication, and restrict network access."),
    9200: ("Elasticsearch service exposed", "HIGH", 8.1,
           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
           "Require authentication, disable unnecessary APIs, and restrict access by network policy."),
    27017: ("MongoDB service exposed", "HIGH", 8.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "Enable authentication and TLS, bind to trusted interfaces, and firewall the port."),
}


def map_findings(ports: List[PortResult]) -> List[Finding]:
    findings = []
    for result in ports:
        rule = _RULES.get(result.port)
        if result.state == "open" and rule:
            title, severity, score, vector, recommendation = rule
            findings.append(Finding(
                title=title,
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                evidence=f"TCP/{result.port} ({result.service}) accepted a connection",
                recommendation=recommendation,
            ))
    return sorted(findings, key=lambda finding: (-finding.cvss_score, finding.title))
