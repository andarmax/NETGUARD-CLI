import unittest

from netguard.findings import map_findings
from netguard.models import PortResult


class FindingTests(unittest.TestCase):
    def test_only_open_risky_ports_are_mapped(self):
        findings = map_findings([
            PortResult(23, state="open", service="telnet"),
            PortResult(80, state="open", service="http"),
            PortResult(445, state="closed", service="smb"),
        ])
        self.assertEqual([finding.title for finding in findings], ["Telnet service exposed"])
        self.assertEqual(findings[0].cvss_score, 7.4)


if __name__ == "__main__":
    unittest.main()
