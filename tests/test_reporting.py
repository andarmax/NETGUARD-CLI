import json
import unittest

from netguard.models import ScanReport
from netguard.reporting import render


class ReportingTests(unittest.TestCase):
    def test_json_is_machine_readable(self):
        report = ScanReport("NETGUARD-CLI", "1.0.0", "scan", "127.0.0.1",
                            "2026-01-01T00:00:00+00:00", 0.1)
        payload = json.loads(render(report, "json"))
        self.assertEqual(payload["target"], "127.0.0.1")

    def test_html_escapes_values(self):
        report = ScanReport("NETGUARD-CLI", "1.0.0", "scan", "<host>",
                            "2026-01-01T00:00:00+00:00", 0.1)
        self.assertIn("&lt;host&gt;", render(report, "html"))


if __name__ == "__main__":
    unittest.main()
