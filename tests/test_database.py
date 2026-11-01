import json
import tempfile
import unittest

from netguard.database import Database, evidence_hash
from netguard.models import PortResult, ScanReport


class DatabaseTests(unittest.TestCase):
    def test_persists_report_history_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(f"{directory}/evidence.db")
            report = ScanReport(
                "NETGUARD-CLI", "1.0.0", "scan", "127.0.0.1",
                "2026-01-01T00:00:00+00:00", 0.1,
                resolved_addresses=["127.0.0.1"],
                ports=[PortResult(80, state="open", service="http")],
            )
            digest = database.save_report(report)
            self.assertEqual(digest, evidence_hash(report))
            self.assertEqual(database.history("127.0.0.1")[0]["evidence_sha256"], digest)
            self.assertEqual(database.latest_report("127.0.0.1")["ports"][0]["port"], 80)
            database.close()


if __name__ == "__main__":
    unittest.main()
