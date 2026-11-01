import unittest

from netguard.ports import parse_ports


class PortParsingTests(unittest.TestCase):
    def test_named_sets_and_ranges(self):
        self.assertIn(22, parse_ports("common"))
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("10-1")


if __name__ == "__main__":
    unittest.main()
