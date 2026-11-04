import unittest
from tools.protocol_candidates import scan_bytes

class ProtocolCandidateTests(unittest.TestCase):
    def test_url_and_host(self):
        result = scan_bytes(b"Visit https://example.com/game and api.example.org:443")
        self.assertIn(("url", "https://example.com/game"), result)
        self.assertIn(("host", "api.example.org:443"), result)

    def test_sensitive_url_suppressed(self):
        result = scan_bytes(b"https://example.com/?token=abc123")
        self.assertNotIn(("url", "https://example.com/?token=abc123"), result)

    def test_non_ascii_ignored(self):
        self.assertEqual(scan_bytes(b"\x00\xff\xfe"), [])

if __name__ == "__main__":
    unittest.main()
