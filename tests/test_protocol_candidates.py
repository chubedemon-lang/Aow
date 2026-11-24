import unittest
from tools.protocol_candidates import scan_bytes

class ProtocolCandidateTests(unittest.TestCase):
    def test_url_and_host(self):
        result = scan_bytes(b"Visit https://example.com/game and api.example.org:443")
        self.assertIn(("origin", "https://example.com"), result)
        self.assertIn(("host", "api.example.org:443"), result)

    def test_sensitive_url_suppressed(self):
        result = scan_bytes(b"https://example.com/?token=abc123")
        self.assertEqual(result, [])

    def test_origin_only_no_private_paths(self):
        data = b"https://EXAMPLE.com/users/alice/private123?x=123 https://example.com/other"
        result = scan_bytes(data)
        self.assertEqual(result, [("origin", "https://example.com"), ("origin", "https://example.com")])
        self.assertNotIn("alice", str(result))
        self.assertNotIn("private123", str(result))

    def test_userinfo_and_sensitive_query_suppressed(self):
        result = scan_bytes(b"https://user:pass@example.com/a https://example.com/a?api_key=abc")
        self.assertEqual(result, [])

    def test_non_ascii_ignored(self):
        self.assertEqual(scan_bytes(b"\x00\xff\xfe"), [])

if __name__ == "__main__":
    unittest.main()
