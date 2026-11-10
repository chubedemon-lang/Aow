import io
import unittest
from email.message import Message

from server.strict_json_request import JsonRequestError, read_json_object


class StrictJsonRequestTests(unittest.TestCase):
    def headers(self, body, *, content_type="application/json", extras=()):
        headers = Message()
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body))
        for name, value in extras:
            headers[name] = value
        return headers

    def parse(self, body, *, content_type="application/json", extras=(), max_bytes=4096):
        return read_json_object(
            self.headers(body, content_type=content_type, extras=extras),
            io.BytesIO(body),
            max_bytes=max_bytes,
        )

    def test_accepts_utf8_json_object(self):
        self.assertEqual(self.parse('{"name":"anh hùng"}'.encode()), {"name": "anh hùng"})

    def test_rejects_duplicate_keys_at_any_depth(self):
        for body in (
            b'{"username":"alice","username":"mallory"}',
            b'{"outer":{"x":1,"x":2}}',
        ):
            with self.subTest(body=body), self.assertRaises(JsonRequestError):
                self.parse(body)

    def test_rejects_non_finite_numbers(self):
        for body in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(body=body), self.assertRaises(JsonRequestError):
                self.parse(body)

    def test_rejects_non_object_roots(self):
        for body in (b'[]', b'null', b'"text"', b'42'):
            with self.subTest(body=body), self.assertRaises(JsonRequestError):
                self.parse(body)

    def test_rejects_non_utf8_and_unsupported_charset(self):
        with self.assertRaises(JsonRequestError):
            self.parse(b'{"name":"\xff"}')
        with self.assertRaises(JsonRequestError):
            self.parse(b'{"name":"x"}', content_type="application/json; charset=iso-8859-1")

    def test_rejects_transfer_encoding_and_compressed_bodies(self):
        with self.assertRaises(JsonRequestError):
            self.parse(b'{"x":1}', extras=(("Transfer-Encoding", "chunked"),))
        with self.assertRaises(JsonRequestError):
            self.parse(b'{"x":1}', extras=(("Content-Encoding", "gzip"),))

    def test_rejects_duplicate_length_and_content_type_headers(self):
        for extras in (
            (("Content-Length", "1"),),
            (("Content-Type", "text/plain"),),
        ):
            with self.subTest(extras=extras), self.assertRaises(JsonRequestError):
                self.parse(b'{"x":1}', extras=extras)

    def test_rejects_invalid_or_oversized_content_length(self):
        for length in ("+7", "-1", "７", "0", "99999"):
            headers = Message()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = length
            with self.subTest(length=length), self.assertRaises(JsonRequestError):
                read_json_object(headers, io.BytesIO(b'{"x":1}'), max_bytes=64)

    def test_rejects_truncated_body(self):
        headers = self.headers(b'{"x":1}')
        with self.assertRaises(JsonRequestError):
            read_json_object(headers, io.BytesIO(b'{"x":'), max_bytes=64)

    def test_rejects_invalid_maximum(self):
        headers = self.headers(b'{"x":1}')
        for maximum in (True, 0, -1, 1.5):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                read_json_object(headers, io.BytesIO(b'{"x":1}'), max_bytes=maximum)


if __name__ == "__main__":
    unittest.main()
