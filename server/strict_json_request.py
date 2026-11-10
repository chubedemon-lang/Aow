"""Strict JSON request-body parsing for the localhost-only synthetic API.

This is generic HTTP input hardening, not an AOW wire-protocol implementation.
"""
import json


class JsonRequestError(ValueError):
    """The HTTP body is not one bounded, unambiguous JSON object."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JsonRequestError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value):
    raise JsonRequestError("non-finite JSON number is not allowed")


def read_json_object(headers, stream, *, max_bytes=4096):
    """Read exactly one bounded UTF-8 JSON object from an HTTP request.

    Reject ambiguous transfer framing, duplicate length/type headers,
    unsupported content encodings, duplicate JSON keys, non-finite numbers,
    invalid UTF-8, truncated bodies, and non-object JSON roots.
    """
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    if headers.get_all("Transfer-Encoding"):
        raise JsonRequestError("transfer encoding is not supported")

    content_types = headers.get_all("Content-Type") or []
    if len(content_types) != 1:
        raise JsonRequestError("exactly one Content-Type is required")
    if headers.get_content_type().lower() != "application/json":
        raise JsonRequestError("application/json is required")
    charset = headers.get_content_charset()
    if charset is not None and charset.lower() != "utf-8":
        raise JsonRequestError("only UTF-8 JSON is supported")

    content_encodings = headers.get_all("Content-Encoding") or []
    if len(content_encodings) > 1 or any(
        value.strip().lower() != "identity" for value in content_encodings
    ):
        raise JsonRequestError("unsupported content encoding")

    lengths = headers.get_all("Content-Length") or []
    if len(lengths) != 1:
        raise JsonRequestError("exactly one Content-Length is required")
    raw_length = lengths[0].strip()
    if not raw_length or not raw_length.isascii() or not raw_length.isdecimal():
        raise JsonRequestError("invalid Content-Length")
    length = int(raw_length)
    if not 1 <= length <= max_bytes:
        raise JsonRequestError("request body size is outside the allowed range")

    body = stream.read(length)
    if not isinstance(body, bytes) or len(body) != length:
        raise JsonRequestError("truncated request body")
    try:
        text = body.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise JsonRequestError("invalid JSON body") from exc

    if not isinstance(payload, dict):
        raise JsonRequestError("JSON root must be an object")
    return payload
