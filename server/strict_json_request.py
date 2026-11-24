"""Strict JSON request-body parsing for the localhost-only synthetic API.

This is generic HTTP input hardening, not an AOW wire-protocol implementation.
"""
import json
import math


class JsonRequestError(ValueError):
    """The HTTP body is not one bounded, unambiguous JSON object."""


_MAX_JSON_INTEGER_DIGITS = 128


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JsonRequestError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value):
    raise JsonRequestError("non-finite JSON number is not allowed")


def _parse_integer(value):
    """Bound integer tokens independently of interpreter conversion settings."""
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > _MAX_JSON_INTEGER_DIGITS:
        raise JsonRequestError("JSON integer exceeds the digit limit")
    try:
        return int(value)
    except ValueError as exc:
        raise JsonRequestError("invalid JSON integer") from exc


def _parse_float(value):
    """Reject valid JSON number syntax that overflows to infinity in Python."""
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise JsonRequestError("invalid JSON number") from exc
    if not math.isfinite(number):
        raise JsonRequestError("non-finite JSON number is not allowed")
    return number


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
    try:
        length = int(raw_length)
    except ValueError as exc:
        # Python may reject extremely long decimal strings before we can
        # compare them with max_bytes. Keep all malformed HTTP lengths inside
        # the parser's documented error type.
        raise JsonRequestError("invalid Content-Length") from exc
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
            parse_int=_parse_integer,
            parse_float=_parse_float,
        )
    except JsonRequestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise JsonRequestError("invalid JSON body") from exc

    if not isinstance(payload, dict):
        raise JsonRequestError("JSON root must be an object")
    return payload
