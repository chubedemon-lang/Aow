"""Runtime guards for the deliberately localhost-only synthetic API.

These checks do not make the prototype production-ready or APK-compatible.
"""
import ipaddress


class RuntimeSafetyError(ValueError):
    """The synthetic API configuration would violate its local-only boundary."""


def validate_loopback_bind(host, port):
    """Return a normalized IPv4 loopback bind tuple or fail closed.

    Hostnames are deliberately rejected: resolving a name at a later time could
    produce a non-loopback address. The current HTTP server is IPv4-only.
    """
    if not isinstance(host, str) or not host or host.strip() != host:
        raise RuntimeSafetyError("host must be a literal IPv4 loopback address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeSafetyError(
            "host must be a literal IPv4 loopback address"
        ) from exc
    if address.version != 4 or not address.is_loopback:
        raise RuntimeSafetyError("synthetic API may bind only to IPv4 loopback")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeSafetyError("port must be an integer from 1 to 65535")
    return str(address), port
