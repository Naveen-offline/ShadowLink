"""Destination-IP enforcement shared by every module that opens a socket to an
untrusted host (TLS inspection and redirect analysis).

Design rules
* A hostname is never trusted on its own: it is resolved here, EVERY returned
  address must be a public, globally routable IP, and callers must then connect
  to one of those validated IP literals (pinning). This removes the
  time-of-check/time-of-use gap that DNS rebinding relies on.
* Mixed answers (one public + one private record) are rejected outright.
"""
from __future__ import annotations

import ipaddress
import socket

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "kubernetes.default",
}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".intranet", ".corp", ".localdomain")

# Cloud metadata endpoints (also covered by link-local / CGNAT checks; listed explicitly).
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class BlockedDestination(Exception):
    """Raised when a host or IP is not an approved public destination."""


class ResolutionError(Exception):
    """Raised when a hostname cannot be resolved."""


def _unwrap(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def is_public_ip(value) -> bool:
    try:
        ip = _unwrap(ipaddress.ip_address(value) if not hasattr(value, "version") else value)
    except ValueError:
        return False
    if ip in METADATA_IPS:
        return False
    return bool(
        ip.is_global
        and not ip.is_multicast
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def is_blocked_hostname(host: str) -> bool:
    h = host.lower().rstrip(".")
    return h in BLOCKED_HOSTNAMES or h.endswith(BLOCKED_SUFFIXES) or "." not in h and not _is_ip(h)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _getaddrinfo(host, port):  # indirection so tests can mock DNS
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve `host` and return validated public IP strings.

    Raises BlockedDestination if the host or ANY resolved address is non-public,
    ResolutionError if it cannot be resolved.
    """
    host = host.strip("[]")
    if _is_ip(host):
        if not is_public_ip(host):
            raise BlockedDestination("IP address is not a public destination")
        return [host]
    if is_blocked_hostname(host):
        raise BlockedDestination("Hostname is not an approved public destination")
    try:
        infos = _getaddrinfo(host, port)
    except socket.gaierror as exc:
        raise ResolutionError("Hostname could not be resolved") from exc
    except OSError as exc:
        raise ResolutionError("DNS lookup failed") from exc
    ips = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise ResolutionError("No addresses returned")
    for addr in ips:
        if not is_public_ip(addr):
            raise BlockedDestination("Hostname resolves to a non-public address")
    return ips
