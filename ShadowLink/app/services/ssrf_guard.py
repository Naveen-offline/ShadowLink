"""Stable SSRF-guard API used by the DNS, redirect and scan modules.

All real rules live in `net_guard` (single source of truth); this module only adapts
them to the names the callers use, so the two can never drift apart.
"""
from __future__ import annotations

import socket

from . import net_guard
from .net_guard import BlockedDestination, ResolutionError  # noqa: F401  (re-exported)
from .url_validator import _canonical_ip


def ip_is_public(ip) -> bool:
    """True only for globally routable, non-reserved unicast addresses."""
    return net_guard.is_public_ip(ip)


def hostname_is_blocked(host: str) -> bool:
    return net_guard.is_blocked_hostname(host)


def check_host_literal(host: str) -> None:
    """Reject internal hostnames and non-public IP literals (including obfuscated
    decimal/hex/octal forms) without any network I/O."""
    host = (host or "").strip().strip("[]")
    canonical = _canonical_ip(host)
    if canonical is not None:
        if not net_guard.is_public_ip(canonical):
            raise BlockedDestination("Non-public IP addresses are not allowed.")
        return
    if net_guard.is_blocked_hostname(host):
        raise BlockedDestination("Internal hostnames are not allowed.")


def resolve_public_ips(host: str, port: int = 443, resolver=None) -> list[str]:
    """Resolve `host`; succeed only if EVERY returned address is public.

    The caller must then connect to one of the returned IP literals (pinning), which
    removes the check-then-connect gap that DNS rebinding relies on."""
    check_host_literal(host)
    canonical = _canonical_ip(host.strip("[]"))
    if canonical is not None:
        return [canonical]
    resolver = resolver or socket.getaddrinfo
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise BlockedDestination("Hostname could not be resolved.") from exc
    ips: list[str] = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if not net_guard.is_public_ip(ip):
            raise BlockedDestination("Hostname resolves to a non-public address.")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise BlockedDestination("Hostname did not resolve.")
    return ips
