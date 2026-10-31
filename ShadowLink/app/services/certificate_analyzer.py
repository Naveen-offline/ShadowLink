"""TLS certificate inspection (handshake only, no HTTP request is sent).

The connection goes to a validated public IP (pinned) with SNI set to the
hostname, using the default verifying SSL context. Verification is never
disabled. A valid certificate says nothing about whether a site is trustworthy.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from . import net_guard
from .url_validator import ParsedURL


def _parse_time(value: str):
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def _name(rdn_seq, field):
    for rdn in rdn_seq or ():
        for k, v in rdn:
            if k == field:
                return v
    return None


def _handshake(ip: str, port: int, hostname: str, timeout: float):
    """Returns (cert_dict, tls_version). Separated so tests can mock it."""
    ctx = ssl.create_default_context()  # CERT_REQUIRED + check_hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            return tls.getpeercert(), tls.version()


def _result(status: str, message: str, checked: bool = False, **extra) -> dict:
    return {"status": status, "checked": checked, "message": message, **extra}


def analyze_certificate(parsed: ParsedURL, enabled=True, timeout=4.0, *,
                        handshake=_handshake, resolver=net_guard.resolve_public) -> dict:
    """Inspect the TLS certificate. `handshake` and `resolver` are injectable for tests.

    `checked` is True only when a TLS handshake actually produced a verdict."""
    if parsed.scheme != "https":
        return _result("not_applicable", "The URL uses plain HTTP; there is no certificate to inspect.")
    if not enabled:
        return _result("unavailable", "TLS inspection is disabled in configuration.")
    port = parsed.port or 443
    try:
        ips = resolver(parsed.hostname, port)
    except net_guard.BlockedDestination:
        return _result("unavailable", "Connection skipped: destination is not an approved public address.")
    except net_guard.ResolutionError:
        return _result("unavailable", "Hostname could not be resolved, so no certificate was checked.")

    try:
        cert, version = handshake(ips[0], port, parsed.hostname, timeout)
    except ssl.SSLCertVerificationError as exc:
        reason = (getattr(exc, "verify_message", "") or "").lower()
        if "expired" in reason:
            status, note = "expired", "The certificate has expired."
        elif "hostname" in reason or "match" in reason or getattr(exc, "verify_code", None) == 62:
            status, note = "hostname_mismatch", "The certificate does not match the hostname."
        else:
            detail = getattr(exc, "verify_message", None) or "unknown reason"
            status, note = "verification_failed", f"Certificate verification failed: {detail}."
        return _result(status, note, checked=True, verified=False)
    except ssl.SSLError:
        return _result("unavailable", "A TLS connection could not be established.", verified=False)
    except (socket.timeout, TimeoutError):
        return _result("unavailable", "The TLS connection timed out.", verified=False)
    except OSError:
        return _result("unavailable", "The server could not be reached on the TLS port.", verified=False)

    not_before, not_after = _parse_time(cert["notBefore"]), _parse_time(cert["notAfter"])
    now = datetime.now(timezone.utc)
    return _result(
        "valid",
        "The certificate chain verified and matches the hostname. This does not indicate the site is safe or trustworthy.",
        checked=True, verified=True,
        issuer=_name(cert.get("issuer"), "organizationName") or _name(cert.get("issuer"), "commonName"),
        subject_cn=_name(cert.get("subject"), "commonName"),
        not_before=not_before.date().isoformat(),
        not_after=not_after.date().isoformat(),
        days_remaining=(not_after - now).days,
        san_count=len(cert.get("subjectAltName", ())),
        tls_version=version,
    )
