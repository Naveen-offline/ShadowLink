"""URL validation and normalisation. Pure string work: nothing is fetched,
nothing is executed, and the URL is never opened in a browser."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit

import tldextract

from . import net_guard

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled PSL snapshot, no network
_extract = _EXTRACT  # alias used by ml.preprocessing

ALLOWED_SCHEMES = {"http", "https"}
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_HOSTPORT_RE = re.compile(r"^[^/:@?#]+:\d{1,5}(/|\?|#|$)")
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f-\x9f]")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9\-_]{1,63}(?<!-)$")


class URLValidationError(ValueError):
    """Raised with a user-safe message."""


@dataclass(frozen=True)
class ParsedURL:
    submitted: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    is_ip: bool
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    query_params: tuple


def _canonical_ip(host: str) -> str | None:
    """Return canonical dotted/IPv6 text if host is an IP in any common obfuscated
    form (decimal, hex, octal, short forms), else None."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", h, re.I):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            return None
    return None


def validate_and_normalize(raw: str, max_length: int = 2048) -> ParsedURL:
    if raw is None or not str(raw).strip():
        raise URLValidationError("Please enter a URL.")
    raw = str(raw).strip()
    if len(raw) > max_length:
        raise URLValidationError(f"URL is too long (maximum {max_length} characters).")
    if _CONTROL_RE.search(raw):
        raise URLValidationError("URL contains whitespace or control characters.")

    m = _SCHEME_RE.match(raw)
    if m and not _HOSTPORT_RE.match(raw):
        scheme_guess = m.group(1).lower()
        if scheme_guess not in ALLOWED_SCHEMES:
            raise URLValidationError("Unsupported URL scheme. Only http:// and https:// are allowed.")
    if raw.startswith("//"):
        raw = "https:" + raw
    elif not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw  # assume https when no scheme was typed

    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise URLValidationError("The URL could not be parsed.") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError("Unsupported URL scheme. Only http:// and https:// are allowed.")
    host = (parts.hostname or "").strip().rstrip(".")
    if not host:
        raise URLValidationError("The URL has no hostname.")
    if port is not None and not (1 <= port <= 65535):
        raise URLValidationError("Invalid port number.")

    ip_text = _canonical_ip(host)
    if ip_text is not None:
        host_norm, is_ip = ip_text, True
        if not net_guard.is_public_ip(ip_text):
            raise URLValidationError("Private, loopback, link-local and reserved addresses cannot be analysed.")
    else:
        try:
            host_norm = host.lower().encode("idna").decode("ascii")
        except UnicodeError:
            raise URLValidationError("The hostname is not valid.") from None
        is_ip = False
        if len(host_norm) > 253 or not all(_LABEL_RE.match(l) for l in host_norm.split(".")):
            raise URLValidationError("The hostname is not valid.")
        if net_guard.is_blocked_hostname(host_norm):
            raise URLValidationError("Local or internal hostnames cannot be analysed.")

    default_port = {"http": 80, "https": 443}[scheme]
    netloc = f"[{host_norm}]" if ":" in host_norm else host_norm
    if port and port != default_port:
        netloc += f":{port}"
    path = quote(unquote(parts.path), safe="/%:@!$&'()*+,;=-._~") or "/"
    query = parts.query
    normalized = f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")

    if is_ip:
        sub, dom, suf, reg = "", host_norm, "", host_norm
    else:
        ext = _EXTRACT(host_norm)
        sub, dom, suf = ext.subdomain, ext.domain, ext.suffix
        reg = ".".join(p for p in (dom, suf) if p) or host_norm

    params = tuple(p for p in query.split("&") if p) if query else ()
    return ParsedURL(
        submitted=str(raw),
        normalized=normalized,
        scheme=scheme,
        hostname=host_norm,
        port=port,
        path=path,
        query=query,
        has_userinfo=bool(parts.username or parts.password or "@" in parts.netloc),
        is_ip=is_ip,
        subdomain=sub,
        domain=dom,
        suffix=suf,
        registered_domain=reg,
        query_params=params,
    )
