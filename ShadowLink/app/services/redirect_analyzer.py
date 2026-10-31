"""Controlled redirect inspection. DISABLED BY DEFAULT.

Safety design (SSRF / DNS rebinding):
  * Every hop's hostname is resolved by us, and ALL addresses must be public.
  * We connect to the validated IP directly (pinning) and send the Host header ourselves,
    so a second, attacker-controlled DNS answer can never be used.
  * Only a HEAD request is sent; the body is never read or executed.
  * Hop count, timeout and header size are bounded. No cookies or credentials are sent.
  * Certificate verification is never disabled.
For production, run this module inside an egress-restricted container/service as well.
"""
import socket
import ssl
from urllib.parse import urljoin

from .ssrf_guard import BlockedDestination, resolve_public_ips
from .url_validator import URLValidationError, validate_and_normalize

MAX_HEADER_BYTES = 16 * 1024


def _fetch_hop(url_info, ip: str, timeout: float) -> tuple[int, dict]:
    """Send one HEAD request to a pinned IP; return (status, lowercase headers)."""
    port = url_info.port or (443 if url_info.scheme == "https" else 80)
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if url_info.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = ctx.wrap_socket(sock, server_hostname=url_info.hostname)
        target = url_info.path + (("?" + url_info.query) if url_info.query else "")
        req = (f"HEAD {target} HTTP/1.1\r\nHost: {url_info.hostname}\r\n"
               "User-Agent: ShadowLink-Analyzer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode("ascii", "ignore"))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < MAX_HEADER_BYTES:
            chunk = sock.recv(2048)
            if not chunk:
                break
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers.setdefault(k.strip().lower(), v.strip())
        return status, headers
    finally:
        sock.close()


def analyze_redirects(normalized_url: str, *, enabled=False, max_redirects=5, timeout=4.0,
                      fetch_hop=_fetch_hop, resolver=resolve_public_ips) -> dict:
    out = {"performed": False, "message": "", "chain": [], "hops": 0, "loop_detected": False,
           "domain_changes": 0, "blocked": False, "final_url": None, "flags": []}
    if not enabled:
        out["message"] = ("Live redirect inspection is disabled by default for safety. "
                          "Results rely on URL-string, DNS and model analysis only.")
        return out

    out["performed"] = True
    seen = set()
    current = normalized_url
    prev_domain = None
    for _ in range(max_redirects + 1):
        if current in seen:
            out["loop_detected"] = True
            out["flags"].append("Redirect loop detected.")
            break
        seen.add(current)
        try:
            info = validate_and_normalize(current)
            ips = resolver(info.hostname, info.port or (443 if info.scheme == "https" else 80))
        except (URLValidationError, BlockedDestination) as exc:
            out["blocked"] = True
            out["message"] = f"Redirect destination blocked for safety: {exc}"
            out["flags"].append("A redirect pointed to a blocked (non-public or invalid) destination.")
            break
        try:
            status, headers = fetch_hop(info, ips[0], timeout)
        except (socket.timeout, TimeoutError):
            out["message"] = "Connection timed out during redirect analysis."
            break
        except (ssl.SSLError, OSError, ValueError, IndexError):
            out["message"] = "A connection error occurred during redirect analysis."
            break
        out["chain"].append({"url": current, "status": status})
        if prev_domain and prev_domain != info.registered_domain:
            out["domain_changes"] += 1
        prev_domain = info.registered_domain
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            current = urljoin(current, headers["location"])
            out["hops"] += 1
            continue
        out["final_url"] = current
        break
    else:
        out["flags"].append(f"Exceeded the maximum of {max_redirects} redirects.")

    if out["hops"] >= 3:
        out["flags"].append("Unusually long redirect chain.")
    if out["domain_changes"] >= 2:
        out["flags"].append("Redirects cross multiple registered domains.")
    if not out["message"]:
        out["message"] = f"Followed {out['hops']} redirect(s) using restricted HEAD requests."
    return out
