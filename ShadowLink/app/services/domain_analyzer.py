"""Domain intelligence: DNS records and RDAP registration data.

Nothing is fabricated: every field is either observed or reported as unavailable.
"""
from datetime import datetime, timezone

import requests

from .ssrf_guard import BlockedDestination, check_host_literal, ip_is_public

RDAP_BOOTSTRAP = "https://rdap.org/domain/"  # fixed trusted service; only the domain is appended


def _dns_query(domain: str, rtype: str, timeout: float):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver.resolve(domain, rtype)


def _http_get_json(url: str, timeout: float):
    resp = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json"},
                        allow_redirects=True, stream=True)
    try:
        if resp.status_code != 200:
            return None
        raw = resp.raw.read(256 * 1024, decode_content=True)
        import json
        return json.loads(raw)
    finally:
        resp.close()


def _parse_creation_date(rdap: dict):
    for ev in rdap.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def analyze_domain(hostname: str, registered_domain: str, is_ip: bool, *, enable_dns=True,
                   enable_rdap=True, timeout=4.0, dns_query=_dns_query, http_get_json=_http_get_json) -> dict:
    result = {
        "hostname": hostname, "registered_domain": registered_domain,
        "dns_checked": False, "dns_error": None, "records": {}, "resolved_ips": [],
        "nameservers": [], "non_public_ips": [], "rdap_checked": False, "rdap_available": False,
        "creation_date": None, "domain_age_days": None, "notes": [],
    }
    if is_ip:
        result["notes"].append("Hostname is an IP address; DNS and registration checks do not apply.")
        return result
    try:
        check_host_literal(hostname)
    except BlockedDestination:
        result["notes"].append("Internal hostname; network lookups skipped.")
        return result

    if enable_dns:
        result["dns_checked"] = True
        found_any = False
        for rtype in ("A", "AAAA", "MX", "TXT"):
            try:
                answers = dns_query(hostname, rtype, timeout)
                vals = [a.to_text() for a in answers][:10]
                result["records"][rtype] = vals
                found_any = True
                if rtype in ("A", "AAAA"):
                    result["resolved_ips"].extend(v for v in vals if v not in result["resolved_ips"])
            except Exception as exc:  # NXDOMAIN, NoAnswer, Timeout...
                name = type(exc).__name__
                if name == "NXDOMAIN":
                    result["dns_error"] = "Domain does not exist (NXDOMAIN)."
                    break
                if name in ("Timeout", "LifetimeTimeout"):
                    result["dns_error"] = "DNS lookup timed out."
                    break
                result["records"].setdefault(rtype, [])
        for ip in result["resolved_ips"]:
            try:
                if not ip_is_public(ip):
                    result["non_public_ips"].append(ip)
            except ValueError:
                pass
        if not result["dns_error"] and not result["records"].get("A") and not result["records"].get("AAAA"):
            result["notes"].append("No A/AAAA records found for this hostname.")
        try:
            ns = dns_query(registered_domain, "NS", timeout)
            result["nameservers"] = [a.to_text().rstrip(".") for a in ns][:10]
        except Exception:
            pass
    else:
        result["notes"].append("DNS lookups are disabled in this deployment.")

    if enable_rdap and not result["dns_error"]:
        result["rdap_checked"] = True
        try:
            data = http_get_json(RDAP_BOOTSTRAP + registered_domain, timeout)
        except Exception:
            data = None
        if data:
            result["rdap_available"] = True
            created = _parse_creation_date(data)
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                result["creation_date"] = created.date().isoformat()
                result["domain_age_days"] = max(0, (datetime.now(timezone.utc) - created).days)
        else:
            result["notes"].append("Registration (RDAP) data was unavailable for this domain.")
    elif not enable_rdap:
        result["notes"].append("RDAP lookups are disabled in this deployment.")
    return result
