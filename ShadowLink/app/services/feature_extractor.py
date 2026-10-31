"""URL feature extraction.

Two feature schemas, each with ONE fixed column order used for both training and prediction:

* FEATURE_NAMES     - full-URL structural features shown in the report and used for the
                      explainable indicators (describe_indicators).
* ML_FEATURE_NAMES  - features of the REGISTERED DOMAIN (Public Suffix List) consumed by the
                      machine-learning model. The benign training list contains only registered
                      domains while the phishing list contains full hostnames; using subdomains
                      would let the model separate the two sources instead of phishing from
                      benign (it scored www.google.com as phishing). Subdomain structure is
                      reported by the explainable rule layer (describe_indicators) instead.

Every value is numeric. No single feature is proof of malice, and HTTPS is never treated
as evidence of legitimacy.
"""
from __future__ import annotations

import math
import re

from .url_validator import _EXTRACT, ParsedURL, URLValidationError, validate_and_normalize

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "update", "secure", "security",
    "banking", "confirm", "password", "passwd", "wallet", "webscr", "suspend", "unlock", "recover",
    "billing", "invoice", "authenticate",
)

FEATURE_NAMES = [
    "url_length", "hostname_length", "num_dots", "num_hyphens", "host_hyphens", "num_subdomains",
    "num_digits", "num_special_chars", "has_ip_host", "has_at_symbol", "has_userinfo",
    "suspicious_keyword_count", "num_query_params", "path_depth", "num_encoded_chars",
    "excessive_encoding", "has_punycode", "host_entropy", "uses_https", "has_nonstandard_port",
]

ML_FEATURE_NAMES = [
    "domain_length", "num_dots", "num_hyphens", "num_digits", "digit_ratio", "entropy",
    "has_ip_host", "has_punycode", "sld_length", "sld_hyphens", "sld_digit_ratio", "sld_vowel_ratio",
    "sld_max_digit_run", "tld_length", "keyword_count",
]

_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip_text(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- full-URL features

def extract_features(parsed: ParsedURL) -> dict:
    url = parsed.normalized
    host = parsed.hostname
    labels = [host] if parsed.is_ip else host.split(".")
    target = (host + parsed.path + "?" + parsed.query).lower()
    pct = len(_PCT_RE.findall(parsed.path + "?" + parsed.query))
    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "host_hyphens": host.count("-"),
        "num_subdomains": len([s for s in parsed.subdomain.split(".") if s]) if parsed.subdomain else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(1 for c in url if not c.isalnum() and c not in "./:-"),
        "has_ip_host": int(parsed.is_ip),
        "has_at_symbol": int("@" in url),             # normalised URL has userinfo removed
        "has_userinfo": int(parsed.has_userinfo),     # '@' that was present in the submitted authority
        "suspicious_keyword_count": sum(1 for k in SUSPICIOUS_KEYWORDS if k in target),
        "num_query_params": len(parsed.query_params),
        "path_depth": len([s for s in parsed.path.split("/") if s]),
        "num_encoded_chars": pct,
        "excessive_encoding": int(pct >= 5),
        "has_punycode": int(any(l.startswith("xn--") for l in labels)),
        "host_entropy": round(_entropy(host), 4),
        "uses_https": int(parsed.scheme == "https"),
        "has_nonstandard_port": int(parsed.port is not None),
    }


def extract_from_url_string(url) -> dict:
    """Validate, normalise and extract. Never raises: invalid input yields all-zero features."""
    try:
        return extract_features(validate_and_normalize(url))
    except (URLValidationError, ValueError, TypeError, AttributeError):
        return {name: 0 for name in FEATURE_NAMES}


def describe_indicators(features: dict) -> list[dict]:
    """Turn raw features into human-readable, explainable indicators.

    A single weak signal (one keyword, one hyphen) is deliberately NOT reported."""
    out: list[dict] = []

    def add(name, value, severity, explanation):
        out.append({"indicator_name": name, "indicator_value": value, "severity": severity,
                    "explanation": explanation})

    f = features
    if f.get("has_ip_host"):
        add("IP address hostname", "yes", "high",
            "The link uses a raw IP address instead of a domain name, a common way to hide the real destination.")
    if f.get("has_at_symbol") or f.get("has_userinfo"):
        add("'@' in URL", "yes", "medium",
            "Text before an '@' in a URL is ignored as a destination, which attackers use to disguise the real host.")
    if f.get("has_punycode"):
        add("Internationalised hostname (punycode)", "yes", "medium",
            "Hostnames in punycode (xn--) can imitate familiar names with look-alike characters. Many are legitimate.")
    if f.get("num_subdomains", 0) >= 3:
        add("Many subdomains", f["num_subdomains"], "medium",
            "Long subdomain chains can bury the real registered domain at the end of a familiar-looking name.")
    if f.get("host_hyphens", 0) >= 3:
        add("Many hyphens in hostname", f["host_hyphens"], "low",
            "Several hyphens in a hostname are more common in throw-away or look-alike domains.")
    if f.get("excessive_encoding"):
        add("Heavy percent-encoding", f.get("num_encoded_chars", 0), "medium",
            "Many %XX sequences can hide the true content of the path or query.")
    if f.get("suspicious_keyword_count", 0) >= 2:
        add("Multiple sensitive keywords", f["suspicious_keyword_count"], "low",
            "Several words such as 'login', 'verify' or 'secure' appear. This is common on real sites too, so it is weak evidence.")
    if f.get("url_length", 0) >= 100:
        add("Very long URL", f["url_length"], "low",
            "Unusually long URLs can hide the meaningful part of the address.")
    if f.get("host_entropy", 0) >= 3.8 and f.get("hostname_length", 0) >= 16:
        add("Random-looking hostname", f["host_entropy"], "low",
            "The hostname looks randomly generated, which is more typical of automatically created domains.")
    if not f.get("uses_https", 1):
        add("Not using HTTPS", "http", "low",
            "The connection is not encrypted. Note that HTTPS alone would not prove a site is trustworthy.")
    return out


# --------------------------------------------------------------------------- ML (hostname-only) features

_DIGIT_RUN_RE = re.compile(r"\d+")


def registered_domain_of(host: str) -> tuple[str, str, str, bool]:
    """(registered_domain, second_level_label, public_suffix, is_ip) for a hostname."""
    host = (host or "").strip().lower().rstrip(".")
    if _is_ip_text(host):
        return host.strip("[]"), host.strip("[]"), "", True
    ext = _EXTRACT(host)
    reg = ".".join(p for p in (ext.domain, ext.suffix) if p) or host
    return reg, ext.domain or host, ext.suffix, False


def ml_features_from_host(host: str) -> dict:
    """Model input. Subdomains are discarded: only the registered domain is scored."""
    dom, sld, suffix, is_ip = registered_domain_of(host)
    labels = [dom] if is_ip else [l for l in dom.split(".") if l]
    digits = sum(c.isdigit() for c in dom)
    sld_digits = sum(c.isdigit() for c in sld)
    letters = [c for c in sld if c.isalpha()]
    return {
        "domain_length": len(dom),
        "num_dots": dom.count("."),
        "num_hyphens": dom.count("-"),
        "num_digits": digits,
        "digit_ratio": round(digits / len(dom), 4) if dom else 0.0,
        "entropy": round(_entropy(dom), 4),
        "has_ip_host": int(is_ip),
        "has_punycode": int(any(l.startswith("xn--") for l in labels)),
        "sld_length": len(sld),
        "sld_hyphens": sld.count("-"),
        "sld_digit_ratio": round(sld_digits / len(sld), 4) if sld else 0.0,
        "sld_vowel_ratio": round(sum(c in "aeiou" for c in letters) / len(letters), 4) if letters else 0.0,
        "sld_max_digit_run": max((len(m) for m in _DIGIT_RUN_RE.findall(sld)), default=0),
        "tld_length": len(suffix),
        "keyword_count": sum(1 for k in SUSPICIOUS_KEYWORDS if k in sld),
    }


def ml_vector(features: dict) -> list[float]:
    """Ordered ML vector. Missing / None / NaN / non-numeric values default to 0.0 (documented)."""
    out = []
    for name in ML_FEATURE_NAMES:
        v = features.get(name, 0)
        try:
            v = float(v)
            if math.isnan(v) or math.isinf(v):
                v = 0.0
        except (TypeError, ValueError):
            v = 0.0
        out.append(v)
    return out
