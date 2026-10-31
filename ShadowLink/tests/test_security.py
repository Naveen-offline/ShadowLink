import re
import socket

import pytest

from app import create_app
from app.config import TestConfig
from app.models import Scan, User, db
from app.services import certificate_analyzer, domain_analyzer, redirect_analyzer
from app.services.ssrf_guard import BlockedDestination, check_host_literal, ip_is_public, resolve_public_ips
from tests.conftest import PASSWORD, make_user


# ---- SSRF guard -----------------------------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254",
                                "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1",
                                "::ffff:127.0.0.1", "100.100.100.200", "fd00:ec2::254", "100.64.0.1"])
def test_non_public_ips_blocked(ip):
    assert ip_is_public(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert ip_is_public(ip) is True


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST.", "metadata.google.internal", "foo.internal",
                                  "printer.local", "127.0.0.1", "2130706433", "0x7f000001", "169.254.169.254", "[::1]", "127.1", "017700000001", "0177.0.0.1"])
def test_internal_hosts_rejected(host):
    with pytest.raises(BlockedDestination):
        check_host_literal(host)


def fake_resolver(addrs):
    def _r(host, port, type=None):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addrs]
    return _r


def test_dns_to_private_address_blocked():
    with pytest.raises(BlockedDestination):
        resolve_public_ips("evil.example", resolver=fake_resolver(["10.0.0.1"]))


def test_dns_rebinding_mixed_answers_blocked():
    # An attacker returning one public and one private A record must be rejected entirely.
    with pytest.raises(BlockedDestination):
        resolve_public_ips("rebind.example", resolver=fake_resolver(["93.184.216.34", "127.0.0.1"]))


def test_public_resolution_returns_pinned_ips():
    assert resolve_public_ips("ok.example", resolver=fake_resolver(["93.184.216.34", "93.184.216.34"])) == ["93.184.216.34"]


def test_unresolvable_host_blocked():
    def boom(*a, **k):
        raise socket.gaierror("nope")
    with pytest.raises(BlockedDestination):
        resolve_public_ips("nx.example", resolver=boom)


# ---- Redirect analyzer ----------------------------------------------------
def res_ok(host, port):
    return ["93.184.216.34"]


def test_live_fetch_disabled_by_default_makes_no_request():
    def must_not_run(*a, **k):
        raise AssertionError("network used while disabled")
    out = redirect_analyzer.analyze_redirects("http://example.com/", fetch_hop=must_not_run)
    assert out["performed"] is False and "disabled" in out["message"].lower()


def test_redirect_to_private_address_rejected():
    def hop(info, ip, timeout):
        return 302, {"location": "http://169.254.169.254/latest/meta-data/"}
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, fetch_hop=hop, resolver=resolve_public_ips_stub())
    assert out["blocked"] is True and out["final_url"] is None
    assert len(out["chain"]) == 1


def resolve_public_ips_stub():
    def r(host, port):
        return resolve_public_ips(host, port, resolver=fake_resolver(["93.184.216.34"]))
    return r


def test_redirect_to_hostname_resolving_private_rejected():
    def resolver(host, port):
        return resolve_public_ips(host, port, resolver=fake_resolver(["10.1.1.1"] if host == "sneaky.example" else ["93.184.216.34"]))
    def hop(info, ip, timeout):
        return 301, {"location": "http://sneaky.example/"}
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, fetch_hop=hop, resolver=resolver)
    assert out["blocked"] is True


def test_redirect_loop_detected():
    def hop(info, ip, timeout):
        return 302, {"location": "/b" if info.path == "/" else "/"}
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, fetch_hop=hop, resolver=resolve_public_ips_stub())
    assert out["loop_detected"] is True


def test_redirect_hop_limit_and_domain_changes():
    n = {"i": 0}
    def hop(info, ip, timeout):
        n["i"] += 1
        return 302, {"location": f"http://site{n['i']}.com/"}
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, max_redirects=3, fetch_hop=hop,
                                              resolver=resolve_public_ips_stub())
    assert n["i"] == 4 and any("Exceeded" in f for f in out["flags"]) and out["domain_changes"] >= 2


def test_redirect_timeout_handled():
    def hop(info, ip, timeout):
        raise socket.timeout()
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, fetch_hop=hop, resolver=resolve_public_ips_stub())
    assert "timed out" in out["message"].lower()


def test_redirect_rejects_non_http_location():
    def hop(info, ip, timeout):
        return 302, {"location": "file:///etc/passwd"}
    out = redirect_analyzer.analyze_redirects("http://example.com/", enabled=True, fetch_hop=hop, resolver=resolve_public_ips_stub())
    assert out["blocked"] is True


# ---- Certificate analyzer -------------------------------------------------
def _pu(url):
    from app.services.url_validator import validate_and_normalize
    return validate_and_normalize(url)


def _res_ok(host, port):
    return ["93.184.216.34"]


def test_cert_not_checked_when_disabled_or_http():
    r = certificate_analyzer.analyze_certificate(_pu("http://example.com/"), enabled=True)
    assert r["status"] == "not_applicable" and r["checked"] is False
    r = certificate_analyzer.analyze_certificate(_pu("https://example.com/"), enabled=False)
    assert r["checked"] is False and "disabled" in r["message"]


def test_cert_skips_private_destination():
    from app.services import net_guard
    def resolver(host, port):
        return net_guard.resolve_public(host, port)
    import app.services.net_guard as ng
    orig = ng._getaddrinfo
    ng._getaddrinfo = lambda h, p: [(2, 1, 6, "", ("10.0.0.9", p))]
    try:
        out = certificate_analyzer.analyze_certificate(_pu("https://internal.example.com/"), enabled=True, resolver=resolver,
                                                       handshake=lambda *a: (_ for _ in ()).throw(AssertionError("must not connect")))
    finally:
        ng._getaddrinfo = orig
    assert out["checked"] is False and "skipped" in out["message"].lower()


def test_cert_timeout_and_valid_paths():
    def timeout(ip, port, host, t):
        raise socket.timeout()
    r = certificate_analyzer.analyze_certificate(_pu("https://example.com/"), enabled=True, handshake=timeout, resolver=_res_ok)
    assert r["status"] == "unavailable" and r["checked"] is False and "timed out" in r["message"]

    def good(ip, port, host, t):
        assert ip == "93.184.216.34"  # connects to the validated, pinned IP
        return ({"notBefore": "Jan  1 00:00:00 2025 GMT", "notAfter": "Jan  1 00:00:00 2099 GMT",
                 "issuer": ((("organizationName", "Test CA"),),), "subject": ((("commonName", host),),)}, "TLSv1.3")
    r = certificate_analyzer.analyze_certificate(_pu("https://example.com/"), enabled=True, handshake=good, resolver=_res_ok)
    assert r["status"] == "valid" and r["checked"] is True and r["issuer"] == "Test CA"
    assert "does not indicate the site is safe" in r["message"]


def test_cert_hostname_mismatch_expired_and_other_failures():
    import ssl
    def raiser(msg, code=1):
        def h(ip, port, host, t):
            e = ssl.SSLCertVerificationError(code, "bad"); e.verify_message = msg; raise e
        return h
    run = lambda h: certificate_analyzer.analyze_certificate(_pu("https://a.example.com/"), enabled=True, handshake=h, resolver=_res_ok)
    assert run(raiser("Hostname mismatch, certificate is not valid"))["status"] == "hostname_mismatch"
    assert run(raiser("certificate has expired"))["status"] == "expired"
    r = run(raiser("self-signed certificate"))
    assert r["status"] == "verification_failed" and r["checked"] is True


def test_cert_resolution_failure_is_unavailable():
    from app.services import net_guard
    def res(host, port):
        raise net_guard.ResolutionError("nope")
    r = certificate_analyzer.analyze_certificate(_pu("https://example.com/"), enabled=True, resolver=res)
    assert r["status"] == "unavailable" and r["checked"] is False


# ---- Domain analyzer ------------------------------------------------------
class _Ans:
    def __init__(self, t): self.t = t
    def to_text(self): return self.t


def test_domain_analysis_with_mocked_dns_and_rdap():
    def dq(name, rtype, timeout):
        return {"A": [_Ans("93.184.216.34")], "NS": [_Ans("ns1.example.net.")]}.get(rtype) or (_ for _ in ()).throw(Exception("none"))
    rd = lambda url, t: {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}
    out = domain_analyzer.analyze_domain("www.example.com", "example.com", False, dns_query=dq, http_get_json=rd)
    assert out["resolved_ips"] == ["93.184.216.34"] and out["nameservers"] == ["ns1.example.net"]
    assert out["creation_date"] == "2020-01-01" and out["domain_age_days"] > 1000


def test_domain_rdap_unavailable_is_not_fabricated():
    def dq(name, rtype, timeout):
        raise Exception("none")
    out = domain_analyzer.analyze_domain("example.com", "example.com", False, dns_query=dq, http_get_json=lambda u, t: None)
    assert out["creation_date"] is None and out["domain_age_days"] is None and out["rdap_available"] is False


def test_domain_flags_non_public_resolution():
    def dq(name, rtype, timeout):
        if rtype == "A":
            return [_Ans("10.0.0.1")]
        raise Exception("none")
    out = domain_analyzer.analyze_domain("rebind.example", "rebind.example", False, enable_rdap=False, dns_query=dq)
    assert out["non_public_ips"] == ["10.0.0.1"]


def test_domain_nxdomain_reported():
    class NXDOMAIN(Exception): pass
    def dq(name, rtype, timeout):
        raise NXDOMAIN()
    out = domain_analyzer.analyze_domain("nope.example", "nope.example", False, dns_query=dq)
    assert "NXDOMAIN" in out["dns_error"]


# ---- Application-level security ------------------------------------------
def test_internal_urls_rejected_by_api(logged_in):
    for u in ("http://localhost/", "http://127.0.0.1:5000/admin", "http://192.168.0.1/", "http://169.254.169.254/latest/meta-data",
              "http://[::1]/", "http://2130706433/", "http://metadata.google.internal/"):
        r = logged_in.post("/api/scan", json={"url": u})
        assert r.status_code == 400, u
    assert Scan.query.count() == 0


def test_oversized_inputs(logged_in):
    assert logged_in.post("/api/scan", json={"url": "http://example.com/" + "a" * 5000}).status_code == 400
    assert logged_in.post("/api/scan", data="x" * 200_000, content_type="application/json").status_code == 413


def test_sql_injection_payloads_are_inert(logged_in):
    for p in ("' OR '1'='1", "'; DROP TABLE scans;--", "\" OR 1=1 --"):
        assert logged_in.get("/api/history", query_string={"q": p, "category": p}).status_code == 200
        assert logged_in.post("/api/scan", json={"url": f"http://example.com/?q={p}"}).status_code in (201, 400)
    assert db.session.execute(db.text("SELECT count(*) FROM users")).scalar() == 1


def test_sql_injection_in_login(client):
    make_user()
    r = client.post("/auth/login", data={"email": "' OR '1'='1' --", "password": "x"})
    assert r.status_code == 200 and b"Invalid email or password" in r.data


def test_xss_payload_is_escaped_in_results_and_history(logged_in):
    payload = "http://example.com/<script>alert(1)</script>?a=<img/src=x/onerror=alert(2)>"
    sid = logged_in.post("/api/scan", json={"url": payload}).get_json()["scan_id"]
    page = logged_in.get(f"/results/{sid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "<img/src=x" not in page
    # JSON API returns data only; rendering uses textContent in the browser
    assert logged_in.get("/api/history").mimetype == "application/json"


def test_xss_in_registration_name_escaped(client):
    client.post("/auth/register", data={"full_name": "<script>alert(1)</script>", "email": "x@example.com", "password": PASSWORD, "confirm": PASSWORD})
    client.post("/auth/login", data={"email": "x@example.com", "password": PASSWORD})
    assert b"<script>alert(1)</script>" not in client.get("/settings").data


def test_security_headers(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "unsafe-eval" not in r.headers["Content-Security-Policy"]


def test_error_pages_do_not_leak_internals(client):
    r = client.get("/nonexistent")
    assert r.status_code == 404 and b"Traceback" not in r.data
    assert client.get("/api/nonexistent").get_json() == {"error": "The requested page or resource was not found."}


def test_secure_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True and app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["LIVE_FETCH_ENABLED"] is False


def test_default_config_has_live_fetch_disabled():
    from app.config import Config
    assert Config.LIVE_FETCH_ENABLED is False  # live fetching is opt-in only


class CsrfCfg(TestConfig):
    WTF_CSRF_ENABLED = True


def test_csrf_enforced():
    app = create_app(CsrfCfg)
    with app.app_context():
        db.create_all()
        make_user()
        c = app.test_client()
        assert c.post("/auth/login", data={"email": "user@example.com", "password": PASSWORD}).status_code == 400
        page = c.get("/auth/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
        r = c.post("/auth/login", data={"email": "user@example.com", "password": PASSWORD, "csrf_token": token})
        assert r.status_code == 302
        # State-changing API calls without token are refused, with header token accepted
        assert c.post("/api/scan", json={"url": "https://example.com"}).status_code == 400
        meta = re.search(r'name="csrf-token" content="([^"]+)"', c.get("/scanner").get_data(as_text=True)).group(1)
        assert c.post("/api/scan", json={"url": "https://example.com"}, headers={"X-CSRFToken": meta}).status_code == 201
        assert c.post("/auth/logout").status_code == 400
        db.drop_all()


class RateCfg(TestConfig):
    RATELIMIT_ENABLED = True


def test_login_rate_limited():
    app = create_app(RateCfg)
    with app.app_context():
        db.create_all()
        c = app.test_client()
        codes = [c.post("/auth/login", data={"email": "a@example.com", "password": "x"}).status_code for _ in range(12)]
        assert 429 in codes and codes[0] == 200
        db.drop_all()
