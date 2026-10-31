import pytest

from app.models import Scan, db
from app.services import threat_intel
from app.services.risk_engine import CATEGORY_HIGH, compute_risk
from app.services.url_validator import validate_and_normalize
from tests.conftest import make_user, login

NO_DOMAIN = {"dns_checked": False, "domain_age_days": None}
NO_TLS = {"checked": False}
NO_RED = {"performed": False}
NO_ML = {"available": False}


@pytest.fixture
def feed(tmp_path):
    f = tmp_path / "feed.txt"
    f.write_text("# comment\nevil-login.example.com\nhttp://bad.example.org/phish\n")
    return str(f)


def test_missing_feed_is_unavailable_not_clean(tmp_path):
    r = threat_intel.check(validate_and_normalize("https://example.com/"), str(tmp_path / "nope.txt"))
    assert r["status"] == "unavailable" and r["match"] is False


def test_host_and_url_matches(feed):
    assert threat_intel.check(validate_and_normalize("https://evil-login.example.com/x"), feed)["match"] is True
    assert threat_intel.check(validate_and_normalize("http://bad.example.org/phish"), feed)["match"] is True


def test_no_match_never_claims_safe(feed):
    r = threat_intel.check(validate_and_normalize("https://example.com/"), feed)
    assert r["status"] == "no_match" and "NOT evidence" in r["note"]


def test_match_adds_points_and_is_reported():
    base = compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, NO_ML, {"status": "no_match", "match": False})
    hit = compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, NO_ML, {"status": "match", "match": True})
    assert hit["score"] - base["score"] == 40 and hit["breakdown"]["threat_intel"] == 40
    assert any(c["group"] == "Threat intelligence" for c in hit["top_contributors"])
    assert "Threat-intelligence feed" not in hit["unavailable_checks"]


def test_unavailable_feed_listed_as_unavailable():
    r = compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, NO_ML, {"status": "unavailable"})
    assert "Threat-intelligence feed" in r["unavailable_checks"]


def test_scan_pipeline_uses_feed(app, client, feed):
    app.config["THREAT_INTEL_PATH"] = feed
    make_user(); login(client)
    r = client.post("/api/scan", json={"url": "https://evil-login.example.com/signin"})
    assert r.status_code == 201
    d = db.session.get(Scan, r.get_json()["scan_id"]).details
    assert d["threat_intel"]["match"] is True
    assert d["risk"]["breakdown"]["threat_intel"] == 40
    assert any(i["indicator_name"] == "Listed in local phishing feed" for i in d["indicators"])
