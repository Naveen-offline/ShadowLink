import re

from app.models import Scan, db
from tests.conftest import PASSWORD, login, make_user

URL = "http://paypal-secure-login.verify-account.example-xyz.com/signin?id=1"


def scan(client, url=URL):
    return client.post("/api/scan", json={"url": url})


def test_scan_creates_record_with_real_analysis(logged_in):
    r = scan(logged_in)
    assert r.status_code == 201
    j = r.get_json()
    s = db.session.get(Scan, j["scan_id"])
    assert s.registered_domain == "example-xyz.com"
    assert 0 <= s.risk_score <= 100 and s.risk_category
    assert s.model_version == "test-1" and s.prediction in ("phishing", "benign")
    assert s.findings, "structural findings should be persisted"
    d = s.details
    assert d["features"]["num_subdomains"] == 2
    assert d["redirects"]["performed"] is False and "disabled" in d["redirects"]["message"].lower()
    assert d["tls"]["checked"] is False


def test_results_page_and_api(logged_in):
    sid = scan(logged_in).get_json()["scan_id"]
    page = logged_in.get(f"/results/{sid}")
    assert page.status_code == 200 and b"Evidence limitations" in page.data
    api = logged_in.get(f"/api/scan/{sid}").get_json()
    assert api["id"] == sid and "details" in api


def test_invalid_inputs(logged_in):
    for body in ({}, {"url": 5}, {"url": ""}, {"url": "javascript:alert(1)"}, {"url": "ftp://x.com"}):
        assert scan(logged_in, body.get("url") if body else None).status_code == 400
    assert logged_in.post("/api/scan", data="notjson", content_type="text/plain").status_code == 400
    assert Scan.query.count() == 0


def test_history_search_filter_sort_delete(logged_in):
    for u in ("https://alpha.example.com/", "https://beta.example.org/", "http://1.2.3.4/login"):
        assert scan(logged_in, u).status_code == 201
    j = logged_in.get("/api/history").get_json()
    assert j["total"] == 3
    assert logged_in.get("/api/history?q=alpha").get_json()["total"] == 1
    assert logged_in.get("/api/history?q=%25").get_json()["total"] == 0  # LIKE wildcards are escaped
    cat = j["items"][0]["risk_category"]
    assert all(i["risk_category"] == cat for i in logged_in.get(f"/api/history?category={cat}").get_json()["items"])
    oldest = logged_in.get("/api/history?sort=oldest").get_json()["items"]
    assert oldest[0]["id"] < oldest[-1]["id"]
    sid = j["items"][0]["id"]
    assert logged_in.delete(f"/api/history/{sid}").status_code == 200
    ids = [i["id"] for i in logged_in.get("/api/history").get_json()["items"]]
    r = logged_in.post("/api/history/bulk-delete", json={"ids": ids})
    assert r.get_json()["deleted"] == 2 and Scan.query.count() == 0
    assert logged_in.post("/api/history/bulk-delete", json={"ids": ["x"]}).status_code == 400


def test_users_cannot_access_each_others_scans(client):
    make_user("a@example.com"); make_user("b@example.com")
    login(client, "a@example.com")
    sid = scan(client).get_json()["scan_id"]
    client.post("/auth/logout")
    login(client, "b@example.com")
    assert client.get(f"/api/scan/{sid}").status_code == 404
    assert client.get(f"/results/{sid}").status_code == 404
    assert client.get(f"/api/report/{sid}/pdf").status_code == 404
    assert client.delete(f"/api/history/{sid}").status_code == 404
    assert client.post("/api/history/bulk-delete", json={"ids": [sid]}).get_json()["deleted"] == 0
    assert client.get("/api/history").get_json()["total"] == 0
    assert client.get("/api/dashboard/stats").get_json()["total"] == 0
    assert db.session.get(Scan, sid) is not None


def test_dashboard_stats_come_from_database(logged_in):
    assert logged_in.get("/api/dashboard/stats").get_json()["total"] == 0
    scan(logged_in); scan(logged_in, "https://example.com/")
    j = logged_in.get("/api/dashboard/stats").get_json()
    assert j["total"] == 2 and j["high"] + j["medium"] + j["lower"] + j["insufficient"] == 2
    assert sum(j["daily"]["counts"]) == 2 and len(j["recent"]) == 2


def test_pdf_report_generation(logged_in, app):
    sid = scan(logged_in).get_json()["scan_id"]
    r = logged_in.get(f"/api/report/{sid}/pdf")
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.data.startswith(b"%PDF")
    assert "attachment" in r.headers["Content-Disposition"]
    assert len(list(app.config["REPORT_DIR"].glob("*.pdf"))) == 1


def test_pdf_handles_hostile_text(logged_in):
    sid = scan(logged_in, "http://example.com/<b>&<script>alert(1)</script>").get_json()["scan_id"]
    assert logged_in.get(f"/api/report/{sid}/pdf").status_code == 200


def test_model_missing_still_works(logged_in, app):
    import app.services.scan_service as ss
    app.config["MODEL_PATH"] = app.config["MODEL_PATH"].with_name("missing.joblib")
    ss.get_detector(force_reload=True)
    r = scan(logged_in)
    assert r.status_code == 201
    d = db.session.get(Scan, r.get_json()["scan_id"]).details
    assert d["ml"]["available"] is False
    assert "Machine-learning model" in d["risk"]["unavailable_checks"]
