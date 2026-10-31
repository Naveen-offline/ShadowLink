from app.services.risk_engine import (CATEGORY_HIGH, CATEGORY_INSUFFICIENT, CATEGORY_LOWER, CATEGORY_MEDIUM,
                                      build_recommendations, categorize, compute_risk)

NO_DOMAIN = {"dns_checked": False, "domain_age_days": None}
NO_TLS = {"checked": False}
NO_RED = {"performed": False}
NO_ML = {"available": False}


def ind(name, sev="medium"):
    return {"indicator_name": name, "indicator_value": "x", "severity": sev, "explanation": ""}


def test_category_thresholds():
    assert categorize(0) == CATEGORY_LOWER and categorize(29) == CATEGORY_LOWER
    assert categorize(30) == CATEGORY_MEDIUM and categorize(59) == CATEGORY_MEDIUM
    assert categorize(60) == CATEGORY_HIGH and categorize(100) == CATEGORY_HIGH


def test_no_evidence_is_insufficient_not_safe():
    r = compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, NO_ML)
    assert r["score"] == 0 and r["category"] == CATEGORY_INSUFFICIENT
    assert "safe" not in r["category"].lower()
    assert len(r["unavailable_checks"]) >= 4


def test_lower_risk_needs_two_independent_checks():
    dom = {"dns_checked": True, "dns_error": None, "domain_age_days": 4000}
    ml = {"available": True, "predicted_class": "benign", "phishing_score": 0.05}
    r = compute_risk([], dom, NO_TLS, NO_RED, ml)
    assert r["category"] == CATEGORY_LOWER and r["independent_checks_completed"] >= 2


def test_group_caps_prevent_stacking():
    many = [ind(n) for n in ["IP address hostname", "'@' in URL", "Heavy percent-encoding", "Many subdomains",
                              "Internationalised hostname (punycode)"]]
    r = compute_risk(many, NO_DOMAIN, NO_TLS, NO_RED, NO_ML)
    assert r["breakdown"]["url_structure"] == 30


def test_tls_uses_worst_single_problem():
    r = compute_risk([], NO_DOMAIN, {"checked": True, "status": "hostname_mismatch"}, NO_RED, NO_ML)
    assert r["breakdown"]["tls"] == 15


def test_valid_certificate_adds_no_risk_and_no_safety_claim():
    r = compute_risk([], NO_DOMAIN, {"checked": True, "status": "valid"}, NO_RED, NO_ML)
    assert r["breakdown"]["tls"] == 0


def test_new_domain_raises_score():
    dom = {"dns_checked": True, "dns_error": None, "domain_age_days": 5}
    assert compute_risk([], dom, NO_TLS, NO_RED, NO_ML)["breakdown"]["domain"] == 20


def test_ml_contribution_is_bounded_and_class_gated():
    hi = {"available": True, "predicted_class": "phishing", "phishing_score": 1.0}
    assert compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, hi)["breakdown"]["machine_learning"] == 35
    lo = {"available": True, "predicted_class": "benign", "phishing_score": 0.4}
    assert compute_risk([], NO_DOMAIN, NO_TLS, NO_RED, lo)["breakdown"]["machine_learning"] == 0


def test_total_never_exceeds_100():
    inds = [ind(n) for n in ["IP address hostname", "'@' in URL", "Heavy percent-encoding", "Many subdomains"]]
    r = compute_risk(inds, {"dns_checked": True, "dns_error": None, "domain_age_days": 1, "non_public_ips": ["10.0.0.1"]},
                     {"checked": True, "status": "expired"},
                     {"performed": True, "blocked": True, "loop_detected": True, "domain_changes": 3, "hops": 4},
                     {"available": True, "predicted_class": "phishing", "phishing_score": 1.0})
    assert r["score"] == 100 and r["category"] == CATEGORY_HIGH


def test_recommendations_contextual():
    r = compute_risk([ind("IP address hostname", "high")], NO_DOMAIN, NO_TLS, NO_RED, NO_ML)
    recs = build_recommendations(r["category"], [ind("IP address hostname", "high")], r, NO_TLS, NO_DOMAIN)
    assert any("address format" in x for x in recs) and any("independent trusted source" in x for x in recs)
    assert len(recs) == len(set(recs))
