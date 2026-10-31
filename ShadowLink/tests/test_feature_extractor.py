from app.services.feature_extractor import (FEATURE_NAMES, ML_FEATURE_NAMES, describe_indicators,
                                            extract_features, extract_from_url_string,
                                            ml_features_from_host, ml_vector)
from app.services.url_validator import validate_and_normalize


def feats(url):
    return extract_features(validate_and_normalize(url))


def test_schema_is_stable_and_ordered():
    f = feats("https://example.com/")
    assert list(f.keys()) == FEATURE_NAMES
    assert list(ml_features_from_host("example.com").keys()) == ML_FEATURE_NAMES


def test_extracted_values():
    f = feats("http://user@login-secure.verify.example.com/a/b/c?x=1&y=2&z=%41%42")
    assert f["has_at_symbol"] == 0  # userinfo stripped by normalisation
    assert f["uses_https"] == 0
    assert f["num_subdomains"] == 2 and f["num_hyphens"] == 1
    assert f["path_depth"] == 3 and f["num_query_params"] == 3
    assert f["suspicious_keyword_count"] >= 2
    assert f["num_encoded_chars"] == 2


def test_ip_host_and_punycode_detected():
    assert feats("http://8.8.8.8/x")["has_ip_host"] == 1
    assert feats("http://bücher.example/")["has_punycode"] == 1


def test_https_alone_is_not_flagged_as_risky_and_http_is_only_low():
    names = {i["indicator_name"]: i["severity"] for i in describe_indicators(feats("http://example.com/"))}
    assert names.get("Not using HTTPS") == "low"
    assert describe_indicators(feats("https://example.com/")) == []


def test_single_keyword_is_not_an_indicator():
    assert describe_indicators(feats("https://example.com/login")) == []


def test_string_extractor_never_raises():
    for s in ["", "not a url", "http://[::1", "http://a b", "%%%", None]:
        assert isinstance(extract_from_url_string(s), dict)


def test_ml_vector_handles_missing_features():
    v = ml_vector({ML_FEATURE_NAMES[0]: 5})
    assert len(v) == len(ML_FEATURE_NAMES) and v[0] == 5.0 and sum(v[1:]) == 0
    assert len(ml_vector({})) == len(ML_FEATURE_NAMES)
    assert ml_vector({"num_dots": None})[ML_FEATURE_NAMES.index("num_dots")] == 0.0


def test_ml_features_ignore_subdomains():
    """Regression: the model must score the registered domain, so adding www./subdomains cannot change it
    (previously www.google.com scored as phishing because benign training data had no subdomains)."""
    base = ml_features_from_host("google.com")
    for h in ("www.google.com", "mail.google.com", "a.b.c.google.com"):
        assert ml_features_from_host(h) == base
    assert ml_features_from_host("shop.example.co.uk")["tld_length"] == len("co.uk")
