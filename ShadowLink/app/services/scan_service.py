"""Orchestrates one scan: validate -> features -> domain -> TLS -> redirects -> threat feed -> ML -> risk."""
import json
from datetime import datetime, timezone

from flask import current_app

from . import certificate_analyzer, domain_analyzer, redirect_analyzer, threat_intel
from .feature_extractor import describe_indicators, extract_features, ml_features_from_host
from .phishing_detector import PhishingDetector
from .risk_engine import build_recommendations, compute_risk
from .ssrf_guard import BlockedDestination, check_host_literal
from .url_validator import URLValidationError, validate_and_normalize


def build_detector(cfg) -> PhishingDetector:
    return PhishingDetector(cfg["MODEL_PATH"], cfg["MODEL_META_PATH"])


def get_detector(force_reload: bool = False) -> PhishingDetector:
    """Per-application detector (stored on the app, so separate apps never share a model)."""
    ext = current_app.extensions
    if force_reload or "detector" not in ext:
        ext["detector"] = build_detector(current_app.config)
    return ext["detector"]


def run_analysis(raw_url: str) -> dict:
    """Run all enabled checks. Raises URLValidationError for bad input."""
    cfg = current_app.config
    parsed = validate_and_normalize(raw_url, cfg["MAX_URL_LENGTH"])
    try:  # defence in depth: the validator already rejects these
        check_host_literal(parsed.hostname)
    except BlockedDestination as exc:
        raise URLValidationError(
            "Internal, local and private-network addresses cannot be analyzed. " + str(exc)) from exc

    features = extract_features(parsed)
    indicators = describe_indicators(features)
    timeout = max(cfg["CONNECT_TIMEOUT"], cfg["READ_TIMEOUT"])

    threat = threat_intel.check(parsed, cfg["THREAT_INTEL_PATH"])
    if threat.get("match"):
        indicators.append({"indicator_name": "Listed in local phishing feed", "indicator_value": parsed.hostname,
                           "severity": "high", "explanation": threat["note"]})

    domain = domain_analyzer.analyze_domain(
        parsed.hostname, parsed.registered_domain, parsed.is_ip,
        enable_dns=cfg["DNS_ANALYSIS_ENABLED"], enable_rdap=cfg["RDAP_ENABLED"], timeout=timeout)
    if domain.get("non_public_ips"):
        indicators.append({
            "indicator_name": "Resolves to a non-public address",
            "indicator_value": ", ".join(domain["non_public_ips"][:3]), "severity": "high",
            "explanation": "A public hostname that resolves to a private or loopback address can indicate DNS rebinding or misconfiguration. ShadowLink did not connect to it."})
    tls = certificate_analyzer.analyze_certificate(parsed, enabled=cfg["TLS_INSPECTION_ENABLED"], timeout=timeout)
    redirects = redirect_analyzer.analyze_redirects(
        parsed.normalized, enabled=cfg["LIVE_FETCH_ENABLED"], max_redirects=cfg["MAX_REDIRECTS"], timeout=timeout)

    ml = get_detector().predict(ml_features_from_host(parsed.hostname))
    risk = compute_risk(indicators, domain, tls, redirects, ml, threat)
    recs = build_recommendations(risk["category"], indicators, risk, tls, domain)

    return {
        "submitted_url": parsed.submitted,
        "normalized_url": parsed.normalized,
        "hostname": parsed.hostname,
        "registered_domain": parsed.registered_domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "features": features,
        "indicators": indicators,
        "domain": domain,
        "tls": tls,
        "redirects": redirects,
        "threat_intel": threat,
        "ml": ml,
        "risk": risk,
        "recommendations": recs,
    }


def persist_scan(db, user_id: int, result: dict):
    from ..models import Scan, ScanFinding
    scan = Scan(
        user_id=user_id,
        submitted_url=result["submitted_url"][:2048],
        normalized_url=result["normalized_url"][:2048],
        registered_domain=result["registered_domain"][:255],
        risk_score=result["risk"]["score"],
        risk_category=result["risk"]["category"],
        prediction=result["ml"].get("predicted_class") if result["ml"].get("available") else "unavailable",
        model_version=result["ml"].get("model_version"),
        scan_status="completed",
        result_json=json.dumps(result),
    )
    db.session.add(scan)
    db.session.flush()
    for ind in result["indicators"]:
        db.session.add(ScanFinding(
            scan_id=scan.id, indicator_name=ind["indicator_name"][:80],
            indicator_value=str(ind["indicator_value"])[:255], severity=ind["severity"],
            explanation=ind["explanation"]))
    db.session.commit()
    return scan
