"""Transparent risk scoring.

Formula (documented in docs/architecture.md):

    score = min(100, URL + DOMAIN + TLS + REDIRECT + ML + THREAT)

Each group is capped so correlated indicators cannot stack without limit:

    URL      <= 30   structural indicators (sum of weights, then capped)
    DOMAIN   <= 25   registration age (max of age tiers) + DNS oddities
    TLS      <= 15   one worst certificate problem (not summed)
    REDIRECT <= 15   redirect behaviour (sum, capped)
    ML       <= 35   35 * model phishing score (only if the model is available
                     and its predicted class is phishing; else 0)
    THREAT   <= 40   exact match in the local phishing feed (hostname or URL)

The ML score is uncalibrated, so it is a bounded contribution, not a probability.
Checks that did not run contribute 0 and are listed in `unavailable_checks`.
The category thresholds are fixed defaults (see docs); they are not claimed to be
statistically calibrated for real-world traffic.
"""

CATEGORY_LOWER = "Lower estimated risk"
CATEGORY_MEDIUM = "Medium estimated risk"
CATEGORY_HIGH = "High estimated risk"
CATEGORY_INSUFFICIENT = "Insufficient evidence"

URL_WEIGHTS = {
    "IP address hostname": 20, "'@' in URL": 8, "Internationalised hostname (punycode)": 6,
    "Many subdomains": 6, "Many hyphens in hostname": 3, "Heavy percent-encoding": 6,
    "Multiple sensitive keywords": 3, "Very long URL": 2, "Random-looking hostname": 3,
    "Not using HTTPS": 2,
}
TLS_WEIGHTS = {"hostname_mismatch": 15, "expired": 12, "verification_failed": 10}


def categorize(score: int) -> str:
    if score >= 60:
        return CATEGORY_HIGH
    if score >= 30:
        return CATEGORY_MEDIUM
    return CATEGORY_LOWER


def compute_risk(url_indicators: list, domain: dict, tls: dict, redirects: dict, ml: dict,
                 threat: dict | None = None) -> dict:
    contributions = []   # (group, points, reason)
    unavailable = []

    # URL structure
    url_pts = 0
    for ind in url_indicators:
        w = URL_WEIGHTS.get(ind["indicator_name"], 0)
        if w:
            url_pts += w
            contributions.append(("URL structure", w, ind["indicator_name"]))
    url_total = min(30, url_pts)

    # Domain
    dom_pts = 0
    if domain.get("dns_checked"):
        if domain.get("dns_error", "") and "NXDOMAIN" in domain["dns_error"]:
            dom_pts += 8
            contributions.append(("Domain", 8, "Domain does not exist in DNS"))
        elif domain.get("dns_error"):
            unavailable.append("DNS lookup (" + domain["dns_error"] + ")")
    else:
        unavailable.append("DNS lookup")
    if domain.get("non_public_ips"):
        dom_pts += 12
        contributions.append(("Domain", 12, "Hostname resolves to a non-public address"))
    age = domain.get("domain_age_days")
    if age is not None:
        tier = 20 if age < 30 else 12 if age < 90 else 4 if age < 365 else 0
        if tier:
            dom_pts += tier
            contributions.append(("Domain", tier, f"Recently registered domain ({age} days old)"))
    else:
        unavailable.append("Domain age (RDAP)")
    dom_total = min(25, dom_pts)

    # TLS: worst single problem
    tls_total = 0
    if tls.get("checked") and tls.get("status") in TLS_WEIGHTS:
        tls_total = TLS_WEIGHTS[tls["status"]]
        contributions.append(("TLS", tls_total, "Certificate problem: " + tls["status"].replace("_", " ")))
    elif not tls.get("checked"):
        unavailable.append("TLS certificate inspection")

    # Redirects
    red_pts = 0
    if redirects.get("performed"):
        if redirects.get("blocked"):
            red_pts += 10
            contributions.append(("Redirects", 10, "Redirect to blocked/non-public destination"))
        if redirects.get("loop_detected"):
            red_pts += 8
            contributions.append(("Redirects", 8, "Redirect loop"))
        if redirects.get("domain_changes", 0) >= 2:
            red_pts += 8
            contributions.append(("Redirects", 8, "Redirects across several domains"))
        if redirects.get("hops", 0) >= 3:
            red_pts += 4
            contributions.append(("Redirects", 4, "Long redirect chain"))
    else:
        unavailable.append("Redirect inspection")
    red_total = min(15, red_pts)

    # ML
    ml_total = 0
    if ml.get("available"):
        if ml.get("predicted_class") == "phishing" and ml.get("phishing_score") is not None:
            ml_total = round(35 * ml["phishing_score"])
            if ml_total:
                contributions.append(("Machine learning", ml_total, "Model classified URL as phishing-like"))
    else:
        unavailable.append("Machine-learning model")

    # Threat intelligence (local feed). A match is strong evidence; no match / no feed adds nothing.
    threat = threat or {"status": "unavailable"}
    threat_total = 0
    if threat.get("match"):
        threat_total = 40
        contributions.append(("Threat intelligence", 40, "Listed in the local phishing feed"))
    elif threat.get("status") == "unavailable":
        unavailable.append("Threat-intelligence feed")

    score = int(min(100, url_total + dom_total + tls_total + red_total + ml_total + threat_total))

    # Evidence sufficiency
    independent_checks = sum([
        bool(ml.get("available")),
        bool(domain.get("dns_checked") and not domain.get("dns_error")),
        age is not None,
        bool(tls.get("checked")),
        bool(redirects.get("performed")),
        threat.get("status") in ("match", "no_match"),
    ])
    category = categorize(score)
    if category == CATEGORY_LOWER and independent_checks < 2:
        category = CATEGORY_INSUFFICIENT

    contributions.sort(key=lambda c: -c[1])
    return {
        "score": score,
        "category": category,
        "breakdown": {"url_structure": url_total, "domain": dom_total, "tls": tls_total,
                      "redirects": red_total, "machine_learning": ml_total, "threat_intel": threat_total},
        "top_contributors": [{"group": g, "points": p, "reason": r} for g, p, r in contributions[:6]],
        "unavailable_checks": unavailable,
        "independent_checks_completed": independent_checks,
        "disclaimer": ("This is an estimate from limited automated checks. A low score does not mean a link "
                       "is safe, and a high score is not proof of malicious intent."),
    }


def build_recommendations(category: str, url_indicators: list, risk: dict, tls: dict, domain: dict) -> list[str]:
    recs = []
    names = {i["indicator_name"] for i in url_indicators}
    if category == CATEGORY_HIGH:
        recs.append("Do not open this link or enter any information on the destination page.")
    if category in (CATEGORY_HIGH, CATEGORY_MEDIUM, CATEGORY_INSUFFICIENT):
        recs.append("Verify the domain through an independent trusted source, such as the organization's official website typed in manually.")
        recs.append("Contact the organization through its official channels if the link claims to come from them.")
    if "IP address hostname" in names or "'@' in URL" in names:
        recs.append("Be cautious: the address format is commonly used to hide the true destination.")
    if domain.get("domain_age_days") is not None and domain["domain_age_days"] < 90:
        recs.append("The domain was registered recently; treat unexpected requests for credentials or payment with extra suspicion.")
    if tls.get("status") in TLS_WEIGHTS:
        recs.append("The site's certificate had problems. Do not proceed past browser security warnings.")
    recs.append("Avoid entering passwords or payment details on sites reached through unsolicited links, and avoid downloading unexpected files.")
    if risk["unavailable_checks"]:
        recs.append("Some checks could not run (" + ", ".join(risk["unavailable_checks"][:3]) + "), so this assessment is incomplete.")
    seen, out = set(), []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out
