# Architecture

```
Browser ──HTTP──> Flask app (app/)
  routes/   auth, dashboard, scanner, history, reports, admin   (authN/authZ, CSRF, rate limits)
  services/ scan_service.run_analysis orchestrates:
     url_validator -> feature_extractor -> threat_intel -> domain_analyzer (DNS, RDAP)
        -> certificate_analyzer (TLS handshake) -> redirect_analyzer (optional)
        -> phishing_detector (joblib model) -> risk_engine -> persisted as Scan.result_json + ScanFinding rows
  report_generator (ReportLab) renders the stored result; models.py (SQLAlchemy / SQLite)
ml/   preprocessing, train_model, evaluate_model, build_blocklist  (offline; writes ml/models/*)
```
Module connections: `scan_service` is the only place the analyzers are combined. Every analyzer returns plain dicts
(with `status`/`checked`/`message` or `available`) so result page, PDF and risk engine read one schema.
All sockets go through `net_guard` (single source of truth for the SSRF rules; `ssrf_guard` is a thin adapter).

## Database
`users`(id, full_name, email*, password_hash, role, created_at) · `scans`(id, user_id→users, submitted_url, normalized_url,
registered_domain*, risk_score, risk_category*, prediction, model_version, scan_status, result_json, created_at*) ·
`scan_findings`(id, scan_id→scans, indicator_name, indicator_value, severity, explanation) ·
`scan_reports`(id, scan_id→scans, report_path, generated_at) · `application_logs`(id, event_type*, event_message, created_at*). (* = indexed)
Deleting a user or scan cascades to dependent rows.

## Risk score
`score = min(100, URL + DOMAIN + TLS + REDIRECT + ML + THREAT)` with caps URL 30, DOMAIN 25, TLS 15 (worst single problem),
REDIRECT 15, ML 35 (`35 × model score`, only when predicted phishing), THREAT 40 (exact match in local feed).
Categories: 0–29 lower, 30–59 medium, 60–100 high estimated risk. "Insufficient evidence" replaces "lower" when fewer than two
independent checks completed. Checks that did not run add 0 and are listed as unavailable.

## SSRF controls
Scheme allow-list; private/loopback/link-local/multicast/reserved/metadata IPs blocked (including decimal/hex/octal/IPv4-mapped forms);
internal hostnames blocked; DNS answers validated (mixed public/private rejected); connection pinned to validated IP; every redirect re-validated;
HEAD only; timeouts and size limits; no credentials/cookies sent; TLS verification always on.
