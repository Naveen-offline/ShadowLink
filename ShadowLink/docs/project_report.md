# ShadowLink — College Project Report (draft)

*Fill in names, guide, institution and date. Add your own literature survey citations; none are invented here.*

## 1. Abstract
ShadowLink is a web application that estimates the risk of a URL without visiting it. It combines rule-based URL analysis, DNS/RDAP and TLS
observations, an optional SSRF-hardened redirect inspector, a local phishing-feed lookup and a scikit-learn classifier into an explainable
0–100 score, stored per user and exportable as PDF. On a held-out domain-grouped test split (24,000 domains) the selected Random Forest reached
F1 = 0.675 and ROC-AUC = 0.762, which is modest and probably optimistic (see §15).

## 2. Introduction
Phishing links imitate trusted brands to steal credentials. Users usually judge a link by appearance or the HTTPS padlock, which is unreliable.

## 3. Problem statement
Give non-expert users a way to inspect a link safely, understand *why* it looks risky, and see what could not be checked.

## 4. Existing system
Browser warnings and public reputation services rely on blocklists and reveal little reasoning. (Cite specific services you studied.)

## 5. Proposed system
Multi-signal, transparent scoring with explicit unavailable-check reporting, a per-user history and reports, and security-first design for handling untrusted URLs.

## 6. Objectives
Validate/normalize URLs; extract features; inspect domain, TLS, redirects; train and compare two classifiers; explain a bounded risk score; authenticate users; export PDFs; test the security controls.

## 7. Literature survey
Write this section from papers you read. Suggested themes: lexical URL features for phishing detection; blocklist-based protection; machine-learning classifiers
(Random Forest: Breiman, *Machine Learning* 45(1), 2001; scikit-learn: Pedregosa et al., *JMLR* 12, 2011); SSRF prevention (OWASP SSRF Prevention Cheat Sheet); RDAP (RFC 7480–7484).
Verify each citation yourself before submission.

## 8. System requirements
Python 3.11+, 4 GB RAM, any modern browser; Windows 10/11 with VS Code. Packages: see `requirements.txt`.

## 9. System architecture / 10. Modules
See `docs/architecture.md` (modules, database schema, data flow).

## 11. Methodology
Data: Phishing.Database ACTIVE list (label 1, MIT) and a top-1M domain ranking (label 0). Every entry is reduced to its registered domain (Public Suffix List),
deduplicated, ambiguous overlaps removed, 60,000 per class sampled (seed 42), split 60/20/20 grouped by domain. 15 lexical features (length, digits, hyphens, entropy, vowel ratio, TLD length, keywords…).
Selection by validation F1; final metrics on the untouched test split.

## 12. Algorithms
Logistic Regression (standardized features) and Random Forest (100 trees, depth ≤ 18, min leaf 20). Risk engine: capped additive score (formula in `docs/architecture.md`).

## 13. Implementation
Flask blueprints + service layer; SQLAlchemy models; Chart.js dashboard; ReportLab PDF; Joblib model with SHA-256 integrity check.

## 14. Testing
`python -m pytest -q` → 156 tests passed in the final run (functional, security, ML plumbing, with mocked network). They cover auth, CSRF, rate limiting, SQL-injection and XSS payloads, authorization between users, SSRF rules, redirect/TLS/DNS handling with mocks, PDF generation, and feature/model consistency.
A live end-to-end run against the real server (register, login, scan, PDF, admin 403) and a browser render of all pages with zero console/CSP errors were also performed. TLS, RDAP and live-fetch checks could not be exercised against real internet hosts in the development sandbox (network allow-list); they are tested with mocks only.

## 15. Results and discussion
| Model | Val F1 | Test accuracy | Test precision | Test recall | Test F1 | Test ROC-AUC |
|---|---|---|---|---|---|---|
| Logistic Regression | 0.653 | – | – | – | 0.654 | 0.741 |
| Random Forest | 0.674 | 0.698 | 0.721 | 0.635 | 0.675 | 0.762 |

Confusion matrix (Random Forest, test; rows = actual benign/phishing): [[9219, 2916], [4332, 7533]].
**An important finding:** the first model trained on full hostnames reported F1 0.82 / ROC-AUC 0.91, but it had learned that subdomains imply phishing
(`www.google.com` → 0.98). Restricting both classes to registered domains removed the shortcut and lowered the metrics to the values above. Remaining weaknesses: weak labels,
popular-vs-reported domain bias, no content/reputation features. Treat the model as one weak signal.

## 16. Advantages
Explainable; honest about missing evidence; works offline of external services; safe handling of untrusted URLs; offline-capable UI.

## 17. Limitations
Modest ML accuracy; fixed uncalibrated thresholds; in-memory rate limiter; SQLite; local feed is a snapshot; no page-content analysis.

## 18. Future enhancements
Calibration on a realistic validation set; content/reputation features; browser extension; QR and email scanning; scheduled monitoring; containerized deployment.

## 19. Conclusion
ShadowLink demonstrates a complete, secure pipeline for link risk estimation and, equally, how dataset artifacts can silently inflate ML metrics.

## 20. References
1. Breiman, L. Random Forests. *Machine Learning* 45(1), 5–32, 2001.
2. Pedregosa et al. Scikit-learn: Machine Learning in Python. *JMLR* 12, 2825–2830, 2011.
3. OWASP. Server-Side Request Forgery Prevention Cheat Sheet.
4. Public Suffix List, https://publicsuffix.org
5. Phishing.Database, https://github.com/mitchellkrogza/Phishing.Database (MIT).
6. zer0h/top-1000000-domains, https://github.com/zer0h/top-1000000-domains
