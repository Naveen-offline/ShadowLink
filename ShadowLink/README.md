# ShadowLink — Intelligent Malicious Link Behavior Analyzer

A Flask web application that analyzes a suspicious URL **without opening it** and produces an explainable
0–100 risk estimate: URL structure, DNS/RDAP domain data, TLS certificate, optional redirect inspection,
a local phishing-feed lookup, and a scikit-learn model. Reports are stored per user and exportable as PDF.

> ShadowLink gives an **estimate with stated limitations**. It never labels a URL "safe".

## Features
Registration/login (Werkzeug hashes, Flask-Login, CSRF, rate limiting) · dashboard with DB-backed stats and Chart.js charts ·
scanner + 8-section result page · history (search, filter, sort, delete, own data only) · PDF export (ReportLab) ·
admin dashboard (role-based) · SSRF-hardened network layer · tests (pytest).

## Stack
Python 3.11+, Flask, Flask-SQLAlchemy/Login/WTF/Limiter, SQLite, scikit-learn, pandas, joblib, dnspython, requests,
tldextract (Public Suffix List snapshot), ReportLab, Bootstrap 5, Chart.js, Font Awesome (all vendored under `app/static/vendor`, so the UI works offline).

## Windows + VS Code setup
```powershell
git clone <your-repo-url> ShadowLink ; cd ShadowLink      # or open the folder in VS Code
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
copy .env.example .env              # then set SECRET_KEY to a long random string
flask --app run init-db             # creates instance\shadowlink.db
flask --app run create-admin        # prompts for email, name, password
```
In VS Code choose the `.venv` interpreter (Ctrl+Shift+P → *Python: Select Interpreter*).

### Dataset and model (already included; rebuild to refresh)
```powershell
python -m ml.preprocessing --download   # downloads public lists, writes ml\datasets\hostnames.csv
python -m ml.train_model                # compares LogReg vs RandomForest, saves ml\models\*
python -m ml.evaluate_model             # re-computes test metrics, checks they match the stored ones
python -m ml.build_blocklist            # optional: local phishing feed for the threat-intel check
```
### Run / test
```powershell
python run.py                           # http://127.0.0.1:5000
python -m pytest -q
```

## Configuration (`.env`)
`SECRET_KEY`, `DATABASE_URL`, `SESSION_COOKIE_SECURE` (true behind HTTPS), `DNS_ANALYSIS_ENABLED`, `RDAP_ENABLED`,
`TLS_INSPECTION_ENABLED`, `LIVE_FETCH_ENABLED` (**false by default**), `MAX_REDIRECTS`, `CONNECT_TIMEOUT`, `READ_TIMEOUT`, `SCAN_RETENTION_DAYS`.

## Machine-learning results (measured, held-out test split, n = 24,000)
| Model | Test F1 | Test ROC-AUC |
|---|---|---|
| Logistic Regression | 0.654 | 0.741 |
| **Random Forest (selected on validation F1)** | **0.675** | **0.762** |

Random Forest test: accuracy 0.698, precision 0.721, recall 0.635. These are **modest** and likely still optimistic:
the model sees only registered-domain text features, labels come from community lists, and the benign class is *popular*
domains. See `ml/datasets/README.md`, including the subdomain-shortcut bug found and fixed during development
(an earlier model reported F1 0.82 but scored `www.google.com` as phishing). The score is uncalibrated and is one bounded input to the risk score.

## Security notes and limitations
* Live HTTP fetching is off by default. When enabled, every hop is resolved by ShadowLink, all addresses must be public, the connection is pinned to the validated IP, redirects are re-validated, HEAD only, bounded hops/time/headers. For real deployments also run it in an egress-restricted container.
* The TLS check performs a verifying handshake only (never disables verification) to a validated public IP. A valid certificate does not make a site trustworthy.
* Reachability of DNS/RDAP/TLS depends on your network; unavailable checks are reported as unavailable and never counted as "clean".
* `joblib` files can execute code on load: only the locally trained artifact is loaded, after a SHA-256 check against its metadata.
* Rate limiting uses in-memory storage (single process). Use Redis for multi-worker deployments. SQLite is for development.
* Thresholds (30/60) are fixed defaults, not statistically calibrated.

## Screenshots
Placeholders: capture the landing page, dashboard, result page and admin page from your own run and add them to `docs/`.

## Future work
Browser extension, QR/email link analysis, external threat-intel APIs, scheduled monitoring, model retraining/calibration, containerized deployment.
