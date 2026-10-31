# API
All state-changing requests need the CSRF token (`X-CSRFToken` header; the page `<meta name="csrf-token">`). JSON errors: `{"error": "..."}`.

| Method & path | Auth | Description |
|---|---|---|
| POST `/auth/register` | – | form: full_name, email, password, confirm |
| POST `/auth/login` | – | form: email, password, remember; rate limited (`LOGIN_RATE_LIMIT`) |
| POST `/auth/logout` | user | |
| POST `/api/scan` | user | `{"url": "..."}` → 201 `{scan_id, risk_score, risk_category, redirect_url}`; 400 invalid/blocked URL |
| GET `/api/scan/<id>` | owner | scan summary + `details` (full analysis); 404 for other users' scans |
| GET `/api/history` | user | query: `q` (domain/URL), `category`, `sort`=newest\|oldest, `page` |
| DELETE `/api/history/<id>` | owner | |
| POST `/api/history/bulk-delete` | user | `{"ids": [..]}` (max 200) |
| GET `/api/dashboard/stats` | user | totals per category, 14-day counts, trend, recent scans |
| GET `/api/report/<id>/pdf` | owner | PDF download |
| GET `/api/admin/stats` | admin | counts, health, model info, config, failures, logs |
| POST `/api/admin/reload-model`, `/api/admin/purge-old` | admin | |
