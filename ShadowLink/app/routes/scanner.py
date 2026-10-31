from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from .. import limiter
from ..models import Scan, db, log_event
from ..services.scan_service import persist_scan, run_analysis
from ..services.url_validator import URLValidationError

bp = Blueprint("scanner", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/scanner")
@login_required
def scanner_page():
    return render_template("scanner.html", prefill=request.args.get("url", "")[:2048])


@bp.route("/results/<int:scan_id>")
@login_required
def results_page(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        abort(404)
    return render_template("results.html", scan=scan, d=scan.details)


@bp.route("/api/scan", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def api_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        return jsonify({"error": "Request body must be JSON with a 'url' string."}), 400
    try:
        result = run_analysis(payload["url"])
    except URLValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        db.session.rollback()
        log_event("scan_failure", "Unexpected error during analysis")
        return jsonify({"error": "The analysis failed unexpectedly. Please try again."}), 500
    try:
        scan = persist_scan(db, current_user.id, result)
    except Exception:
        db.session.rollback()
        log_event("scan_failure", "Database error while saving scan")
        return jsonify({"error": "The result could not be saved."}), 500
    return jsonify({"scan_id": scan.id, "risk_score": scan.risk_score,
                    "risk_category": scan.risk_category, "redirect_url": f"/results/{scan.id}"}), 201


@bp.route("/api/scan/<int:scan_id>")
@login_required
def api_scan_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({**scan.to_dict(), "details": scan.details})
