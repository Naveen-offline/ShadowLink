from datetime import timedelta
from functools import wraps

from flask import Blueprint, abort, current_app, jsonify, render_template
from flask_login import current_user, login_required
from sqlalchemy import func, text

from ..models import ApplicationLog, Scan, User, db, log_event, utcnow
from ..services.scan_service import get_detector

bp = Blueprint("admin", __name__)


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.is_admin:
            abort(403)
        return fn(*a, **kw)
    return wrapper


@bp.route("/admin")
@admin_required
def admin_page():
    return render_template("admin.html")


@bp.route("/api/admin/stats")
@admin_required
def stats():
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    det = get_detector()
    cfg = current_app.config
    cats = dict(db.session.query(Scan.risk_category, func.count(Scan.id)).group_by(Scan.risk_category).all())
    day_ago = utcnow() - timedelta(days=1)
    logs = ApplicationLog.query.order_by(ApplicationLog.created_at.desc()).limit(30).all()
    failures = ApplicationLog.query.filter(ApplicationLog.event_type.like("%failure")).order_by(
        ApplicationLog.created_at.desc()).limit(15).all()
    meta = det.metadata or {}
    return jsonify({
        "users": User.query.count(),
        "scans_total": Scan.query.count(),
        "scans_24h": Scan.query.filter(Scan.created_at >= day_ago).count(),
        "categories": cats,
        "health": {"database": db_ok, "model_loaded": det.available, "model_error": det.error},
        "model": {"version": det.version, "name": meta.get("model_name"), "trained_at": meta.get("trained_at"),
                  "test_metrics": (meta.get("results", {}).get(meta.get("model_name"), {}) or {}).get("test")},
        "config": {k: cfg[k] for k in ("DNS_ANALYSIS_ENABLED", "TLS_INSPECTION_ENABLED", "RDAP_ENABLED",
                                       "LIVE_FETCH_ENABLED", "MAX_REDIRECTS", "CONNECT_TIMEOUT", "READ_TIMEOUT",
                                       "SCAN_RETENTION_DAYS")},
        "failures": [{"type": l.event_type, "message": l.event_message, "at": l.created_at.isoformat() + "Z"} for l in failures],
        "logs": [{"type": l.event_type, "message": l.event_message, "at": l.created_at.isoformat() + "Z"} for l in logs],
    })


@bp.route("/api/admin/reload-model", methods=["POST"])
@admin_required
def reload_model():
    det = get_detector(force_reload=True)
    log_event("admin", f"Model reload requested by admin id={current_user.id}")
    return jsonify({"model_loaded": det.available, "version": det.version, "error": det.error})


@bp.route("/api/admin/purge-old", methods=["POST"])
@admin_required
def purge_old():
    days = current_app.config["SCAN_RETENTION_DAYS"]
    if days <= 0:
        return jsonify({"deleted": 0, "message": "Retention is disabled."})
    old = Scan.query.filter(Scan.created_at < utcnow() - timedelta(days=days)).all()
    for s in old:
        db.session.delete(s)
    db.session.commit()
    log_event("admin", f"Purged {len(old)} scans older than {days} days")
    return jsonify({"deleted": len(old)})
