from collections import defaultdict
from datetime import timedelta

from flask import Blueprint, jsonify, render_template
from flask_login import current_user, login_required
from sqlalchemy import func

from ..models import Scan, db, utcnow
from ..services.risk_engine import CATEGORY_HIGH, CATEGORY_INSUFFICIENT, CATEGORY_LOWER, CATEGORY_MEDIUM

bp = Blueprint("dashboard", __name__)


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@bp.route("/api/dashboard/stats")
@login_required
def stats():
    uid = current_user.id
    base = Scan.query.filter_by(user_id=uid)
    total = base.count()
    counts = dict(db.session.query(Scan.risk_category, func.count(Scan.id))
                  .filter(Scan.user_id == uid).group_by(Scan.risk_category).all())
    since = utcnow() - timedelta(days=13)
    rows = base.filter(Scan.created_at >= since.replace(hour=0, minute=0, second=0, microsecond=0)).all()
    per_day, score_sum = defaultdict(int), defaultdict(int)
    for s in rows:
        d = s.created_at.date().isoformat()
        per_day[d] += 1
        score_sum[d] += s.risk_score or 0
    days = [(since + timedelta(days=i)).date().isoformat() for i in range(14)]
    recent = base.order_by(Scan.created_at.desc()).limit(8).all()
    return jsonify({
        "total": total,
        "high": counts.get(CATEGORY_HIGH, 0),
        "medium": counts.get(CATEGORY_MEDIUM, 0),
        "lower": counts.get(CATEGORY_LOWER, 0),
        "insufficient": counts.get(CATEGORY_INSUFFICIENT, 0),
        "daily": {"labels": days, "counts": [per_day.get(d, 0) for d in days]},
        "trend": {"labels": days,
                  "avg_score": [round(score_sum[d] / per_day[d], 1) if per_day.get(d) else None for d in days]},
        "recent": [s.to_dict() for s in recent],
    })
