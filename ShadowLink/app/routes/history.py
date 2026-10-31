from sqlalchemy import or_
from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..models import Scan, db

bp = Blueprint("history", __name__)


@bp.route("/history")
@login_required
def history_page():
    return render_template("history.html")


@bp.route("/api/history")
@login_required
def api_history():
    q = Scan.query.filter_by(user_id=current_user.id)
    search = (request.args.get("q") or "").strip()[:255]
    if search:
        like = "%" + search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"
        q = q.filter(or_(Scan.registered_domain.ilike(like, escape="\\"),
                         Scan.normalized_url.ilike(like, escape="\\")))
    category = request.args.get("category")
    if category:
        q = q.filter(Scan.risk_category == category)
    order = Scan.created_at.asc() if request.args.get("sort") == "oldest" else Scan.created_at.desc()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 15
    total = q.count()
    items = q.order_by(order).offset((page - 1) * per_page).limit(per_page).all()
    return jsonify({"items": [s.to_dict() for s in items], "total": total, "page": page,
                    "pages": max(1, -(-total // per_page))})


@bp.route("/api/history/<int:scan_id>", methods=["DELETE"])
@login_required
def delete_one(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return jsonify({"error": "Scan not found."}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"deleted": 1})


@bp.route("/api/history/bulk-delete", methods=["POST"])
@login_required
def bulk_delete():
    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids) or len(ids) > 200:
        return jsonify({"error": "Provide a list of up to 200 integer ids."}), 400
    scans = Scan.query.filter(Scan.user_id == current_user.id, Scan.id.in_(ids)).all()
    for s in scans:
        db.session.delete(s)
    db.session.commit()
    return jsonify({"deleted": len(scans)})
