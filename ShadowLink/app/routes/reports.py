import uuid
from pathlib import Path

from flask import Blueprint, current_app, jsonify, send_file
from flask_login import current_user, login_required

from ..models import Scan, ScanReport, db, log_event
from ..services.report_generator import generate_pdf

bp = Blueprint("reports", __name__)


@bp.route("/api/report/<int:scan_id>/pdf")
@login_required
def pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return jsonify({"error": "Scan not found."}), 404
    report_dir = Path(current_app.config["REPORT_DIR"])
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"scan_{scan.id}_{uuid.uuid4().hex[:8]}.pdf"  # server-generated name only
    try:
        generate_pdf(scan, path)
        db.session.add(ScanReport(scan_id=scan.id, report_path=path.name))
        db.session.commit()
    except Exception:
        db.session.rollback()
        log_event("report_failure", f"PDF generation failed for scan {scan.id}")
        return jsonify({"error": "The report could not be generated."}), 500
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=f"shadowlink_report_{scan.id}.pdf")
