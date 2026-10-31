"""SQLAlchemy models. Schema follows the project specification; `result_json`
on Scan stores the full structured analysis so result pages and PDFs are
rendered from stored real analysis output."""
import json
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")  # user | admin
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    scans = db.relationship("Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    submitted_url = db.Column(db.String(2100), nullable=False)
    normalized_url = db.Column(db.String(2100))
    registered_domain = db.Column(db.String(255), index=True)
    risk_score = db.Column(db.Integer)
    risk_category = db.Column(db.String(32), index=True)
    prediction = db.Column(db.String(32))
    model_version = db.Column(db.String(64))
    scan_status = db.Column(db.String(16), nullable=False, default="completed")  # completed | failed
    result_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    findings = db.relationship("ScanFinding", backref="scan", lazy="select", cascade="all, delete-orphan")
    reports = db.relationship("ScanReport", backref="scan", lazy="select", cascade="all, delete-orphan")

    @property
    def details(self) -> dict:
        """Full structured analysis stored at scan time (never recomputed)."""
        try:
            return json.loads(self.result_json) if self.result_json else {}
        except ValueError:
            return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id, "submitted_url": self.submitted_url, "normalized_url": self.normalized_url,
            "registered_domain": self.registered_domain, "risk_score": self.risk_score,
            "risk_category": self.risk_category, "prediction": self.prediction,
            "model_version": self.model_version, "scan_status": self.scan_status,
            "created_at": self.created_at.isoformat() + "Z",
        }


class ScanFinding(db.Model):
    __tablename__ = "scan_findings"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    indicator_name = db.Column(db.String(80), nullable=False)
    indicator_value = db.Column(db.String(255))
    severity = db.Column(db.String(16), nullable=False)  # info | low | medium | high
    explanation = db.Column(db.Text)


class ScanReport(db.Model):
    __tablename__ = "scan_reports"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    report_path = db.Column(db.String(512), nullable=False)
    generated_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ApplicationLog(db.Model):
    __tablename__ = "application_logs"
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)
    event_message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


def log_event(event_type: str, message: str) -> None:
    """Record an activity/failure event. Callers must never pass secrets."""
    try:
        db.session.add(ApplicationLog(event_type=event_type, event_message=message[:500]))
        db.session.commit()
    except Exception:  # logging must never break a request
        db.session.rollback()


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
