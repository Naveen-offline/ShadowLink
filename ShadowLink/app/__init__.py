"""ShadowLink application factory."""
import click
from flask import Flask, jsonify, render_template, request

from .config import Config
from .extensions import csrf, db, limiter, login_manager


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from .routes import admin, auth, dashboard, history, reports, scanner

    for bp in (auth.bp, dashboard.bp, scanner.bp, history.bp, reports.bp, admin.bp):
        app.register_blueprint(bp)

    from .services.phishing_detector import PhishingDetector

    app.extensions["detector"] = PhishingDetector(app.config["MODEL_PATH"], app.config["MODEL_META_PATH"])

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; "
            "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        return resp

    def wants_json():
        return request.path.startswith("/api/") or request.is_json

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def http_error(err):
        code = getattr(err, "code", 500)
        messages = {
            400: "The request was invalid or the security token expired. Please reload and try again.",
            403: "You do not have permission to access this resource.",
            404: "The requested page or resource was not found.",
            405: "This method is not allowed here.",
            413: "The request was too large.",
            429: "Too many requests. Please slow down and try again shortly.",
        }
        if wants_json():
            return jsonify(error=messages.get(code, "Error")), code
        return render_template("error.html", code=code, message=messages.get(code, "Error")), code

    @app.errorhandler(500)
    def server_error(err):
        db.session.rollback()
        if wants_json():
            return jsonify(error="An internal error occurred."), 500
        return render_template("error.html", code=500, message="An internal error occurred."), 500

    @login_manager.unauthorized_handler
    def unauthorized():
        from flask import redirect, url_for

        if wants_json():
            return jsonify(error="Authentication required."), 401
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))

    with app.app_context():
        from . import models  # noqa: F401

        db.create_all()

    @app.cli.command("init-db")
    def init_db():
        """Create database tables."""
        db.create_all()
        click.echo("Database initialised.")

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--name", prompt=True)
    @click.password_option()
    def create_admin(email, name, password):
        """Create (or promote) an administrator account."""
        from .models import User

        user = User.query.filter_by(email=email.lower()).first()
        if user is None:
            user = User(full_name=name, email=email.lower())
            user.set_password(password)
            db.session.add(user)
        user.role = "admin"
        db.session.commit()
        click.echo(f"Admin ready: {user.email}")

    @app.cli.command("purge-old-scans")
    def purge_old_scans():
        """Delete scans older than SCAN_RETENTION_DAYS."""
        from datetime import timedelta

        from .models import Scan, utcnow

        cutoff = utcnow() - timedelta(days=app.config["SCAN_RETENTION_DAYS"])
        n = 0
        for scan in Scan.query.filter(Scan.created_at < cutoff).all():
            db.session.delete(scan)
            n += 1
        db.session.commit()
        click.echo(f"Deleted {n} scans.")

    return app
