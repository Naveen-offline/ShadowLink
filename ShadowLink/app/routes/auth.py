from urllib.parse import urljoin, urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .. import limiter
from ..forms import ChangePasswordForm, LoginForm, RegisterForm, password_problems  # noqa: F401
from ..models import User, db, log_event

bp = Blueprint("auth", __name__)

# Used to equalise timing when the account does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def _safe_next(target):
    if not target:
        return None
    host = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, target))
    if test.scheme in ("http", "https") and host.netloc == test.netloc and target.startswith("/") and not target.startswith("//"):
        return target
    return None


@bp.route("/auth/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            form.email.errors.append("An account with this email already exists.")
        else:
            user = User(full_name=form.full_name.data.strip(), email=email, role="user")
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            log_event("register", f"New user registered (id={user.id})")
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@bp.route("/auth/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            ok = user.check_password(form.password.data)
        else:
            check_password_hash(_DUMMY_HASH, form.password.data)  # equalise timing
            ok = False
        if user and ok:
            login_user(user, remember=form.remember.data)
            log_event("login", f"User logged in (id={user.id})")
            return redirect(_safe_next(request.args.get("next")) or url_for("dashboard.dashboard"))
        log_event("login_failed", "Failed login attempt")
        flash("Invalid email or password.", "danger")
    return render_template("login.html", form=form)


@bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("scanner.index"))


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            form.current.errors.append("Current password is incorrect.")
        else:
            current_user.set_password(form.password.data)
            db.session.commit()
            log_event("password_change", f"Password changed (id={current_user.id})")
            flash("Password updated.", "success")
            return redirect(url_for("auth.settings"))
    return render_template("settings.html", form=form)
