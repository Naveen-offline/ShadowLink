from app.models import User, db
from tests.conftest import PASSWORD, login, make_user


def reg(client, **over):
    data = {"full_name": "Ada Lovelace", "email": "ada@example.com", "password": PASSWORD, "confirm": PASSWORD}
    data.update(over)
    return client.post("/auth/register", data=data)


def test_registration_success_and_password_is_hashed(client):
    r = reg(client)
    assert r.status_code == 302
    u = User.query.filter_by(email="ada@example.com").first()
    assert u is not None and u.password_hash != PASSWORD and PASSWORD not in u.password_hash
    assert u.check_password(PASSWORD)
    assert u.role == "user"


def test_duplicate_email_rejected(client):
    reg(client)
    r = reg(client, full_name="Other")
    assert r.status_code == 200 and b"already exists" in r.data
    assert User.query.count() == 1


def test_weak_password_rejected(client):
    r = reg(client, password="short", confirm="short")
    assert r.status_code == 200 and b"Password needs" in r.data
    assert User.query.count() == 0


def test_password_mismatch_rejected(client):
    r = reg(client, confirm="Different!Passw0rd")
    assert b"Passwords must match" in r.data


def test_login_success_and_logout(client):
    make_user()
    r = login(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200
    # Logout must be POST
    assert client.get("/auth/logout").status_code == 405
    assert client.post("/auth/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_invalid_login_generic_message(client):
    make_user()
    r1 = login(client, password="Wrong!Passw0rd1")
    r2 = login(client, email="nobody@example.com")
    for r in (r1, r2):
        assert r.status_code == 200 and b"Invalid email or password" in r.data


def test_open_redirect_blocked(client):
    make_user()
    r = client.post("/auth/login?next=https://evil.example/", data={"email": "user@example.com", "password": PASSWORD})
    assert r.headers["Location"].endswith("/dashboard")
    r = client.post("/auth/login?next=//evil.example", data={"email": "user@example.com", "password": PASSWORD})
    assert "evil" not in r.headers["Location"]


def test_protected_pages_require_login(client):
    for path in ("/dashboard", "/scanner", "/history", "/settings"):
        r = client.get(path)
        assert r.status_code == 302 and "/auth/login" in r.headers["Location"]
    assert client.post("/api/scan", json={"url": "https://example.com"}).status_code in (302, 401)


def test_admin_forbidden_for_regular_user(logged_in):
    assert logged_in.get("/admin").status_code == 403
    assert logged_in.get("/api/admin/stats").status_code == 403
    assert logged_in.post("/api/admin/purge-old").status_code == 403


def test_admin_allowed(client):
    make_user("admin@example.com", role="admin")
    login(client, "admin@example.com")
    r = client.get("/api/admin/stats")
    assert r.status_code == 200
    j = r.get_json()
    assert j["health"]["database"] is True and j["model"]["version"] == "test-1"
    assert "password" not in str(j).lower()
