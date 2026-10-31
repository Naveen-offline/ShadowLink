import hashlib
import json

import joblib
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from app import create_app
from app.config import TestConfig
from app.models import User, db
from app.services.feature_extractor import ML_FEATURE_NAMES

PASSWORD = "Str0ng!Passw0rd"


@pytest.fixture(scope="session")
def tiny_model_dir(tmp_path_factory):
    """A tiny, hermetic model trained on synthetic rows. Used only to test plumbing,
    never to make any claim about detection quality."""
    d = tmp_path_factory.mktemp("model")
    import numpy as np
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.integers(0, 20, size=(200, len(ML_FEATURE_NAMES))), columns=ML_FEATURE_NAMES)
    y = (X["num_hyphens"] + X["num_digits"] > 19).astype(int)
    model = RandomForestClassifier(n_estimators=5, random_state=0).fit(X, y)
    mp = d / "m.joblib"
    joblib.dump(model, mp)
    meta = {"version": "test-1", "model_name": "RandomForest", "feature_names": ML_FEATURE_NAMES,
            "sha256": hashlib.sha256(mp.read_bytes()).hexdigest(), "results": {}}
    (d / "meta.json").write_text(json.dumps(meta))
    return d


@pytest.fixture
def app(tmp_path, tiny_model_dir):
    class Cfg(TestConfig):
        MODEL_PATH = tiny_model_dir / "m.joblib"
        MODEL_META_PATH = tiny_model_dir / "meta.json"
        REPORT_DIR = tmp_path / "reports"
    application = create_app(Cfg)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def make_user(email="user@example.com", role="user", name="Test User"):
    u = User(full_name=name, email=email, role=role)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, email="user@example.com", password=PASSWORD):
    return client.post("/auth/login", data={"email": email, "password": password})


@pytest.fixture
def logged_in(client):
    make_user()
    login(client)
    return client
