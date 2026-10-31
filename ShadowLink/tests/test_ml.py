import hashlib
import json

import numpy as np
import pandas as pd
import pytest

from app.services.feature_extractor import ML_FEATURE_NAMES, ml_features_from_host
from app.services.phishing_detector import PhishingDetector
from ml.preprocessing import load_dataset, make_features, split_train_val_test


def det(d):
    return PhishingDetector(d / "m.joblib", d / "meta.json")


def test_model_loads_and_predicts_expected_format(tiny_model_dir):
    d = det(tiny_model_dir)
    assert d.available and d.version == "test-1"
    out = d.predict(ml_features_from_host("login-secure.verify.example-xyz.com"))
    assert out["predicted_class"] in ("phishing", "benign") and 0 <= out["phishing_score"] <= 1
    assert set(out["features"]) == set(ML_FEATURE_NAMES) and out["model_version"] == "test-1"
    assert out["predicted_at"] and "Uncalibrated" in out["score_note"]


def test_missing_features_do_not_crash(tiny_model_dir):
    assert det(tiny_model_dir).predict({})["available"] is True


def test_missing_model_file_reported(tmp_path):
    d = PhishingDetector(tmp_path / "nope.joblib", tmp_path / "nope.json")
    out = d.predict({})
    assert d.available is False and out["available"] is False and "not found" in out["message"].lower()


def test_tampered_model_rejected(tiny_model_dir, tmp_path):
    import shutil
    shutil.copy(tiny_model_dir / "m.joblib", tmp_path / "m.joblib")
    meta = json.loads((tiny_model_dir / "meta.json").read_text())
    meta["sha256"] = "0" * 64
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    d = det(tmp_path)
    assert d.available is False and "integrity" in d.error.lower()


def test_schema_mismatch_rejected(tiny_model_dir, tmp_path):
    import shutil
    shutil.copy(tiny_model_dir / "m.joblib", tmp_path / "m.joblib")
    meta = json.loads((tiny_model_dir / "meta.json").read_text())
    meta["feature_names"] = ["wrong"]
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    assert "schema" in det(tmp_path).error.lower()


def test_training_and_prediction_use_same_feature_function():
    df = pd.DataFrame({"host": ["login.example.com"], "label": [1]})
    X, _, _ = make_features(df)
    assert list(X.columns) == ML_FEATURE_NAMES
    assert X.iloc[0].to_dict() == {k: float(v) if not isinstance(v, int) else v for k, v in ml_features_from_host("login.example.com").items()} or \
        X.iloc[0].tolist() == list(ml_features_from_host("login.example.com").values())


def synthetic_csv(tmp_path):
    rng = np.random.default_rng(1)
    rows = []
    for i in range(400):
        rows.append((f"site{i}.example{i % 80}.com", int(i % 2)))
    rows += [("dup.example.com", 1), ("dup.example.com", 1), ("", 1), ("x.example.com", None), ("y.example.com", "phishing")]
    p = tmp_path / "d.csv"
    pd.DataFrame(rows, columns=["host", "label"]).to_csv(p, index=False)
    return p


def test_preprocessing_cleans_dedups_and_normalises_labels(tmp_path):
    df = load_dataset(synthetic_csv(tmp_path))
    assert df.host.is_unique and set(df.label.unique()) <= {0, 1}
    assert (df.host != "").all() and "x.example.com" not in set(df.host)
    assert df[df.host == "y.example.com"].label.iloc[0] == 1


def test_split_is_deterministic_and_leak_free(tmp_path):
    df = load_dataset(synthetic_csv(tmp_path))
    X, y, g = make_features(df)
    a = split_train_val_test(X, y, g)
    b = split_train_val_test(X, y, g)
    assert all((x == z).all() for x, z in zip(a, b))
    tr, va, te = a
    assert not (set(g[tr]) & set(g[va])) and not (set(g[tr]) & set(g[te])) and not (set(g[va]) & set(g[te]))
    assert len(set(tr) | set(va) | set(te)) == len(df)


def test_evaluation_reproducible(tmp_path):
    from sklearn.linear_model import LogisticRegression
    from ml.train_model import metrics
    df = load_dataset(synthetic_csv(tmp_path))
    X, y, g = make_features(df)
    tr, _, te = split_train_val_test(X, y, g)
    m1 = metrics(LogisticRegression(max_iter=500, random_state=42).fit(X.iloc[tr], y[tr]), X.iloc[te], y[te])
    m2 = metrics(LogisticRegression(max_iter=500, random_state=42).fit(X.iloc[tr], y[tr]), X.iloc[te], y[te])
    assert m1 == m2 and {"accuracy", "precision", "recall", "f1", "confusion_matrix", "roc_auc"} <= set(m1)
