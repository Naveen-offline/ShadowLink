"""Train and compare Logistic Regression and Random Forest; save the better one.

Run:  python -m ml.train_model
Selection uses the VALIDATION split (F1, ties by ROC-AUC). Final metrics are reported
on a held-out TEST split that was not used for any choice. Nothing here is hard-coded.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.services.feature_extractor import ML_FEATURE_NAMES
from ml.preprocessing import DATASET_CSV, SEED, load_dataset, make_features, split_train_val_test

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
META_PATH = MODEL_DIR / "model_metadata.json"


def candidates():
    return {
        "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=SEED)),
        "RandomForest": RandomForestClassifier(n_estimators=100, min_samples_leaf=20, max_depth=18, n_jobs=-1, random_state=SEED),
    }


def metrics(model, X, y) -> dict:
    pred = model.predict(X)
    out = {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1]).tolist(),
        "n": int(len(y)),
    }
    if hasattr(model, "predict_proba") and len(set(y)) == 2:
        p = model.predict_proba(X)[:, 1]
        out["roc_auc"] = roc_auc_score(y, p)
        out["brier_score"] = brier_score_loss(y, p)
    return {k: (round(float(v), 4) if isinstance(v, (float, np.floating)) else v) for k, v in out.items()}


def main(dataset=DATASET_CSV):
    if not Path(dataset).exists():
        sys.exit(f"Dataset not found: {dataset}\nBuild it first: python -m ml.preprocessing --download")
    df = load_dataset(dataset)
    X, y, groups = make_features(df)
    tr, va, te = split_train_val_test(X, y, groups)
    # Leakage guard: no registered domain appears in more than one split.
    assert not (set(groups[tr]) & set(groups[va]) or set(groups[tr]) & set(groups[te]) or set(groups[va]) & set(groups[te]))

    results = {}
    fitted = {}
    for name, model in candidates().items():
        model.fit(X.iloc[tr], y[tr])
        fitted[name] = model
        results[name] = {"validation": metrics(model, X.iloc[va], y[va]), "test": metrics(model, X.iloc[te], y[te])}
        print(f"{name}: val F1={results[name]['validation']['f1']}  test F1={results[name]['test']['f1']}")

    best = max(results, key=lambda n: (results[n]["validation"]["f1"], results[n]["validation"].get("roc_auc", 0)))
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(fitted[best], MODEL_PATH)
    sha = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    now = datetime.now(timezone.utc)
    meta = {
        "version": now.strftime("%Y.%m.%d") + "-" + sha[:7],
        "model_name": best,
        "trained_at": now.isoformat(timespec="seconds"),
        "sha256": sha,
        "feature_names": ML_FEATURE_NAMES,
        "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "dataset": {"file": str(Path(dataset).name), "rows": int(len(df)),
                    "phishing": int(y.sum()), "benign": int((y == 0).sum()),
                    "train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
        "selection_rule": "highest validation F1 (ties: ROC-AUC)",
        "results": results,
        "notes": ("Hostname-only features. Metrics are on a domain-grouped holdout of this specific dataset "
                  "and will likely overstate real-world performance; probabilities are uncalibrated."),
    }
    META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Selected {best}. Saved {MODEL_PATH.name} and {META_PATH.name}")
    print(json.dumps(results[best]["test"], indent=2))


if __name__ == "__main__":
    main()
