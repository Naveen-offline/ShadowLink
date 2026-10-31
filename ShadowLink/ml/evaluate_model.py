"""Re-evaluate the saved model on the same deterministic test split.

Run:  python -m ml.evaluate_model
Confirms reproducibility against the metrics stored at training time and writes
ml/models/evaluation_report.json.
"""
import json
import sys

import joblib

from ml.preprocessing import DATASET_CSV, load_dataset, make_features, split_train_val_test
from ml.train_model import META_PATH, MODEL_DIR, MODEL_PATH, metrics


def evaluate() -> dict:
    if not MODEL_PATH.exists() or not META_PATH.exists():
        sys.exit("No trained model found. Run: python -m ml.train_model")
    meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    df = load_dataset(DATASET_CSV)
    X, y, groups = make_features(df)
    _, _, te = split_train_val_test(X, y, groups)
    model = joblib.load(MODEL_PATH)  # trusted local artefact produced by train_model
    current = metrics(model, X.iloc[te], y[te])
    stored = meta["results"][meta["model_name"]]["test"]
    report = {
        "model": meta["model_name"], "version": meta["version"],
        "current_test_metrics": current, "stored_test_metrics": stored,
        "reproducible": all(abs(current[k] - stored[k]) < 1e-9 for k in ("accuracy", "precision", "recall", "f1")),
    }
    (MODEL_DIR / "evaluation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
