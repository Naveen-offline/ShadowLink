"""Loads the trained scikit-learn model and produces predictions.

Only a locally trained artifact from ml/models/ is loaded, and its SHA-256 must match
the value recorded in model_metadata.json at training time (integrity check). Never load
joblib files from untrusted sources: joblib/pickle can execute code on load.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from .feature_extractor import ML_FEATURE_NAMES, ml_vector


class ModelUnavailable(Exception):
    pass


class PhishingDetector:
    def __init__(self, model_path, metadata_path):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.model = None
        self.metadata = {}
        self.error = None
        self._load()

    def _load(self):
        try:
            if not self.model_path.exists() or not self.metadata_path.exists():
                raise ModelUnavailable("Model file not found. Run: python -m ml.train_model")
            self.metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            digest = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
            if digest != self.metadata.get("sha256"):
                raise ModelUnavailable("Model integrity check failed (hash mismatch). Retrain the model.")
            if self.metadata.get("feature_names") != ML_FEATURE_NAMES:
                raise ModelUnavailable("Model feature schema does not match the application. Retrain the model.")
            self.model = joblib.load(self.model_path)
        except ModelUnavailable as exc:
            self.error = str(exc)
        except Exception:
            self.error = "Model could not be loaded."

    @property
    def available(self) -> bool:
        return self.model is not None

    @property
    def version(self) -> str:
        return self.metadata.get("version", "unavailable")

    def predict(self, features: dict) -> dict:
        if not self.available:
            return {"available": False, "message": self.error or "Model unavailable.",
                    "model_version": self.version}
        vec = pd.DataFrame([ml_vector(features)], columns=ML_FEATURE_NAMES)
        label = int(self.model.predict(vec)[0])
        proba = None
        if hasattr(self.model, "predict_proba"):
            proba = float(self.model.predict_proba(vec)[0][1])
        return {
            "available": True,
            "predicted_class": "phishing" if label == 1 else "benign",
            "phishing_score": round(proba, 4) if proba is not None else None,
            "score_note": ("Uncalibrated model output based only on the registered domain; not a probability of maliciousness. "
                           "Treat as one signal among several."),
            "features": {k: features.get(k, 0) for k in ML_FEATURE_NAMES},
            "model_name": self.metadata.get("model_name"),
            "model_version": self.version,
            "predicted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
