"""Dataset preparation, feature extraction and leakage-safe splitting.

CLI:
    python -m ml.preprocessing --download           # fetch public sources and build ml/datasets/hostnames.csv
    python -m ml.preprocessing --phish FILE --benign FILE   # build from local copies

Labels: 1 = phishing (listed in Phishing.Database ACTIVE list), 0 = benign (listed in a top-domains ranking).
The `host` column holds each entry's registered domain.
See ml/datasets/README.md for sources, licensing and limitations.
"""
import argparse
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from app.services.feature_extractor import ML_FEATURE_NAMES, ml_features_from_host, registered_domain_of
from app.services.url_validator import _extract

DATASET_DIR = Path(__file__).resolve().parent / "datasets"
DATASET_CSV = DATASET_DIR / "hostnames.csv"
SEED = 42

PHISH_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
BENIGN_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"


def download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)  # fixed trusted URLs only
    return dest


def _host_from_url(line: str):
    line = line.strip()
    if not line:
        return None
    try:
        p = urlsplit(line if "://" in line else "http://" + line)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    return host or None


def build_dataset(phish_path, benign_path, out_csv=DATASET_CSV, n_per_class=60000, seed=SEED) -> pd.DataFrame:
    # Both classes are reduced to their REGISTERED DOMAIN (Public Suffix List). The benign source lists
    # only registered domains, so keeping subdomains for phishing would teach the model to detect the
    # source format instead of phishing (see ml/datasets/README.md).
    to_domain = lambda h: registered_domain_of(h)[0] if h else None
    phish_hosts = pd.Series([to_domain(_host_from_url(l)) for l in Path(phish_path).read_text(errors="ignore").splitlines()])
    benign_hosts = pd.Series([to_domain(_host_from_url(l)) for l in Path(benign_path).read_text(errors="ignore").splitlines()])
    phish = pd.DataFrame({"host": phish_hosts.dropna().drop_duplicates()})
    benign = pd.DataFrame({"host": benign_hosts.dropna().drop_duplicates()})
    # Domains present in both sources are ambiguous (e.g. phishing pages hosted on popular sites): drop from both.
    both = set(phish.host) & set(benign.host)
    phish = phish[~phish.host.isin(both)]
    benign = benign[~benign.host.isin(both)]
    # Keep the most popular benign domains (list is rank-ordered), then sample phishing hosts.
    benign = benign.head(max(n_per_class * 2, n_per_class)).sample(n=min(n_per_class, len(benign)), random_state=seed)
    phish = phish.sample(n=min(n_per_class, len(phish)), random_state=seed)
    phish["label"], benign["label"] = 1, 0
    df = pd.concat([phish, benign], ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    df.to_csv(out_csv, index=False)
    return df


def load_dataset(path=DATASET_CSV) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df.dropna(subset=["host", "label"])               # missing values
    df["host"] = df["host"].astype(str).str.strip().str.lower()
    df = df[df.host != ""]
    df["label"] = df["label"].map({1: 1, 0: 0, "1": 1, "0": 0, "phishing": 1, "benign": 0})
    df = df.dropna(subset=["label"]).astype({"label": int})  # normalise labels
    df = df.drop_duplicates(subset="host")                   # remove duplicates
    conflicts = df[df.duplicated("host", keep=False)].host.unique()
    return df[~df.host.isin(conflicts)].reset_index(drop=True)


def registered_domain(host: str) -> str:
    ext = _extract(host)
    return ext.top_domain_under_public_suffix or host


def make_features(df: pd.DataFrame):
    X = pd.DataFrame([ml_features_from_host(h) for h in df.host], columns=ML_FEATURE_NAMES)
    y = df.label.to_numpy()
    groups = df.host.map(registered_domain).to_numpy()
    return X, y, groups


def split_train_val_test(X, y, groups, seed=SEED):
    """60/20/20 split, grouped by registered domain so related hosts never straddle splits."""
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    trainval_idx, test_idx = next(gss.split(X, y, groups))
    g_tv = groups[trainval_idx]
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
    tr_rel, val_rel = next(gss2.split(X.iloc[trainval_idx], y[trainval_idx], g_tv))
    train_idx, val_idx = trainval_idx[tr_rel], trainval_idx[val_rel]
    return train_idx, val_idx, test_idx


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--phish")
    ap.add_argument("--benign")
    ap.add_argument("--n-per-class", type=int, default=60000)
    a = ap.parse_args()
    if a.download:
        raw = DATASET_DIR / "raw"
        a.phish = str(download(PHISH_URL, raw / "phishing-links-ACTIVE.txt"))
        a.benign = str(download(BENIGN_URL, raw / "top-1000000-domains.txt"))
    if not (a.phish and a.benign):
        ap.error("Provide --download or both --phish and --benign")
    d = build_dataset(a.phish, a.benign, n_per_class=a.n_per_class)
    print(f"Wrote {DATASET_CSV} with {len(d)} rows: {d.label.value_counts().to_dict()}")
