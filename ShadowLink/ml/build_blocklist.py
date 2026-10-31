"""Build the local threat-intelligence list from the public Phishing.Database snapshot.

Run (after `python -m ml.preprocessing --download`):
    python -m ml.build_blocklist

Output: ml/datasets/local_blocklist.txt, one lowercase hostname per line. Hostnames that
also appear in the benign top-domains ranking are excluded, so a compromised popular site
is not blanket-flagged. A match means "listed in a community feed", not proof of malice,
and absence from the list never means a URL is safe.
"""
from pathlib import Path

from ml.preprocessing import DATASET_DIR, _host_from_url

RAW = DATASET_DIR / "raw"
OUT = DATASET_DIR / "local_blocklist.txt"


def build(phish_path=RAW / "phishing-links-ACTIVE.txt", benign_path=RAW / "top-1000000-domains.txt", out=OUT) -> int:
    if not Path(phish_path).exists():
        raise SystemExit(f"Missing {phish_path}. Run: python -m ml.preprocessing --download")
    phish = {h for h in (_host_from_url(l) for l in Path(phish_path).read_text(errors="ignore").splitlines()) if h}
    if Path(benign_path).exists():
        benign = {h for h in (_host_from_url(l) for l in Path(benign_path).read_text(errors="ignore").splitlines()) if h}
        phish -= benign
    Path(out).write_text("# Hostnames from Phishing.Database (MIT). Community feed; not proof of malice.\n"
                         + "\n".join(sorted(phish)) + "\n", encoding="utf-8")
    return len(phish)


if __name__ == "__main__":
    print(f"Wrote {OUT} with {build()} hostnames")
