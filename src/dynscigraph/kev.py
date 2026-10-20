"""Does yesterday's EPSS rank vulnerabilities that CISA later adds to the KEV catalog?

Universe: CVEs present in an EPSS daily file and not already in KEV on that
score date. Label: dateAdded in (score_date, score_date + horizon].
The score is the published EPSS probability. Nothing is refit.
"""

from __future__ import annotations

import csv
import gzip
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from .metrics import average_precision, precision_at, recall_at

ROOT = Path(__file__).resolve().parents[2]


def _load_epss(path: Path) -> dict[str, float]:
    scores = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            if not line or line[0] in "#c":
                continue
            cve, epss, _pct = line.strip().split(",")
            scores[cve] = float(epss)
    return scores


def _load_kev(path: Path) -> dict[str, str]:
    with path.open(newline="") as f:
        return {r["cve"]: r["date_added"] for r in csv.DictReader(f)}


def evaluate_window(score_date: str, horizon_days: int = 365) -> dict:
    epss_path = ROOT / "data" / "raw" / f"epss_scores-{score_date}.csv.gz"
    epss = _load_epss(epss_path)
    added = _load_kev(ROOT / "data" / "derived" / "cisa_kev.csv")
    end = (datetime.strptime(score_date, "%Y-%m-%d") + timedelta(days=horizon_days)).strftime("%Y-%m-%d")
    already = {c for c, d in added.items() if d <= score_date}
    future = {c for c, d in added.items() if score_date < d <= end}
    cves = [c for c in epss if c not in already]
    y = np.array([1.0 if c in future else 0.0 for c in cves])
    scores = np.array([epss[c] for c in cves])
    base = float(y.mean()) if len(y) else 0.0
    ap = average_precision(y, scores)
    return {
        "score_date": score_date,
        "horizon_end": end,
        "epss_file": epss_path.name,
        "n_scored_not_yet_kev": int(len(cves)),
        "n_added_to_kev": int(y.sum()),
        "base_rate": round(base, 8),
        "average_precision": round(ap, 6),
        "lift_ap_vs_base": round(ap / base, 2) if base else None,
        "precision_at_10": round(precision_at(y, scores, 10), 4),
        "precision_at_50": round(precision_at(y, scores, 50), 4),
        "precision_at_100": round(precision_at(y, scores, 100), 4),
        "recall_at_100": round(recall_at(y, scores, 100), 4),
    }


def run_kev_benchmark() -> dict:
    return {
        "task": "Rank not-yet-catalogued CVEs by the EPSS file dated the cutoff. Label is later addition to CISA KEV.",
        "sources": [
            "https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
        "fetched": "2026-10-19",
        "kev_catalog": "2026.10.16",
        "disclaimer": "EPSS score, unfitted. Windows fixed before precision@k.",
        "windows": [
            evaluate_window("2024-06-01"),
            evaluate_window("2025-06-01"),
        ],
    }
