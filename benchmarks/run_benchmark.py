#!/usr/bin/env python3
"""Retrospective synthetic benchmark for DynSciGraph-TF.

Writes benchmarks/results/synthetic_validation.json and prints the table.
These figures are prototype measurements on a planted synthetic threat graph.
They are not a substitute for the historical MITRE/NVD/EPSS evaluation
specified in the concept paper.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dynscigraph.model import calibration_table, run_retrospective  # noqa: E402


def main() -> None:
    rows = run_retrospective()
    cal = calibration_table()
    out_dir = ROOT / "benchmarks" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "protocol": {
            "data": "synthetic temporal threat graph, seed=7, 24 monthly snapshots",
            "cutoff": "month 18",
            "horizon_days": 90,
            "label": "edges first observed in months 19-21",
            "disclaimer": "Synthetic prototype validation only. Not historical CTI results.",
        },
        "metrics": [
            {
                "model": r.model,
                "precision_at_10": round(r.precision_at_10, 4),
                "recall_at_50": round(r.recall_at_50, 4),
                "f1_at_50": round(r.f1_at_50, 4),
                "lead_time_days": round(r.lead_time_days, 1),
                "calibration_error": round(r.calibration_error, 4),
                "n_true_future_edges": r.n_true_future,
            }
            for r in rows
        ],
        "calibration_bins": cal,
    }
    dest = out_dir / "synthetic_validation.json"
    dest.write_text(json.dumps(payload, indent=2) + "\n")
    header = f"{'Model':<28} {'P@10':>8} {'R@50':>8} {'F1@50':>8} {'Lead d':>8} {'CalErr':>8}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r.model:<28} {r.precision_at_10:8.3f} {r.recall_at_50:8.3f} "
            f"{r.f1_at_50:8.3f} {r.lead_time_days:8.1f} {r.calibration_error:8.3f}"
        )
    print(f"\nWrote {dest}")


if __name__ == "__main__":
    main()
