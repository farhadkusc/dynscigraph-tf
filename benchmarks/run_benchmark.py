#!/usr/bin/env python3
"""Run both public-data evaluations and write benchmarks/results/evaluation.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dynscigraph.attack import run_attack_benchmark  # noqa: E402
from dynscigraph.kev import run_kev_benchmark  # noqa: E402


def main() -> None:
    payload = {
        "package": "dynscigraph-tf",
        "version": "0.2.0",
        "attack": run_attack_benchmark(),
        "kev": run_kev_benchmark(),
    }
    out = ROOT / "benchmarks" / "results" / "evaluation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print("ATT&CK group→technique, next 365 days")
    for run in payload["attack"]["runs"]:
        b = run["baselines"]["technique_degree"]
        print(
            f"  cutoff {run['cutoff']}: model AP {run['ap']:.4f} "
            f"(degree {b['ap']:.4f}, base {run['base_rate']:.4f}) "
            f"P@10 {run['p_at_10']:.2f}  future {run['n_future']}"
        )
    print("EPSS file vs later CISA KEV")
    for w in payload["kev"]["windows"]:
        print(
            f"  {w['score_date']}: AP {w['average_precision']:.4f} "
            f"lift {w['lift_ap_vs_base']}x  P@10 {w['precision_at_10']:.2f}  "
            f"added {w['n_added_to_kev']}"
        )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
