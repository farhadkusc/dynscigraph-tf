#!/usr/bin/env python3
"""Seed and horizon sweep for the ATT&CK cutoff ranker.

The graph score does not use the seed. The logistic baseline does, because
each seed draws a different negative sample. The lab profile is the run to
submit on NJIT Wulver. Smoke is the two-job check.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from dynscigraph import __version__  # noqa: E402
from dynscigraph.attack import load_tables, run_cutoff  # noqa: E402

CUTOFFS = ("2022-12-31", "2023-12-31", "2024-12-31")
LAB_HORIZONS = (90, 180, 365, 540)
LAB_SEEDS = range(128)
SMOKE_HORIZONS = (365,)
SMOKE_SEEDS = (0, 1)
SMOKE_CUTOFFS = ("2024-12-31",)

_TABLES = None


def _worker(job: tuple) -> dict:
    global _TABLES
    if _TABLES is None:
        _TABLES = load_tables()
    cutoff, horizon, seed = job
    out = run_cutoff(_TABLES, cutoff, horizon_days=int(horizon), seed=int(seed))
    baselines = out.get("baselines") or {}
    logistic = baselines.get("logistic_combination") or {}
    degree = baselines.get("technique_degree") or {}
    random_row = baselines.get("random") or {}
    return {
        "cutoff": cutoff,
        "horizon_days": int(horizon),
        "seed": int(seed),
        "graph_ap": out.get("ap"),
        "logistic_ap": logistic.get("ap"),
        "degree_ap": degree.get("ap"),
        "random_ap": random_row.get("ap"),
        "base_rate": out.get("base_rate"),
        "n_future": out.get("n_future"),
        "n_candidates": out.get("n_candidates"),
        "n_train_pos": out.get("n_train_pos"),
    }


def _jobs(profile: str) -> list[tuple]:
    if profile == "smoke":
        return [(c, h, s) for c in SMOKE_CUTOFFS for h in SMOKE_HORIZONS for s in SMOKE_SEEDS]
    if profile == "lab":
        return [(c, h, s) for c in CUTOFFS for h in LAB_HORIZONS for s in LAB_SEEDS]
    raise SystemExit(f"unknown profile {profile}")


def _summary(rows: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault((row["cutoff"], row["horizon_days"]), []).append(row)
    out = []
    for (cutoff, horizon), items in sorted(groups.items()):
        graph = [r["graph_ap"] for r in items if r["graph_ap"] is not None]
        logistic = [r["logistic_ap"] for r in items if r["logistic_ap"] is not None]
        graph_span = max(graph) - min(graph) if graph else None
        beats = None
        if logistic and graph:
            g = graph[0]
            beats = sum(v > g for v in logistic) / len(logistic)
        out.append(
            {
                "cutoff": cutoff,
                "horizon_days": horizon,
                "n_seeds": len(items),
                "graph_ap": None if not graph else round(graph[0], 6),
                "graph_ap_span": None if graph_span is None else round(graph_span, 8),
                "logistic_ap_mean": None if not logistic else round(sum(logistic) / len(logistic), 6),
                "logistic_ap_min": None if not logistic else round(min(logistic), 6),
                "logistic_ap_max": None if not logistic else round(max(logistic), 6),
                "fraction_logistic_beats_graph": None if beats is None else round(beats, 4),
                "n_future": items[0]["n_future"],
                "base_rate": items[0]["base_rate"],
            }
        )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="NJIT Wulver sweep for DynSciGraph-TF")
    parser.add_argument("--profile", choices=("smoke", "lab"), default="smoke")
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    args = parser.parse_args()
    jobs = _jobs(args.profile)
    started = time.perf_counter()
    workers = max(1, min(args.workers, len(jobs)))
    if workers == 1:
        rows = [_worker(job) for job in jobs]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(_worker, jobs, chunksize=1))
    elapsed = round(time.perf_counter() - started, 3)
    report = {
        "package": "dynscigraph-tf",
        "package_version": __version__,
        "profile": args.profile,
        "host": socket.gethostname(),
        "ran_on_wulver": False,
        "purpose": "Sensitivity of the public-data cutoff ranker to horizon and to the logistic negative-sample seed.",
        "n_jobs": len(rows),
        "workers": workers,
        "elapsed_sec": elapsed,
        "summary": _summary(rows),
        "jobs": rows,
    }
    out_dir = ROOT / "lab" / "njit" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "smoke.json" if args.profile == "smoke" else "lab.json"
    path = out_dir / name
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"jobs {len(rows)} workers {workers} elapsed {elapsed}s -> {path}")


if __name__ == "__main__":
    main()
