"""Synthetic institution fixtures.

See data/dummy/README.md. Results go to benchmarks/results/dummy_evaluation.json.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from . import __version__
from .attack import GraphTables, run_cutoff
from .metrics import average_precision, precision_at

ROOT = Path(__file__).resolve().parents[2]
DUMMY = ROOT / "data" / "dummy"

STATEMENT = "Synthetic fixture. Organization names are scenario labels."


def _read(name: str) -> list[dict]:
    with (DUMMY / name).open(newline="") as f:
        return list(csv.DictReader(f))


def load_organizations() -> list[dict]:
    return _read("organizations.csv")


def load_scenario() -> dict:
    return json.loads((DUMMY / "attack_scenario.json").read_text())


def score_attack_scenario() -> dict:
    """Grey Harbor: rank the fictional actor's held-out links on a six-technique graph."""
    scenario = load_scenario()
    actor = scenario["adversary"]["id"]
    blue = scenario["blue_observer_id"]
    tool = scenario["tool_id"]
    seen = scenario["tool_seen"]
    gt = []
    mt = []
    for tech in scenario["techniques"]:
        gt.append((blue, tech["id"], tech["tactic"], tech["blue_seen"]))
        if tech["actor_seen"]:
            gt.append((actor, tech["id"], tech["tactic"], tech["actor_seen"]))
        if tech["on_tool"]:
            mt.append((tool, tech["id"], seen))
    tables = GraphTables(gt, mt, [(actor, tool, seen)], {})
    scored = run_cutoff(tables, scenario["cutoff"])
    return {
        "exercise_id": scenario["exercise_id"],
        "title": scenario["title"],
        "kind": scenario["kind"],
        "statement": scenario["statement"],
        "adversary_id": actor,
        "blue_cell": scenario["blue_cell"],
        "out_of_scope": scenario["out_of_scope"],
        "sites": [site["id"] for site in scenario["sites"]],
        "cutoff": scenario["cutoff"],
        "n_future": scored["n_future"],
        "n_candidates": scored["n_candidates"],
        "ap": scored["ap"],
        "base_rate": scored["base_rate"],
        "baselines": scored["baselines"],
        "held_out": ["SYN-TH-04", "SYN-TH-05"],
        "unbridged": "SYN-TH-00",
    }


def load_dummy_tables() -> GraphTables:
    gt = [
        (r["group_id"], r["technique_id"], r["tactic"], r["created"])
        for r in _read("group_technique.csv")
    ]
    mt = [(r["malware_id"], r["technique_id"], r["created"]) for r in _read("malware_technique.csv")]
    gm = [(r["group_id"], r["malware_id"], r["created"]) for r in _read("group_malware.csv")]
    parent = {r["child_id"]: (r["parent_id"], r["created"]) for r in _read("subtechnique.csv")}
    return GraphTables(gt, mt, gm, parent)


def score_catalog(score_date: str = "2025-06-01", horizon_days: int = 365) -> dict:
    rows = _read("vuln_catalog.csv")
    end = (datetime.strptime(score_date, "%Y-%m-%d") + timedelta(days=horizon_days)).strftime("%Y-%m-%d")
    already = {r["syn_id"] for r in rows if r["date_added"] and r["date_added"] <= score_date}
    universe = [r for r in rows if r["syn_id"] not in already]
    y = np.array(
        [1.0 if r["date_added"] and score_date < r["date_added"] <= end else 0.0 for r in universe],
        dtype=float,
    )
    scores = np.array([float(r["score"]) for r in universe], dtype=float)
    base = float(y.mean()) if len(y) else 0.0
    ap = average_precision(y, scores)
    return {
        "score_date": score_date,
        "horizon_end": end,
        "n_excluded_already_listed": len(already),
        "n_scored": int(len(universe)),
        "n_added_later": int(y.sum()),
        "base_rate": round(base, 6),
        "average_precision": round(ap, 6),
        "precision_at_10": round(precision_at(y, scores, 10), 4),
        "note": "Separable synthetic catalog. Not EPSS and not CISA KEV.",
    }


def run_dummy() -> dict:
    orgs = load_organizations()
    counts = Counter(o["klass"] for o in orgs)
    graph = run_cutoff(load_dummy_tables(), "2024-12-31")
    graph["cutoff"] = "2024-12-31"
    graph["note"] = (
        "Planted observation graph. Groups are scenario labels, not intrusion sets. "
        "Timestamps are fixture dates, not ATT&CK created dates."
    )
    return {
        "kind": "synthetic-fixture",
        "package": "dynscigraph-tf",
        "package_version": __version__,
        "statement": STATEMENT,
        "n_organizations": len(orgs),
        "counts": dict(counts),
        "observation_graph": graph,
        "vulnerability_catalog": score_catalog(),
        "attack_scenario": score_attack_scenario(),
    }
