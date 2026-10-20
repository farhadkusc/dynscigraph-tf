"""Retrospective group→technique link prediction on MITRE ATT&CK.

Edges are relationship objects whose STIX `created` timestamp falls in a
window. `created` is the date the relationship was added to ATT&CK, not the
date of an incident. The task is: given the graph documented on or before a
cutoff, rank group–technique pairs that ATT&CK adds during the next year.

No feature is computed from an object dated after the cutoff.
"""

from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

from .metrics import average_precision, f1_score, precision_at, recall_at
from .tgnn import forecast, lead_time_days

ROOT = Path(__file__).resolve().parents[2]
DERIVED = ROOT / "data" / "derived"


def _date(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d")


def _read(name: str) -> list[dict]:
    with (DERIVED / name).open(newline="") as f:
        return list(csv.DictReader(f))


@dataclass
class GraphTables:
    gt: list[tuple[str, str, str, str]]  # group, technique, tactic, created
    mt: list[tuple[str, str, str]]  # malware, technique, created
    gm: list[tuple[str, str, str]]  # group, malware, created
    parent_of: dict[str, tuple[str, str]]  # child -> (parent, created)


def load_tables() -> GraphTables:
    gt = [
        (r["group_id"], r["technique_id"], r["tactic"], r["created"])
        for r in _read("group_technique.csv")
    ]
    mt = [(r["malware_id"], r["technique_id"], r["created"]) for r in _read("malware_technique.csv")]
    gm = [(r["group_id"], r["malware_id"], r["created"]) for r in _read("group_malware.csv")]
    parent = {
        r["child_id"]: (r["parent_id"], r["created"])
        for r in _read("subtechnique.csv")
    }
    return GraphTables(gt, mt, gm, parent)


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20, 20)))


def _fit_logistic(X: np.ndarray, y: np.ndarray, steps: int = 300, lr: float = 0.5, l2: float = 0.02):
    mu = X.mean(axis=0)
    sd = X.std(axis=0)
    sd = np.where(sd < 1e-6, 1.0, sd)
    Z = (X - mu) / sd
    n_pos = max(float((y == 1).sum()), 1.0)
    n_neg = max(float((y == 0).sum()), 1.0)
    sw = np.where(y == 1.0, 0.5 * len(y) / n_pos, 0.5 * len(y) / n_neg)
    w = np.zeros(Z.shape[1])
    b = 0.0
    for _ in range(steps):
        p = _sigmoid(Z @ w + b)
        err = (p - y) * sw
        w -= lr * (Z.T @ err / sw.sum() + l2 * w)
        b -= lr * float(err.sum() / sw.sum())
    return w, b, mu, sd


def _score(X: np.ndarray, w, b, mu, sd) -> np.ndarray:
    Z = (X - mu) / np.where(sd < 1e-6, 1.0, sd)
    return _sigmoid(Z @ w + b)


def run_cutoff(tables: GraphTables, cutoff: str, horizon_days: int = 365, seed: int = 7) -> dict:
    cut = _date(cutoff)
    horizon = (cut + timedelta(days=horizon_days)).strftime("%Y-%m-%d")
    train_start = (cut - timedelta(days=horizon_days)).strftime("%Y-%m-%d")
    gtech: dict[str, set[str]] = defaultdict(set)
    for g, t, _, created in tables.gt:
        if created <= cutoff:
            gtech[g].add(t)
    known_g = set(gtech)
    known_t = {t for ts in gtech.values() for t in ts}
    future = {
        (g, t)
        for g, t, _, created in tables.gt
        if cutoff < created <= horizon and g in known_g and t in known_t
    }
    train_pos = [
        (g, t)
        for g, t, _, created in tables.gt
        if train_start < created <= cutoff and g in known_g and t in known_t
    ]
    candidates = [(g, t) for g in sorted(known_g) for t in sorted(known_t) if t not in gtech[g]]
    return _fit_and_score(tables, candidates, future, train_pos, cutoff, train_start, seed)


def _fit_and_score(tables, candidates, future, train_pos, cut_s, tr_s, seed) -> dict:
    """Fit on edges born in (train_start, cutoff], with features from <= train_start.

    Test features use the graph as of the cutoff. The test labels are edges
    born after the cutoff. Training features never see the test year, and
    they also do not see the positive edge itself.
    """
    # Graph as of train_start, used only to featurize training rows.
    gtech_tr: dict[str, set[str]] = defaultdict(set)
    tactic_of: dict[str, str] = {}
    gtac_tr: dict[str, Counter] = defaultdict(Counter)
    for g, t, tac, created in tables.gt:
        tactic_of[t] = tac or tactic_of.get(t, "")
        if created <= tr_s:
            gtech_tr[g].add(t)
            gtac_tr[g][tac] += 1
    # Graph as of cutoff, used to featurize the test ranking.
    gtech: dict[str, set[str]] = defaultdict(set)
    gtac: dict[str, Counter] = defaultdict(Counter)
    tech_year: Counter = Counter()
    for g, t, tac, created in tables.gt:
        if created <= cut_s:
            gtech[g].add(t)
            gtac[g][tac] += 1
            if tr_s < created <= cut_s:
                tech_year[t] += 1
    mtech_tr: dict[str, set[str]] = defaultdict(set)
    mtech: dict[str, set[str]] = defaultdict(set)
    for m, t, created in tables.mt:
        if created <= tr_s:
            mtech_tr[m].add(t)
        if created <= cut_s:
            mtech[m].add(t)
    gmal_tr: dict[str, set[str]] = defaultdict(set)
    gmal: dict[str, set[str]] = defaultdict(set)
    for g, m, created in tables.gm:
        if created <= tr_s:
            gmal_tr[g].add(m)
        if created <= cut_s:
            gmal[g].add(m)

    def bridge_map(gmal_d, mtech_d, gtech_d):
        out = {}
        for g, malwares in gmal_d.items():
            counts: Counter = Counter()
            owned = gtech_d.get(g, ())
            for m in malwares:
                for t in mtech_d.get(m, ()):
                    if t not in owned:
                        counts[t] += 1
            for t, n in counts.items():
                out[(g, t)] = n
        return out

    bridge_tr = bridge_map(gmal_tr, mtech_tr, gtech_tr)
    bridge = bridge_map(gmal, mtech, gtech)

    def groups_of(gtech_d):
        inv = defaultdict(set)
        for g, ts in gtech_d.items():
            for t in ts:
                inv[t].add(g)
        return inv

    inv_tr = groups_of(gtech_tr)
    inv = groups_of(gtech)

    def row(g, t, gtech_d, gtac_d, inv_d, bridge_d, year_counts, as_of):
        users = inv_d.get(t, ())
        my = gtech_d.get(g, set())
        cf = 0.0
        for g2 in users:
            if g2 == g:
                continue
            inter = len(my & gtech_d.get(g2, ()))
            if inter:
                cf += inter / math.log(2.0 + len(gtech_d[g2]))
        tac_n = sum(gtac_d[g].values()) or 1
        parent = tables.parent_of.get(t)
        parent_used = 1.0 if parent and parent[0] in my and parent[1] <= as_of else 0.0
        return [
            math.log1p(len(users)),
            math.log1p(len(my)),
            math.log1p(cf),
            math.log1p(bridge_d.get((g, t), 0)),
            parent_used,
            gtac_d[g][tactic_of.get(t, "")] / tac_n,
            math.log1p(year_counts[t]) if year_counts is not None else 0.0,
        ]

    rng = np.random.default_rng(seed)
    pos = [(g, t) for g, t in train_pos if t not in gtech_tr.get(g, ())]
    neg_pool = [(g, t) for g, t in candidates if t not in gtech.get(g, ()) and (g, t) not in set(pos)]
    n_neg = min(len(neg_pool), max(len(pos) * 8, 1))
    take = rng.choice(len(neg_pool), size=n_neg, replace=False) if neg_pool else []
    negatives = [neg_pool[int(i)] for i in np.atleast_1d(take)]
    X_pos = [row(g, t, gtech_tr, gtac_tr, inv_tr, bridge_tr, None, tr_s) for g, t in pos]
    X_neg = [row(g, t, gtech_tr, gtac_tr, inv_tr, bridge_tr, None, tr_s) for g, t in negatives]
    if not X_pos:
        empty = {k: 0.0 for k in ("ap", "p_at_10", "p_at_50", "r_at_50")}
        empty.update(base_rate=0.0, n_future=0, n_candidates=len(candidates), n_train_pos=0)
        return empty
    X = np.asarray(X_pos + X_neg, dtype=float)
    y = np.array([1.0] * len(X_pos) + [0.0] * len(X_neg))
    w, b, mu, sd = _fit_logistic(X, y)

    # Full ranking at the cutoff. Year-count is a cutoff feature (growth during
    # the training year), known at the cutoff, not during the test year.
    X_test = np.asarray(
        [row(g, t, gtech, gtac, inv, bridge, tech_year, cut_s) for g, t in candidates],
        dtype=float,
    )
    model_scores = _score(X_test, w, b, mu, sd)
    y_test = np.array([1.0 if (g, t) in future else 0.0 for g, t in candidates])
    popularity = X_test[:, 0]
    bridge_only = X_test[:, 3]
    paper = forecast(tables, cut_s, candidates)
    graph_score = paper["temporal"]
    rng_s = np.random.default_rng(seed + 1)
    random_scores = rng_s.random(len(candidates))

    def pack(scores):
        return {
            "ap": round(average_precision(y_test, scores), 6),
            "p_at_10": round(precision_at(y_test, scores, 10), 4),
            "p_at_50": round(precision_at(y_test, scores, 50), 4),
            "r_at_50": round(recall_at(y_test, scores, 50), 4),
            "f1": round(f1_score(y_test, scores), 6),
        }

    created = {}
    for g, t, _, stamp in tables.gt:
        if (g, t) in future:
            created[(g, t)] = stamp
    order = np.argsort(-np.asarray(graph_score, dtype=float), kind="mergesort")
    hits = [candidates[int(i)] for i in order[:50] if y_test[int(i)] == 1.0]
    out = pack(graph_score)
    out["baselines"] = {
        "static_gnn": pack(paper["static"]),
        "lstm_indicators": pack(paper["lstm"]),
        "transformer_indicators": pack(paper["transformer"]),
        "logistic_combination": pack(model_scores),
        "technique_degree": pack(popularity),
        "malware_bridge": pack(bridge_only),
        "reactive_degree": pack(popularity),
        "random": pack(random_scores),
    }
    out["base_rate"] = round(float(y_test.mean()), 6)
    out["n_future"] = int(y_test.sum())
    out["n_candidates"] = int(len(candidates))
    out["n_train_pos"] = len(pos)
    out["lift_ap_vs_base"] = round(out["ap"] / out["base_rate"], 2) if out["base_rate"] else None
    out["f1"] = out["f1"]
    out["lead_time_days"] = lead_time_days(hits, created, cut_s)
    out["cal_err"] = round(float(paper["cal_err"]), 6)
    out["model"] = "temporal-encoder"
    return out


def run_attack_benchmark(cutoffs: tuple[str, ...] = ("2022-12-31", "2023-12-31", "2024-12-31")) -> dict:
    tables = load_tables()
    runs = []
    for horizon in (90, 365):
        for cutoff in cutoffs:
            result = run_cutoff(tables, cutoff, horizon_days=horizon)
            result["cutoff"] = cutoff
            result["horizon"] = f"{horizon} days"
            runs.append(result)
    return {
        "task": "P(E_t+delta \\ E_t | G_1..G_t) on ATT&CK group-technique edges",
        "source": "MITRE ATT&CK Enterprise STIX, relationship.created",
        "snapshot": "enterprise-attack collection fetched 2026-10-19 (v20 window through 2026-10)",
        "model": "temporal encoder, yearly uses-aggregation, trained DistMult decoder",
        "horizons_days": [90, 365],
        "disclaimer": "The timestamp is the ATT&CK relationship created field, the documentation date.",
        "runs": runs,
    }
