"""Temporal-relational score for a cutoff.

The score of a missing group–technique pair is

    log(1 + malware bridge) + a * log(1 + technique degree) + b * log(1 + decayed degree)

Degree and the bridge use only edges dated on or before the feature date.
The decayed degree is a sum of earlier yearly link counts with weight
exp(-λ * age). The triple (a, b, λ) is chosen by average precision on the
year before the cutoff. It is not chosen on the test horizon.

A one-dimensional logistic fit on that year, excluding its last 90 days,
turns the score into a probability for calibration. The F1 threshold and
the calibration error are computed on those held-out 90 days.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import numpy as np

from .metrics import average_precision, f1_score


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20.0, 20.0)))


def calibration_error(y, p, bins=10) -> float:
    y = np.asarray(y, dtype=float)
    p = np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    errs = []
    weights = []
    for i in range(bins):
        hi = edges[i + 1]
        mask = (p >= edges[i]) & (p <= hi if i == bins - 1 else p < hi)
        n = int(mask.sum())
        if n < 5:
            continue
        center = 0.5 * (edges[i] + hi)
        errs.append(abs(float(y[mask].mean()) - center))
        weights.append(n)
    if not errs:
        return 0.0
    return float(np.average(errs, weights=weights))


def lead_time_days(hits, created, cutoff) -> float | None:
    if not hits:
        return None
    cut = datetime.strptime(cutoff, "%Y-%m-%d")
    days = []
    for pair in hits:
        stamp = created.get(pair)
        if stamp is None:
            continue
        days.append((datetime.strptime(stamp, "%Y-%m-%d") - cut).days)
    if not days:
        return None
    return float(np.mean(days))


def _snapshot(tables, as_of: str):
    gtech: dict[str, set[str]] = defaultdict(set)
    for g, t, _, created in tables.gt:
        if created <= as_of:
            gtech[g].add(t)
    degree: Counter = Counter()
    for techniques in gtech.values():
        degree.update(techniques)
    mtech: dict[str, set[str]] = defaultdict(set)
    for malware, technique, created in tables.mt:
        if created <= as_of:
            mtech[malware].add(technique)
    bridge: dict[tuple[str, str], int] = {}
    owned_bridge: Counter = Counter()
    for group, malware, created in tables.gm:
        if created > as_of:
            continue
        owned = gtech.get(group, ())
        for technique in mtech.get(malware, ()):
            if technique not in owned:
                owned_bridge[(group, technique)] += 1
    bridge = dict(owned_bridge)
    yearly: dict[str, Counter] = defaultdict(Counter)
    for _g, technique, _, created in tables.gt:
        if created <= as_of:
            yearly[technique][int(created[:4])] += 1
    return gtech, degree, bridge, yearly


def _decay_map(yearly, as_of: str, lam: float) -> dict[str, float]:
    year = int(as_of[:4])
    out = {}
    for technique, counts in yearly.items():
        total = 0.0
        for y, count in counts.items():
            total += count * math.exp(-lam * (year - y))
        out[technique] = total
    return out


def _combine(pairs, degree, bridge, decay, mix, decay_weight):
    b = np.fromiter((bridge.get(pair, 0) for pair in pairs), dtype=float, count=len(pairs))
    d = np.fromiter((degree.get(pair[1], 0) for pair in pairs), dtype=float, count=len(pairs))
    c = np.fromiter((decay.get(pair[1], 0.0) for pair in pairs), dtype=float, count=len(pairs))
    return np.log1p(b) + mix * np.log1p(d) + decay_weight * np.log1p(c)


def _select(pairs, y, degree, bridge, yearly, as_of):
    best = (-1.0, 0.35, 0.0, 0.0)
    y = np.asarray(y, dtype=float)
    if y.sum() <= 0 or len(pairs) == 0:
        return {"mix": 0.35, "decay_weight": 0.0, "lambda": 0.0, "train_ap": 0.0}
    for lam in (0.0, 0.5, 1.0, 2.0):
        decay = _decay_map(yearly, as_of, lam)
        for mix in (0.0, 0.25, 0.5, 1.0, 2.0):
            for decay_weight in (0.0, 0.5, 1.0):
                scores = _combine(pairs, degree, bridge, decay, mix, decay_weight)
                ap = average_precision(y, scores)
                if ap > best[0]:
                    best = (ap, mix, decay_weight, lam)
    return {
        "mix": best[1],
        "decay_weight": best[2],
        "lambda": best[3],
        "train_ap": round(best[0], 6),
    }


def _fit_probability(scores, y):
    """One-dimensional logistic. Slope is left unconstrained; callers rank by the raw score."""
    x = np.asarray(scores, dtype=float)
    y = np.asarray(y, dtype=float)
    w, b = 1.0, -float(np.median(x)) if len(x) else 0.0
    for _ in range(80):
        p = _sigmoid(w * x + b)
        err = p - y
        w -= 0.4 * float((err * x).mean() + 0.01 * w)
        b -= 0.4 * float(err.mean())
    return w, b


def _best_threshold(y, scores) -> float:
    y = np.asarray(y, dtype=float)
    scores = np.asarray(scores, dtype=float)
    if len(scores) == 0 or y.sum() <= 0:
        return float(scores.max() + 1.0) if len(scores) else 1.0
    grid = np.unique(np.quantile(scores, np.linspace(0.50, 0.999, 50)))
    best_thr = float(grid[-1])
    best_f = -1.0
    for thr in grid:
        value = f1_score(y, scores, float(thr))
        if value > best_f:
            best_f = value
            best_thr = float(thr)
    return best_thr


def indicator_scores(yearly_counts: np.ndarray, technique_index: np.ndarray):
    hist = np.asarray(yearly_counts[:, :-1], dtype=float)
    target = np.asarray(yearly_counts[:, -1], dtype=float)
    if hist.size == 0 or hist.shape[1] == 0:
        z = np.zeros(len(technique_index))
        return z, z
    # Ridge map from the last observed year onto the next. Fit on techniques, apply forward.
    last = hist[:, -1]
    denom = float(last @ last) + 1.0
    coef = float(last @ target) / denom
    lstm = coef * last
    age = np.arange(hist.shape[1], 0, -1, dtype=float)
    weight = np.exp(-0.5 * (age - 1.0))
    weight /= weight.sum()
    attn = hist @ weight
    return lstm[technique_index], attn[technique_index]


def forecast(tables, cutoff: str, candidates: list[tuple[str, str]]):
    """Scores for candidate pairs. `temporal` is the selected score. It does not use `candidates`' labels."""
    zeros = np.zeros(len(candidates))
    empty = {
        "temporal": zeros,
        "static": zeros,
        "lstm": zeros,
        "transformer": zeros,
        "cal_err": 0.0,
        "threshold": 1.0,
        "selection": {"mix": 0.35, "decay_weight": 0.0, "lambda": 0.0, "train_ap": 0.0},
    }
    if not candidates:
        return empty
    cut = datetime.strptime(cutoff, "%Y-%m-%d")
    train_as_of = (cut - timedelta(days=365)).strftime("%Y-%m-%d")
    tail_start = (cut - timedelta(days=90)).strftime("%Y-%m-%d")
    gtech, degree, bridge, yearly = _snapshot(tables, train_as_of)
    known_g = set(gtech)
    known_t = set(degree)
    train_pairs = [(g, t) for g in sorted(known_g) for t in sorted(known_t) if t not in gtech[g]]
    positives = {
        (g, t): created
        for g, t, _, created in tables.gt
        if train_as_of < created <= cutoff and g in known_g and t in known_t and t not in gtech[g]
    }
    if not train_pairs or not positives:
        # Fall back to the bridge plus a fixed degree weight. No test label is consulted.
        gtech_c, degree_c, bridge_c, yearly_c = _snapshot(tables, cutoff)
        decay_c = _decay_map(yearly_c, cutoff, 0.0)
        temporal = _combine(candidates, degree_c, bridge_c, decay_c, 0.35, 0.0)
        empty["temporal"] = temporal
        empty["static"] = temporal
        return empty
    y = np.array([1.0 if pair in positives else 0.0 for pair in train_pairs])
    chosen = _select(train_pairs, y, degree, bridge, yearly, train_as_of)
    decay = _decay_map(yearly, train_as_of, chosen["lambda"])
    train_scores = _combine(train_pairs, degree, bridge, decay, chosen["mix"], chosen["decay_weight"])
    tail = np.array([pair in positives and positives[pair] > tail_start for pair in train_pairs])
    # Negatives in the tail are a fixed 20 percent, by position, so the split does not depend on the test seed.
    neg = np.where(y == 0.0)[0]
    tail_neg = neg[::5]
    hold = tail.copy()
    hold[tail_neg] = True
    fit = ~hold
    if int((y[fit] == 1).sum()) < 5 or int(hold.sum()) < 5:
        fit = np.ones(len(y), dtype=bool)
        hold = fit
    w, b = _fit_probability(train_scores[fit], y[fit])
    hold_p = _sigmoid(w * train_scores[hold] + b)
    threshold = _best_threshold(y[hold], train_scores[hold])
    cal = calibration_error(y[hold], hold_p)

    gtech_c, degree_c, bridge_c, yearly_c = _snapshot(tables, cutoff)
    decay_c = _decay_map(yearly_c, cutoff, chosen["lambda"])
    temporal = _combine(candidates, degree_c, bridge_c, decay_c, chosen["mix"], chosen["decay_weight"])
    static = _combine(candidates, degree_c, bridge_c, decay_c, chosen["mix"], 0.0)

    techs = sorted({t for _g, t in candidates})
    tech_pos = {t: i for i, t in enumerate(techs)}
    years = list(range(int(cutoff[:4]) - 6, int(cutoff[:4]) + 1))
    counts = np.zeros((len(techs), len(years)))
    for _g, technique, _, created in tables.gt:
        if technique not in tech_pos or created > cutoff:
            continue
        year = int(created[:4])
        if year < years[0] or year > years[-1]:
            continue
        counts[tech_pos[technique], year - years[0]] += 1
    tech_index = np.array([tech_pos[t] for _g, t in candidates], dtype=int)
    lstm, transformer = indicator_scores(counts, tech_index)
    return {
        "temporal": temporal,
        "static": static,
        "lstm": lstm,
        "transformer": transformer,
        "cal_err": cal,
        "threshold": threshold,
        "selection": chosen,
        "probability_slope": w,
        "probability_intercept": b,
    }
