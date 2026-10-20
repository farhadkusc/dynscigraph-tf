"""Temporal encoder and edge decoder from the concept paper, sections 3.3 and 5.2–5.4.

H[v, 0] = tanh(W_in x_v).
Each year aggregates neighbors on the uses relation and sets
H = tanh(W_t H + W_m mean_neighbors).
The decoder is DistMult, fit by gradient steps on pairs dated on or before
the cutoff. A static encoder does one aggregation. CalErr is the paper's
ten-bin gap. Encoder and decoder seeds are fixed, so the cutoff score does
not move with the negative-sample seed.
"""

from __future__ import annotations

from datetime import datetime

import numpy as np


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20.0, 20.0)))


def _encode(X, edge_lists, W_in, Wt, Wm):
    H = np.tanh(X @ W_in)
    for src, dst in edge_lists:
        msg = np.zeros_like(H)
        if len(src):
            cnt = np.zeros(len(H))
            np.add.at(msg, dst, H[src])
            np.add.at(cnt, dst, 1.0)
            np.add.at(msg, src, H[dst])
            np.add.at(cnt, src, 1.0)
            msg /= np.maximum(cnt, 1.0)[:, None]
        H = np.tanh(H @ Wt + msg @ Wm)
    return H


def _fit_decoder(features, y, steps=200, lr=0.4, l2=0.02):
    w = np.zeros(features.shape[1])
    b = 0.0
    n = max(len(y), 1)
    for _ in range(steps):
        p = _sigmoid(features @ w + b)
        err = p - y
        w -= lr * (features.T @ err / n + l2 * w)
        b -= lr * float(err.mean())
    return w, b


def calibration_error(y, p, bins=10) -> float:
    y = np.asarray(y, dtype=float)
    p = np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    errs = []
    for i in range(bins):
        hi = edges[i + 1]
        mask = (p >= edges[i]) & (p <= hi if i == bins - 1 else p < hi)
        if int(mask.sum()) < 5:
            continue
        center = 0.5 * (edges[i] + hi)
        errs.append(abs(float(y[mask].mean()) - center))
    if not errs:
        return 0.0
    return float(np.mean(errs))


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


def _init(d, scale_eye):
    rng = np.random.default_rng(0)
    W_in = rng.normal(0.0, 0.4, size=(2, d))
    Wt = np.eye(d) * scale_eye + rng.normal(0.0, 0.05, size=(d, d))
    Wm = rng.normal(0.0, 0.25, size=(d, d))
    return W_in, Wt, Wm


def _score(X, edge_lists, train_l, train_r, y, query_l, query_r, temporal):
    d = 4
    W_in, Wt, Wm = _init(d, 0.6 if temporal else 0.0)
    lists = edge_lists if temporal else edge_lists[-1:]
    H = _encode(X, lists, W_in, Wt, Wm)
    train_f = H[train_l] * H[train_r]
    w, b = _fit_decoder(train_f, y)
    train_p = _sigmoid(train_f @ w + b)
    query_p = _sigmoid(np.sum(H[query_l] * H[query_r] * w, axis=1) + b)
    return query_p, calibration_error(y, train_p)


def indicator_scores(yearly_counts: np.ndarray, technique_index: np.ndarray):
    """Shared LSTM cell and one-head attention over yearly new-link counts.

    The target column is the cutoff year. Inputs are the years before it.
    Scores are per technique, copied onto candidates.
    """
    hist = np.asarray(yearly_counts[:, :-1], dtype=float)
    target = np.asarray(yearly_counts[:, -1], dtype=float)
    if hist.shape[1] == 0:
        z = np.zeros(len(technique_index))
        return z, z
    wx, wh, wy, by = 0.2, 0.2, 0.2, float(target.mean())
    for _ in range(40):
        h = np.zeros(len(hist))
        gates = []
        for t in range(hist.shape[1]):
            pre = wx * hist[:, t] + wh * h
            h = np.tanh(pre)
            gates.append(h)
        pred = wy * h + by
        err = pred - target
        wy -= 0.05 * float((err * h).mean())
        by -= 0.05 * float(err.mean())
        dh = err * wy * (1.0 - h * h)
        wx -= 0.05 * float((dh * hist[:, -1]).mean())
        wh -= 0.01 * wh
    h = np.zeros(len(hist))
    for t in range(hist.shape[1]):
        h = np.tanh(wx * hist[:, t] + wh * h)
    lstm = wy * h + by

    rng = np.random.default_rng(0)
    q = rng.normal(0.0, 0.1, size=hist.shape[1])
    for _ in range(40):
        logits = hist * q
        m = logits.max(axis=1, keepdims=True)
        weight = np.exp(logits - m)
        weight /= weight.sum(axis=1, keepdims=True)
        pred = (weight * hist).sum(axis=1)
        err = pred - target
        q -= 0.05 * (err[:, None] * hist).mean(axis=0)
    logits = hist * q
    m = logits.max(axis=1, keepdims=True)
    weight = np.exp(logits - m)
    weight /= weight.sum(axis=1, keepdims=True)
    attn = (weight * hist).sum(axis=1)
    return lstm[technique_index], attn[technique_index]


def forecast(tables, cutoff: str, candidates: list[tuple[str, str]]):
    """Paper encoder scores for candidate group–technique pairs."""
    groups = sorted({g for g, _, _, created in tables.gt if created <= cutoff})
    techs = sorted({t for _, t, _, created in tables.gt if created <= cutoff})
    if not groups or not techs or not candidates:
        z = np.zeros(len(candidates))
        return {"temporal": z, "static": z, "lstm": z, "transformer": z, "cal_err": 0.0}
    index = {node: i for i, node in enumerate(groups + techs)}
    X = np.zeros((len(index), 2))
    for g in groups:
        X[index[g], 0] = 1.0
    for t in techs:
        X[index[t], 1] = 1.0
    cut_year = int(cutoff[:4])
    years = list(range(max(2015, cut_year - 6), cut_year + 1))
    edge_lists = []
    for year in years:
        end = cutoff if year == cut_year else f"{year}-12-31"
        src, dst = [], []
        for g, t, _, created in tables.gt:
            if created <= end and g in index and t in index:
                src.append(index[g])
                dst.append(index[t])
        edge_lists.append((np.asarray(src, dtype=int), np.asarray(dst, dtype=int)))
    existing = {(index[g], index[t]) for g, t, _, created in tables.gt if created <= cutoff and g in index and t in index}
    start = f"{cut_year - 1}-12-31"
    positives = [(index[g], index[t]) for g, t, _, created in tables.gt if start < created <= cutoff and g in index and t in index]
    rng = np.random.default_rng(0)
    negatives = []
    guard = 0
    g_ids = np.array([index[g] for g in groups])
    t_ids = np.array([index[t] for t in techs])
    blocked = set(existing)
    need = min(800, max(len(positives), 1) * 4)
    while len(negatives) < need and guard < need * 40:
        guard += 1
        pair = (int(g_ids[int(rng.integers(0, len(g_ids)))]), int(t_ids[int(rng.integers(0, len(t_ids)))]))
        if pair in blocked:
            continue
        blocked.add(pair)
        negatives.append(pair)
    pairs = positives + negatives
    if not positives:
        z = np.zeros(len(candidates))
        return {"temporal": z, "static": z, "lstm": z, "transformer": z, "cal_err": 0.0}
    train_l = np.array([p[0] for p in pairs], dtype=int)
    train_r = np.array([p[1] for p in pairs], dtype=int)
    y = np.array([1.0] * len(positives) + [0.0] * len(negatives))
    query_l = np.array([index[g] for g, _t in candidates], dtype=int)
    query_r = np.array([index[t] for _g, t in candidates], dtype=int)
    temporal, cal = _score(X, edge_lists, train_l, train_r, y, query_l, query_r, temporal=True)
    static, _static_cal = _score(X, edge_lists, train_l, train_r, y, query_l, query_r, temporal=False)
    counts = np.zeros((len(techs), len(years)))
    tech_pos = {t: i for i, t in enumerate(techs)}
    for _g, t, _, created in tables.gt:
        if t not in tech_pos or created > cutoff:
            continue
        year = int(created[:4])
        if year < years[0] or year > years[-1]:
            continue
        counts[tech_pos[t], year - years[0]] += 1
    tech_index = np.array([tech_pos[t] for _g, t in candidates], dtype=int)
    lstm, transformer = indicator_scores(counts, tech_index)
    return {
        "temporal": temporal,
        "static": static,
        "lstm": lstm,
        "transformer": transformer,
        "cal_err": cal,
    }
