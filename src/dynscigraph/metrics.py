"""Ranking metrics. Average precision uses the standard interpolated-free definition
AP = sum_k Precision(k) * rel(k) / n_relevant.
"""

from __future__ import annotations

import numpy as np


def average_precision(y_true: np.ndarray, scores: np.ndarray) -> float:
    y = np.asarray(y_true, dtype=float)
    if y.sum() <= 0:
        return 0.0
    order = np.argsort(-np.asarray(scores, dtype=float), kind="mergesort")
    rel = y[order]
    precision = np.cumsum(rel) / np.arange(1, len(rel) + 1)
    return float(np.sum(precision * rel) / rel.sum())


def precision_at(y_true: np.ndarray, scores: np.ndarray, k: int) -> float:
    order = np.argsort(-np.asarray(scores, dtype=float), kind="mergesort")
    top = np.asarray(y_true, dtype=float)[order][:k]
    if len(top) == 0:
        return 0.0
    return float(top.mean())


def recall_at(y_true: np.ndarray, scores: np.ndarray, k: int) -> float:
    y = np.asarray(y_true, dtype=float)
    if y.sum() <= 0:
        return 0.0
    order = np.argsort(-np.asarray(scores, dtype=float), kind="mergesort")
    return float(y[order][:k].sum() / y.sum())


def f1_score(y_true: np.ndarray, scores: np.ndarray, threshold: float = 0.5) -> float:
    y = np.asarray(y_true, dtype=float)
    pred = np.asarray(scores, dtype=float) >= threshold
    tp = float(((pred == 1) & (y == 1)).sum())
    fp = float(((pred == 1) & (y == 0)).sum())
    fn = float(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    if prec + rec == 0.0:
        return 0.0
    return float(2 * prec * rec / (prec + rec))
