"""Schema-aligned extraction, temporal encoder, and edge decoder.

Implements the forecasting task from the concept paper on a fully specified
synthetic critical-infrastructure threat graph:

    P(E_{t+Δ} \\ E_t | G_1, ..., G_t)

Numbers produced by this module are prototype measurements on synthetic data.
They are not historical MITRE / NVD / EPSS results.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

NODE_TYPES = (
    "Vulnerability",
    "Technique",
    "AdversaryGroup",
    "TargetSector",
    "Tool",
)
EDGE_TYPES = ("uses", "exploits", "targets", "chains-with")

# Allowed (source type, relation, target type) triples. Extraction rejects the rest.
SCHEMA = {
    ("AdversaryGroup", "uses", "Technique"),
    ("Technique", "exploits", "Vulnerability"),
    ("AdversaryGroup", "targets", "TargetSector"),
    ("Vulnerability", "chains-with", "Vulnerability"),
    ("AdversaryGroup", "uses", "Tool"),
}


@dataclass
class Node:
    id: str
    ntype: str
    attrs: dict


@dataclass
class Snapshot:
    t: int
    nodes: dict[str, Node]
    edges: set[tuple[str, str, str]]  # (src, dst, rel)


@dataclass
class ForecastResult:
    model: str
    precision_at_10: float
    recall_at_50: float
    f1_at_50: float
    lead_time_days: float
    calibration_error: float
    n_true_future: int
    notes: str = ""


def _sigmoid(x: np.ndarray) -> np.ndarray:
    x = np.clip(x, -20, 20)
    return 1.0 / (1.0 + np.exp(-x))


def build_world(seed: int = 7, months: int = 24) -> list[Snapshot]:
    """Plant a latent affinity process and reveal edges over monthly snapshots."""
    rng = np.random.default_rng(seed)
    nodes: dict[str, Node] = {}

    def add(prefix: str, n: int, ntype: str, attr_fn) -> list[str]:
        ids = []
        for i in range(n):
            nid = f"{prefix}-{i:03d}"
            nodes[nid] = Node(nid, ntype, attr_fn(i))
            ids.append(nid)
        return ids

    vulns = add("CVE", 28, "Vulnerability", lambda i: {
        "cvss": float(rng.uniform(4.0, 10.0)),
        "epss": float(rng.beta(1.4, 6.0)),
        "family": int(i % 7),
    })
    techs = add("T", 24, "Technique", lambda i: {"tactic": int(i % 6)})
    groups = add("G", 8, "AdversaryGroup", lambda i: {"sophistication": float(rng.uniform(0.2, 1))})
    sectors = add("S", 16, "TargetSector", lambda i: {"criticality": float(rng.uniform(0.3, 1))})
    tools = add("TOOL", 10, "Tool", lambda i: {"prevalence": float(rng.uniform(0.1, 1))})

    # Latent affinities that generate future edges. The model never sees these.
    g_tech = rng.random((len(groups), len(techs)))
    tech_vuln = (np.array([nodes[t].attrs["tactic"] for t in techs])[:, None]
                 == np.array([nodes[v].attrs["family"] % 6 for v in vulns])[None, :]).astype(float)
    tech_vuln = 0.15 + 0.85 * tech_vuln
    g_sector = rng.random((len(groups), len(sectors)))
    vuln_chain = rng.random((len(vulns), len(vulns)))
    np.fill_diagonal(vuln_chain, 0)
    g_tool = rng.random((len(groups), len(tools)))

    catalogs = {
        "uses": (groups, techs, g_tech, 0.22),
        "exploits": (techs, vulns, tech_vuln, 0.18),
        "targets": (groups, sectors, g_sector, 0.20),
        "chains-with": (vulns, vulns, vuln_chain, 0.08),
        "uses-tool": (groups, tools, g_tool, 0.16),
    }

    # Candidate universe with a birth month drawn from a hazard that rises with affinity.
    births: dict[tuple[str, str, str], int] = {}
    for rel, (srcs, dsts, aff, rate) in catalogs.items():
        edge_rel = "uses" if rel == "uses-tool" else rel
        for i, s in enumerate(srcs):
            for j, d in enumerate(dsts):
                if s == d:
                    continue
                p = rate * float(aff[i, j])
                # Geometric-like first appearance.
                if rng.random() < p * 1.6:
                    month = int(rng.integers(1, months))
                    # Higher affinity appears earlier on average.
                    month = int(np.clip(month - int(3 * aff[i, j]), 1, months - 1))
                    births[(s, d, edge_rel)] = month

    snapshots: list[Snapshot] = []
    revealed: set[tuple[str, str, str]] = set()
    for t in range(months):
        for edge, born in births.items():
            if born <= t:
                revealed.add(edge)
        snapshots.append(Snapshot(t=t, nodes=nodes, edges=set(revealed)))
    return snapshots


def schema_filter(edges: set[tuple[str, str, str]], nodes: dict[str, Node]) -> set[tuple[str, str, str]]:
    """Ontology constraint used by the extraction layer."""
    kept = set()
    for s, d, r in edges:
        if (nodes[s].ntype, r, nodes[d].ntype) in SCHEMA:
            kept.add((s, d, r))
    return kept


def _node_index(nodes: dict[str, Node]) -> tuple[list[str], dict[str, int]]:
    ids = sorted(nodes)
    return ids, {n: i for i, n in enumerate(ids)}


def encode_temporal(snapshots: list[Snapshot], dim: int = 16, decay: float = 0.72) -> np.ndarray:
    """Heterogeneous temporal message passing with exponential memory.

    H[v, τ] mixes the previous state with relation-typed neighbor means.
    Returns H at the last snapshot, shape (n_nodes, dim).
    """
    nodes = snapshots[-1].nodes
    ids, index = _node_index(nodes)
    n = len(ids)
    rng = np.random.default_rng(11)
    type_table = {t: rng.normal(0, 0.4, size=dim) for t in NODE_TYPES}
    rel_scale = {r: 0.55 + 0.1 * i for i, r in enumerate(EDGE_TYPES)}
    H = np.stack([type_table[nodes[i].ntype] for i in ids])
    # Attribute channel on dim 0 so CVSS/EPSS are visible to the encoder.
    for i, nid in enumerate(ids):
        attrs = nodes[nid].attrs
        H[i, 0] += 0.15 * float(attrs.get("cvss", attrs.get("criticality", 0.5)) or 0.5)

    for snap in snapshots:
        acc = np.zeros_like(H)
        counts = np.zeros(n)
        for s, d, r in snap.edges:
            scale = rel_scale[r]
            acc[index[d]] += scale * H[index[s]]
            acc[index[s]] += 0.35 * scale * H[index[d]]
            counts[index[s]] += 1
            counts[index[d]] += 1
        counts = np.maximum(counts, 1.0)[:, None]
        messages = acc / counts
        H = decay * H + (1.0 - decay) * messages
    # L2 normalize for stable scores.
    norms = np.linalg.norm(H, axis=1, keepdims=True)
    return H / np.maximum(norms, 1e-8)


def _rel_degrees(edges: set[tuple[str, str, str]]) -> dict[tuple[str, str], int]:
    """Map (node, role) counts. role is 'out:rel' or 'in:rel'."""
    deg: dict[tuple[str, str], int] = {}
    for s, d, r in edges:
        deg[(s, f"out:{r}")] = deg.get((s, f"out:{r}"), 0) + 1
        deg[(d, f"in:{r}")] = deg.get((d, f"in:{r}"), 0) + 1
    return deg


def _tactic_hist(edges: set[tuple[str, str, str]], nodes: dict[str, Node], group: str) -> np.ndarray:
    hist = np.zeros(6)
    for s, d, r in edges:
        if s == group and r == "uses" and nodes[d].ntype == "Technique":
            hist[int(nodes[d].attrs["tactic"])] += 1
    total = hist.sum()
    if total == 0:
        return np.ones(6) / 6
    return hist / total


def pair_features(history: list[Snapshot], edge: tuple[str, str, str], H: np.ndarray, index: dict[str, int]) -> np.ndarray:
    """Observable features only. No latent affinity matrix is read."""
    s, d, r = edge
    nodes = history[-1].nodes
    now = history[-1].edges
    deg = _rel_degrees(now)
    prev = history[max(0, len(history) - 4)].edges
    deg_prev = _rel_degrees(prev)
    out_now = deg.get((s, f"out:{r}"), 0)
    in_now = deg.get((d, f"in:{r}"), 0)
    out_g = out_now - deg_prev.get((s, f"out:{r}"), 0)
    in_g = in_now - deg_prev.get((d, f"in:{r}"), 0)
    # Schema-legal attribute compatibility. These fields exist on the nodes.
    compat = 0.0
    if r == "exploits":
        compat = 1.0 if int(nodes[s].attrs.get("tactic", -1)) == int(nodes[d].attrs.get("family", -2)) % 6 else 0.0
    elif r == "chains-with":
        compat = 1.0 if nodes[s].attrs.get("family") == nodes[d].attrs.get("family") else 0.0
    elif r == "targets":
        compat = float(nodes[d].attrs.get("criticality", 0.5))
    elif r == "uses" and nodes[d].ntype == "Technique":
        hist = _tactic_hist(now, nodes, s)
        compat = float(hist[int(nodes[d].attrs["tactic"])])
    elif r == "uses" and nodes[d].ntype == "Tool":
        compat = float(nodes[d].attrs.get("prevalence", 0.5))
    # Two-hop support: intermediates already tied to both endpoints.
    src_neighbors = {x for a, b, _ in now for x in ((b,) if a == s else (a,) if b == s else ())}
    dst_neighbors = {x for a, b, _ in now for x in ((b,) if a == d else (a,) if b == d else ())}
    shared = len(src_neighbors & dst_neighbors)
    rel = np.zeros(len(EDGE_TYPES))
    rel[EDGE_TYPES.index(r)] = 1.0
    dot = float(np.dot(H[index[s]], H[index[d]]))
    return np.array([
        out_now / 20.0,
        in_now / 20.0,
        out_g / 5.0,
        in_g / 5.0,
        compat,
        shared / 5.0,
        dot,
        float(nodes[d].attrs.get("epss", nodes[d].attrs.get("criticality", 0.0)) or 0.0),
        *rel,
    ], dtype=float)


def candidate_universe(snap: Snapshot) -> list[tuple[str, str, str]]:
    nodes = snap.nodes
    by_type: dict[str, list[str]] = {t: [] for t in NODE_TYPES}
    for n in nodes.values():
        by_type[n.ntype].append(n.id)
    cands = []
    for s_type, rel, d_type in SCHEMA:
        for s in by_type[s_type]:
            for d in by_type[d_type]:
                if s != d:
                    cands.append((s, d, rel))
    return cands


@dataclass
class ThreatForecaster:
    """Per-relation logistic decoders on temporal and schema features.

    One weight vector per edge type, matching g_phi(h_u, h_v, r).
    """

    dim: int = 16
    l2: float = 0.02
    steps: int = 220
    lr: float = 0.45
    weights: dict[str, np.ndarray] | None = field(default=None, repr=False)
    bias: dict[str, float] = field(default_factory=dict)

    def fit(self, snapshots: list[Snapshot], cutoff: int) -> "ThreatForecaster":
        hist = snapshots[: cutoff + 1]
        H = encode_temporal(hist, dim=self.dim)
        _, index = _node_index(hist[-1].nodes)
        present = snapshots[cutoff].edges
        born_by = {r: [] for r in EDGE_TYPES}
        for t in range(1, cutoff + 1):
            for edge in snapshots[t].edges - snapshots[t - 1].edges:
                born_by[edge[2]].append(edge)
        rng = np.random.default_rng(21)
        pool = [e for e in candidate_universe(snapshots[cutoff]) if e not in present]
        self.weights = {}
        self.bias = {}
        for rel in EDGE_TYPES:
            positives = born_by[rel][-80:]
            if not positives:
                self.weights[rel] = np.zeros(8)
                self.bias[rel] = -1.0
                continue
            neg_pool = [e for e in pool if e[2] == rel]
            take = min(len(neg_pool), len(positives) * 4)
            choice = rng.choice(len(neg_pool), size=max(take, 1), replace=False) if neg_pool else []
            negatives = [neg_pool[int(i)] for i in np.atleast_1d(choice)]
            X = [pair_features(hist, e, H, index)[:8] for e in positives + negatives]
            y = np.array([1.0] * len(positives) + [0.0] * len(negatives))
            X = np.asarray(X, dtype=float)
            sw = np.where(y == 1, 0.5 * len(y) / max((y == 1).sum(), 1), 0.5 * len(y) / max((y == 0).sum(), 1))
            w = np.zeros(X.shape[1])
            b = -0.3
            for _ in range(self.steps):
                p = _sigmoid(X @ w + b)
                err = (p - y) * sw
                w -= self.lr * (X.T @ err / sw.sum() + self.l2 * w)
                b -= self.lr * float(err.sum() / sw.sum())
            self.weights[rel] = w
            self.bias[rel] = float(b)
        return self

    def score(self, snapshots: list[Snapshot], cutoff: int) -> dict[tuple[str, str, str], float]:
        assert self.weights is not None
        hist = snapshots[: cutoff + 1]
        H = encode_temporal(hist, dim=self.dim)
        _, index = _node_index(hist[-1].nodes)
        known = snapshots[cutoff].edges
        scores = {}
        for edge in candidate_universe(snapshots[cutoff]):
            if edge in known:
                continue
            rel = edge[2]
            feat = pair_features(hist, edge, H, index)[:8]
            scores[edge] = float(_sigmoid(np.array(feat @ self.weights[rel] + self.bias[rel]))[()])
        return scores


def _topk(scores: dict[tuple, float], k: int) -> list[tuple]:
    return [e for e, _ in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:k]]


def _metrics(scores: dict[tuple, float], truth: set[tuple], horizon_days: int) -> ForecastResult:
    if not scores:
        return ForecastResult("empty", 0, 0, 0, 0, 1, len(truth))
    top10 = set(_topk(scores, 10))
    top50 = set(_topk(scores, 50))
    p10 = len(top10 & truth) / 10
    r50 = len(top50 & truth) / max(len(truth), 1)
    # F1 on the top-50 operating point.
    prec50 = len(top50 & truth) / 50
    f1 = 0.0 if prec50 + r50 == 0 else 2 * prec50 * r50 / (prec50 + r50)
    hits = top50 & truth
    lead = float(horizon_days) if hits else 0.0
    # Reliability diagram, 10 bins.
    bins = np.linspace(0, 1, 11)
    stated, empirical, weights = [], [], []
    items = list(scores.items())
    for lo, hi in zip(bins[:-1], bins[1:]):
        group = [e for e, p in items if lo <= p < hi or (hi == 1 and p == 1)]
        if not group:
            continue
        acc = sum(1 for e in group if e in truth) / len(group)
        center = (lo + hi) / 2
        stated.append(center)
        empirical.append(acc)
        weights.append(len(group))
    if weights:
        cal = float(np.average(np.abs(np.array(empirical) - np.array(stated)), weights=weights))
    else:
        cal = 1.0
    return ForecastResult("", p10, r50, f1, lead, cal, len(truth))


def _baseline_scores(snapshots: list[Snapshot], cutoff: int, kind: str) -> dict[tuple, float]:
    snap = snapshots[cutoff]
    nodes = snap.nodes
    known = snap.edges
    # Degree and attribute baselines.
    deg: dict[str, int] = {n: 0 for n in nodes}
    for s, d, _ in known:
        deg[s] += 1
        deg[d] += 1
    max_deg = max(deg.values()) or 1
    scores = {}
    for e in candidate_universe(snap):
        if e in known:
            continue
        s, d, r = e
        if kind == "epss":
            score = float(nodes[d].attrs.get("epss", 0.05))
            if nodes[s].ntype == "Vulnerability":
                score = 0.5 * (score + float(nodes[s].attrs.get("epss", 0.05)))
        elif kind == "cvss":
            raw = float(nodes[d].attrs.get("cvss", nodes[d].attrs.get("criticality", 5)))
            score = raw / 10.0
        elif kind == "static-degree":
            score = 0.5 * (deg[s] + deg[d]) / max_deg
        elif kind == "ema":
            # Intensity baseline: fraction of history the pair's endpoints were active.
            hits = 0
            for past in snapshots[: cutoff + 1]:
                active = {a for edge in past.edges for a in edge[:2]}
                if s in active and d in active:
                    hits += 1
            score = hits / max(cutoff + 1, 1)
        elif kind == "reactive":
            score = 0.0  # already-observed edges are excluded; reactive has no forecast
        else:
            raise ValueError(kind)
        scores[e] = score
    return scores


def run_retrospective(seed: int = 7, months: int = 24, cutoff: int = 18, horizon: int = 3) -> list[ForecastResult]:
    """Train through `cutoff` and score edges that first appear in (cutoff, cutoff+horizon]."""
    world = build_world(seed=seed, months=months)
    for snap in world:
        snap.edges = schema_filter(snap.edges, snap.nodes)
    future = world[min(cutoff + horizon, months - 1)].edges - world[cutoff].edges
    model = ThreatForecaster().fit(world, cutoff)
    scored = model.score(world, cutoff)
    rows = []
    primary = _metrics(scored, future, horizon_days=horizon * 30)
    primary.model = "DynSciGraph-TF"
    primary.notes = "synthetic retrospective; schema-constrained encoder-decoder"
    rows.append(primary)
    labels = {
        "epss": "EPSS-only baseline",
        "cvss": "CVSS-only ranking",
        "static-degree": "Static degree baseline",
        "ema": "EMA intensity baseline",
        "reactive": "Reactive baseline",
    }
    for kind, name in labels.items():
        m = _metrics(_baseline_scores(world, cutoff, kind), future, horizon_days=horizon * 30)
        m.model = name
        m.notes = "synthetic retrospective"
        rows.append(m)
    return rows


def calibration_table(seed: int = 7) -> list[dict]:
    world = build_world(seed=seed)
    for snap in world:
        snap.edges = schema_filter(snap.edges, snap.nodes)
    cutoff, horizon = 18, 3
    future = world[cutoff + horizon].edges - world[cutoff].edges
    scores = ThreatForecaster().fit(world, cutoff).score(world, cutoff)
    bins = []
    for i, lo in enumerate(np.linspace(0, 0.9, 10)):
        hi = lo + 0.1
        group = [(e, p) for e, p in scores.items() if lo <= p < hi or (i == 9 and p == 1)]
        if not group:
            continue
        acc = sum(1 for e, _ in group if e in future) / len(group)
        bins.append({
            "bin": f"{lo:.1f}-{hi:.1f}",
            "count": len(group),
            "mean_confidence": round(float(np.mean([p for _, p in group])), 4),
            "empirical_accuracy": round(acc, 4),
        })
    return bins


def math_self_check() -> dict:
    """Closed checks used by the unit tests."""
    world = build_world(seed=3, months=12)
    assert all(len(s.edges) <= len(world[-1].edges) for s in world)
    assert all(world[i].edges <= world[i + 1].edges for i in range(len(world) - 1))
    filtered = schema_filter(world[-1].edges, world[-1].nodes)
    assert filtered == world[-1].edges or filtered <= world[-1].edges
    H = encode_temporal(world[:8])
    assert H.shape[0] == len(world[-1].nodes)
    assert np.isfinite(H).all()
    rows = run_retrospective(seed=3, months=16, cutoff=11, horizon=3)
    assert rows[0].model == "DynSciGraph-TF"
    assert 0 <= rows[0].precision_at_10 <= 1
    assert rows[0].n_true_future > 0
    return {"nodes": len(world[-1].nodes), "final_edges": len(world[-1].edges), "future": rows[0].n_true_future}
