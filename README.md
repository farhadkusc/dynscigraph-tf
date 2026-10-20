# DynSciGraph-TF

Temporal knowledge-graph forecasting prototype for pre-incident cyber threat prediction in U.S. critical infrastructure.

Author: **Md Farhad Kabir**

This repository is the runnable reference package for the DynSciGraph-TF concept: schema-constrained extraction, a cybersecurity temporal encoder, an edge decoder, and calibrated ranking. The forecasting task is

\[
P(E_{t+\Delta}\setminus E_t \mid G_1,\ldots,G_t)
\]

## What is in the package

| Path | Role |
| --- | --- |
| `src/dynscigraph/model.py` | World model, ontology filter, temporal encoder, logistic decoder, baselines, metrics |
| `benchmarks/run_benchmark.py` | Retrospective cutoff experiment; writes `benchmarks/results/synthetic_validation.json` |
| `docs/TECHNICAL_REPORT.md` | Architecture, metrics, and how to read the numbers |
| `docs/ARCHITECTURE.md` | Pipeline diagram |
| `tests/test_model.py` | Monotonicity, schema rejection, forecast-vs-reactive check |

## Run

```bash
python3 -m pip install -r requirements.txt
python3 -m unittest tests/test_model.py
python3 benchmarks/run_benchmark.py
```

## Honest scope

The benchmark is a **synthetic retrospective**. A planted affinity process reveals edges over 24 months. The model is trained only on months `0..18` and scored on edges that first appear in the next 90 days. It does **not** train on MITRE ATT&CK, NVD, or EPSS dumps. Those sources are the planned Phase-1 corpus in the concept paper. Do not cite the JSON numbers as operational detection performance.

## Layout of the model

1. **Schema filter.** An edge is kept only if `(source type, relation, target type)` is in the ontology (`uses`, `exploits`, `targets`, `chains-with`).
2. **Temporal encoder.** Each month, a node state is a decayed mix of its previous state and relation-scaled neighbor means.
3. **Decoder.** Pair features (elementwise interaction, both endpoints, relation id, dot product) are scored by L2-regularized logistic regression fit on edges born before the cutoff versus sampled negatives.
4. **Metrics.** Precision@10, Recall@50, F1 at the top-50 operating point, lead time, and binned calibration error.

## License

MIT. See `LICENSE`.
