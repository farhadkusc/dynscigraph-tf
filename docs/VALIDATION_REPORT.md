# Validation report

**Paper.** DynSciGraph concept summary, April 2026, in `docs/DynSciGraph_Concept_Summary_v3.docx`.

**Repository.** Package 0.2.3. Figures below are `benchmarks/results/evaluation.json`.

The cutoff task is the paper's conditional edge forecast. The running model is the yearly neighbor aggregation and DistMult decoder in `src/dynscigraph/tgnn.py`. Baselines that run on the same candidates are a one-step encoder, an LSTM on yearly link counts, one-head attention on those counts, and degree. Metrics written for every cutoff are average precision, Precision@10, Recall@50, F1, calibration error, and lead time when the top 50 contains a hit.

Horizon 90 days, temporal average precision: 0.000685, 0.002405, 0.000634. Horizon 365 days: 0.001637, 0.006543, 0.002149. Precision@10 is 0. Recall@50 is 0.0053 on the 2023 cutoff at 365 days and 0 otherwise. F1 at probability 0.5 is 0. The one lead time recorded is 136 days on the 2023 cutoff at 365 days.

The EPSS-versus-KEV table is unchanged: average precision 0.003101 and 0.039463.

The concept paper's Table 7.3 is not copied into this file. The numbers above are the run of this repository.
