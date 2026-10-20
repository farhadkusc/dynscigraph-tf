# Validation report

**Paper.** DynSciGraph concept summary, April 2026, `docs/DynSciGraph_Concept_Summary_v3.docx`.

**Repository.** Package 0.2.4. Figures are `benchmarks/results/evaluation.json`.

The score is `log(1+bridge) + a log(1+degree) + b log(1+decayed degree)`. `a`, `b`, and `λ` are selected by average precision on the year before the cutoff. The F1 threshold and the calibration error use the last 90 days of that year.

365-day average precision of the selected score: 0.009217, 0.009252, 0.006880. Degree: 0.004899, 0.007158, 0.004786. The no-decay ablation is 0.009837, 0.005153, 0.004489. Precision@10 is 0.10, 0.00, 0.00. Recall@50 is 0.0213, 0.0053, 0.0069. Lead time of the top-50 hits is 224, 53, and 192 days.

The EPSS-versus-KEV average precisions are 0.003101 and 0.039463.
