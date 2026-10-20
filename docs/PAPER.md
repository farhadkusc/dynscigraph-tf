# DynSciGraph-TF

Temporal-relational ranking of missing group–technique edges in MITRE ATT&CK, with an unfitted EPSS ranking against later additions to the CISA Known Exploited Vulnerabilities catalog.

Md Farhad Kabir

Research draft for package 0.2.4. Every figure in this draft is taken from `benchmarks/results/evaluation.json` or `benchmarks/results/dummy_evaluation.json` in farhadkusc/dynscigraph-tf. The generator that wrote this file reads those two files and refuses a draft in which a recorded figure is absent.

## Abstract

The forecasting question is which directed edges from an intrusion set to an attack pattern are absent from a dated ATT&CK snapshot and appear within a stated horizon. The time field is the STIX `relationship.created` timestamp, the date the relationship object was added to the knowledge base. A candidate pair is scored only if both endpoints already exist at the cutoff. The score is

s(g, t) = log(1 + B(g, t)) + a · log(1 + d(t)) + b · log(1 + d_λ(t)),

where B(g, t) is the malware-bridge count, d(t) is the number of intrusion sets that already use technique t, and d_λ(t) is a decayed sum of the yearly counts of new uses of t. The coefficients a, b, and the decay constant λ are chosen by average precision on the year before the cutoff. The test horizon is not an input to that choice.

On the 365-day horizon the selected average precision is 0.009217 at the 2022 cutoff, 0.009252 at the 2023 cutoff, and 0.00688 at the 2024 cutoff. Degree average precision on those cutoffs is 0.004899, 0.007158, and 0.004786. Precision at 10 is 0.1, 0.0, and 0.0.

A second task leaves the graph. It ranks every CVE that appears in an EPSS daily file and is not yet listed in CISA KEV. The score is the EPSS probability printed in that file. Average precision is 0.003101 for the file dated 2024-06-01 and 0.039463 for the file dated 2025-06-01.

## 1. Question

Let G_T be the directed typed graph of ATT&CK relationships whose `created` field is on or before date T. The forecast at horizon Δ is the set of group–technique edges with T < created ≤ T + Δ whose two endpoints are already present in G_T. The model returns a real score for every pair (g, t) that is absent from G_T. Higher scores rank first. The implementation is `forecast` in `src/dynscigraph/tgnn.py`, called from `run_cutoff` in `src/dynscigraph/attack.py`.

Two horizons are reported, 90 days and 365 days, at the cutoffs 2022-12-31, 2023-12-31, and 2024-12-31. The 90-day horizon is the horizon written into the forecasting definition. The 365-day horizon is the same function with a longer window, so the coefficient selection, which always uses the preceding 365 days, is shared by the two horizons of a given cutoff. That is why the selected (a, b, λ), the calibration error, and the F1 threshold are identical across the two horizons of one cutoff, while the labels and therefore the average precision are not.

## 2. Graph

The derived tables in `data/derived/` are built from the ATT&CK Enterprise STIX bundle fetched on 2026-10-19.

| Table | Record | Role in the score |
| --- | --- | --- |
| group_technique.csv | intrusion set, attack pattern, tactic, created | The predicted edge, and the degree |
| malware_technique.csv | malware, attack pattern, created | One side of the bridge |
| group_malware.csv | intrusion set, malware, created | The other side of the bridge |
| subtechnique.csv | child, parent, created | A binary feature in the logistic baseline only |

A snapshot at date T retains an edge if and only if its `created` value is less than or equal to T. Degree d(t) is the number of distinct intrusion sets that use t in that snapshot. The bridge B(g, t) counts malware m such that the group–malware edge and the malware–technique edge are both dated on or before T and t is not already used by g. A technique that g already uses is not a candidate, so the bridge is defined on the complement.

The decayed degree uses the calendar year of `created`. If c(t, y) is the number of group–technique edges for technique t whose year is y, and Y is the year of the feature date, then

d_λ(t) = Σ_y c(t, y) · exp(−λ · (Y − y)),

the sum running over years y ≤ Y. λ = 0 recovers a sum of historical counts. Larger λ concentrates the sum on the most recent year.

## 3. Coefficient selection

The feature date for selection is 365 days before the cutoff. Training pairs are the group–technique pairs that are absent at that earlier date and whose endpoints exist then. A training pair is positive when ATT&CK adds the edge on or before the cutoff. The grid is

a ∈ {0, 0.25, 0.5, 1, 2}, b ∈ {0, 0.5, 1}, λ ∈ {0, 0.5, 1, 2}.

There are 5 · 3 · 4 = 60 triples. Each triple is scored by average precision on the training pairs. The winning triple is frozen and applied to candidates at the cutoff, with features recomputed from the cutoff snapshot. The test labels are not an argument of the search.

The no-decay column uses the selected a and sets b = 0. When the search itself selects a = 0, the no-decay column equals the bridge column, because the score reduces to log(1 + B(g, t)). That equality is visible at the 2023 and 2024 cutoffs.

If the training year has no positive edges, the code falls back to a = 0.35, b = 0, λ = 0. None of the six public cutoffs takes that branch. Each reports a `train_ap` above zero.

## 4. Probability, threshold, and calibration

Ranking uses the raw score s(g, t). A separate one-dimensional logistic,

p = σ(w · s + b), σ(z) = 1 / (1 + exp(−clip(z, −20, 20))),

is fit for calibration only. The fit excludes a tail. A training positive is in the tail when its `created` date falls in the last 90 days before the cutoff. One fifth of the training negatives, taken as every fifth negative in the constructed order, are also in the tail. The logistic uses 80 gradient steps at learning rate 0.4 and an L2 coefficient of 0.01 on w. The slope is not constrained. Ranking does not use p, so a negative slope cannot invert the reported order.

The F1 threshold is the score quantile, among 50 quantiles from 0.50 to 0.999 of the tail scores, that maximizes F1 on the tail. That threshold is then applied to the test scores. It is stored as `f1_threshold`.

Calibration error uses ten equal bins on [0, 1]. A bin with fewer than five tail probabilities is skipped. Inside a kept bin the error is the absolute gap between the positive rate and the bin center. The reported CalErr is the mean of those gaps weighted by the bin counts. This is the definition in `calibration_error`.

Lead time is the mean, over true positives that fall inside the top 50, of (created − cutoff) in days. A cutoff whose top 50 contains no true positive records none. The value is therefore defined only when Recall@50 is positive, and it is a property of the hits, not of the whole positive set.

## 5. Baselines

All baselines are scored on the same candidate list as the selected score.

Degree is log(1 + d(t)) at the cutoff. The reactive-degree column is the same vector. The malware bridge is log(1 + B(g, t)) at the cutoff.

The seven-feature logistic is a different estimator. It is fit on the training window with features taken at the start of that window, so a positive edge is not a feature of itself. Negatives are a sample of eight times the positive count, drawn with seed 7. Class weights balance the two classes. The optimizer runs 300 steps at learning rate 0.5 with L2 coefficient 0.02. The seven coordinates, each passed through log(1 + ·) except the two rates, are:

1. number of intrusion sets using the technique,
2. number of techniques the group already uses,
3. a collaborative sum, over other users of the technique, of shared-technique count divided by log(2 + that group's technique count),
4. the malware bridge,
5. whether the group already uses the parent technique of a sub-technique, and the parent edge is dated on or before the feature date,
6. the share of the group's existing edges that carry the technique's tactic,
7. the count of new uses of the technique during the year that ends at the feature date.

The indicator baselines ignore the group. Yearly technique counts for the six years ending at the cutoff are stored in a matrix. A ridge map from the last observed year onto the next year produces the column labeled LSTM. Weights exp(−0.5 · age), normalized to sum to one, produce the column labeled Attention. Both are functions of the technique index of the candidate, so every group that shares a technique receives the same indicator score.

The random column is a uniform ranking drawn with seed equal to the cutoff seed plus one. Average precision of that ranking sits next to the base rate, as a ranking of an uninformed order must.

## 6. Metric definitions

Average precision is Σ_k Precision(k) · rel(k) / N_relevant, with ties broken by a stable mergesort on the negated score. Precision@k is the positive rate inside the first k positions. Recall@k is the fraction of all positives that fall inside those k positions. F1 is the harmonic mean of precision and recall at a single threshold. Base rate is the positive rate of the candidate list. Lift is average precision divided by that base rate.

## 7. ATT&CK results, 90 days

| Cutoff | Future | Candidates | Base | Selected | No decay | Bridge | Degree | Logistic | LSTM | Attention | Random | P@10 | P@50 | R@50 | F1 | CalErr | Lead | a | b | lambda | Train AP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 40 | 46376 | 0.000863 | 0.001841 | 0.001962 | 0.001717 | 0.001645 | 0.002664 | 0.001577 | 0.001678 | 0.000977 | 0.0 | 0.0 | 0.0 | 0.0 | 0.049217 | none | 0.25 | 1.0 | 2.0 | 0.020143 |
| 2023-12-31 | 57 | 53923 | 0.001057 | 0.002702 | 0.002131 | 0.002131 | 0.001607 | 0.001459 | 0.001334 | 0.001657 | 0.001095 | 0.0 | 0.02 | 0.0175 | 0.005951 | 0.049568 | 53.0 | 0.0 | 0.5 | 0.5 | 0.010333 |
| 2024-12-31 | 40 | 65689 | 0.000609 | 0.001347 | 0.000726 | 0.000726 | 0.001302 | 0.000535 | 0.000931 | 0.001715 | 0.00061 | 0.0 | 0.0 | 0.0 | 0.002894 | 0.048328 | none | 0.0 | 1.0 | 1.0 | 0.0094 |

### Reading the 90 days table

Cutoff 2022-12-31. The candidate set has 46376 pairs and 40 positives, so the base rate is 0.000863. The selected score, with a = 0.25, b = 1.0, and λ = 2.0, has average precision 0.001841. That is 2.13 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.020143. Degree is 0.001645. The malware bridge alone is 0.001717. Setting the decay weight to zero, which is the no-decay column, gives 0.001962. The seven-feature logistic is 0.002664. The last-year ridge indicator is 0.001577. The exponential year-weight indicator is 0.001678. A uniform random ranking is 0.000977. Precision at 10 is 0.0 and precision at 50 is 0.0. Recall at 50 is 0.0. F1 at the threshold 4.168384504977334 chosen on the training tail is 0.0. The size-weighted ten-bin calibration error on that tail is 0.049217. Lead time of the top-50 hits is none days.

Cutoff 2023-12-31. The candidate set has 53923 pairs and 57 positives, so the base rate is 0.001057. The selected score, with a = 0.0, b = 0.5, and λ = 0.5, has average precision 0.002702. That is 2.56 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.010333. Degree is 0.001607. The malware bridge alone is 0.002131. Setting the decay weight to zero, which is the no-decay column, gives 0.002131. The seven-feature logistic is 0.001459. The last-year ridge indicator is 0.001334. The exponential year-weight indicator is 0.001657. A uniform random ranking is 0.001095. Precision at 10 is 0.0 and precision at 50 is 0.02. Recall at 50 is 0.0175. F1 at the threshold 1.1916526747508918 chosen on the training tail is 0.005951. The size-weighted ten-bin calibration error on that tail is 0.049568. Lead time of the top-50 hits is 53.0 days.

Cutoff 2024-12-31. The candidate set has 65689 pairs and 40 positives, so the base rate is 0.000609. The selected score, with a = 0.0, b = 1.0, and λ = 1.0, has average precision 0.001347. That is 2.21 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.0094. Degree is 0.001302. The malware bridge alone is 0.000726. Setting the decay weight to zero, which is the no-decay column, gives 0.000726. The seven-feature logistic is 0.000535. The last-year ridge indicator is 0.000931. The exponential year-weight indicator is 0.001715. A uniform random ranking is 0.00061. Precision at 10 is 0.0 and precision at 50 is 0.0. Recall at 50 is 0.0. F1 at the threshold 2.0399802564456078 chosen on the training tail is 0.002894. The size-weighted ten-bin calibration error on that tail is 0.048328. Lead time of the top-50 hits is none days.


On a 90-day horizon the positive sets are 40, 57, and 40 edges. Precision at 10 is 0.0 at every cutoff in this horizon. The only cutoff with a top-50 hit is 2023-12-31, where recall at 50 is 0.0175 and the lead time of that hit is 53.0 days. The 2022 and 2024 rows record lead time none.

## 8. ATT&CK results, 365 days

| Cutoff | Future | Candidates | Base | Selected | No decay | Bridge | Degree | Logistic | LSTM | Attention | Random | P@10 | P@50 | R@50 | F1 | CalErr | Lead | a | b | lambda | Train AP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 46376 | 0.002027 | 0.009217 | 0.009837 | 0.008235 | 0.004899 | 0.00396 | 0.005543 | 0.005692 | 0.001852 | 0.1 | 0.04 | 0.0213 | 0.017167 | 0.049217 | 224.0 | 0.25 | 1.0 | 2.0 | 0.020143 |
| 2023-12-31 | 187 | 53923 | 0.003468 | 0.009252 | 0.005153 | 0.005153 | 0.007158 | 0.005025 | 0.006949 | 0.008029 | 0.003644 | 0.0 | 0.02 | 0.0053 | 0.022337 | 0.049568 | 53.0 | 0.0 | 0.5 | 0.5 | 0.010333 |
| 2024-12-31 | 145 | 65689 | 0.002207 | 0.00688 | 0.004489 | 0.004489 | 0.004786 | 0.002101 | 0.004242 | 0.005619 | 0.002119 | 0.0 | 0.02 | 0.0069 | 0.01349 | 0.048328 | 192.0 | 0.0 | 1.0 | 1.0 | 0.0094 |

### Reading the 365 days table

Cutoff 2022-12-31. The candidate set has 46376 pairs and 94 positives, so the base rate is 0.002027. The selected score, with a = 0.25, b = 1.0, and λ = 2.0, has average precision 0.009217. That is 4.55 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.020143. Degree is 0.004899. The malware bridge alone is 0.008235. Setting the decay weight to zero, which is the no-decay column, gives 0.009837. The seven-feature logistic is 0.00396. The last-year ridge indicator is 0.005543. The exponential year-weight indicator is 0.005692. A uniform random ranking is 0.001852. Precision at 10 is 0.1 and precision at 50 is 0.04. Recall at 50 is 0.0213. F1 at the threshold 4.168384504977334 chosen on the training tail is 0.017167. The size-weighted ten-bin calibration error on that tail is 0.049217. Lead time of the top-50 hits is 224.0 days.

Cutoff 2023-12-31. The candidate set has 53923 pairs and 187 positives, so the base rate is 0.003468. The selected score, with a = 0.0, b = 0.5, and λ = 0.5, has average precision 0.009252. That is 2.67 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.010333. Degree is 0.007158. The malware bridge alone is 0.005153. Setting the decay weight to zero, which is the no-decay column, gives 0.005153. The seven-feature logistic is 0.005025. The last-year ridge indicator is 0.006949. The exponential year-weight indicator is 0.008029. A uniform random ranking is 0.003644. Precision at 10 is 0.0 and precision at 50 is 0.02. Recall at 50 is 0.0053. F1 at the threshold 1.1916526747508918 chosen on the training tail is 0.022337. The size-weighted ten-bin calibration error on that tail is 0.049568. Lead time of the top-50 hits is 53.0 days.

Cutoff 2024-12-31. The candidate set has 65689 pairs and 145 positives, so the base rate is 0.002207. The selected score, with a = 0.0, b = 1.0, and λ = 1.0, has average precision 0.00688. That is 3.12 times the base rate. The same coefficients, scored on the year used to choose them, had average precision 0.0094. Degree is 0.004786. The malware bridge alone is 0.004489. Setting the decay weight to zero, which is the no-decay column, gives 0.004489. The seven-feature logistic is 0.002101. The last-year ridge indicator is 0.004242. The exponential year-weight indicator is 0.005619. A uniform random ranking is 0.002119. Precision at 10 is 0.0 and precision at 50 is 0.02. Recall at 50 is 0.0069. F1 at the threshold 2.0399802564456078 chosen on the training tail is 0.01349. The size-weighted ten-bin calibration error on that tail is 0.048328. Lead time of the top-50 hits is 192.0 days.


Three comparisons hold on every 365-day cutoff. The selected average precision is above the degree average precision. It is above the seven-feature logistic. It is above the random ranking.

The decay term is not uniformly helpful. At the 2022 cutoff the no-decay score is 0.009837 and the selected score is 0.009217. At the 2023 cutoff the selected score is 0.009252 and the no-decay score is 0.005153. At the 2024 cutoff the selected score is 0.00688 and the no-decay score is 0.004489. The search is allowed to set b = 0. It did not. The 2022 test year is the year in which that choice costs average precision.

Precision at 10 is 0.1 at the 2022 cutoff, which is one hit in the first ten, and 0.0 and 0.0 at the later cutoffs. Recall at 50 is 0.0213, 0.0053, and 0.0069. Lead times of those hits are 224.0, 53.0, and 192.0 days.

The calibration errors, 0.049217, 0.049568, and 0.048328, are properties of the training tail. They do not change when the test horizon changes.

## 9. EPSS against later KEV

This task does not use the graph score. The universe is every CVE present in an EPSS daily file and absent from CISA KEV on the file date. The score is the EPSS probability in the file. The label is addition to KEV within 365 days. The catalog version recorded with the result is 2026.10.16, fetched 2026-10-19. The two score dates are the June 1 files already in the repository. They were fixed before precision at 10 was inspected.

| Score date | Horizon end | Universe | Later KEV | Base | AP | Lift | P@10 | P@50 | P@100 | R@100 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2024-06-01 | 2025-06-01 | 247899 | 69 | 0.00027834 | 0.003101 | 11.14 | 0.0 | 0.02 | 0.02 | 0.029 |
| 2025-06-01 | 2026-06-01 | 279411 | 92 | 0.00032926 | 0.039463 | 119.85 | 0.3 | 0.14 | 0.08 | 0.087 |

The 2024-06-01 file scores 247899 CVEs that are not yet in the catalog. 69 of them are added by 2025-06-01. Average precision 0.003101 is 11.14 times the base rate 0.00027834. Precision at 10 is 0.0. Precision at 100 is 0.02, and recall at 100 is 0.029.

The 2025-06-01 file scores 279411 CVEs. 92 are added by 2026-06-01. Average precision 0.039463 is 119.85 times the base rate 0.00032926. Precision at 10 is 0.3, which is three of the ten highest EPSS values among CVEs not yet listed. Precision at 50 is 0.14. Precision at 100 is 0.08. Recall at 100 is 0.087.

The two windows do not agree about the head of the list. The earlier window has ranking lift and an empty top 10. The later window places later KEV additions inside the top 10. Both numbers are in the result file.

## 10. Grey Harbor

The fixture is a separate graph under `data/dummy/`. Identifiers begin with `SYN-`. Exercise SYN-EXERCISE-GREY-HARBOR, titled Grey Harbor. The adversary is SYN-ACTOR-HARBOR. The sites are SYN-SITE-RIVER-SWITCH, SYN-SITE-LOCK-METER. The blue cell is FED-DOE, FED-CISA, FEDLAB-INL, IBM-XFORCE, IBM-FEDERAL, RES-CMU-SEI. The out-of-scope organization is IBM-QUANTUM. The cutoff is 2026-03-31. The held-out techniques are SYN-TH-04, SYN-TH-05. The unbridged technique is SYN-TH-00.

The same `run_cutoff` function returns n_future 2, n_candidates 3, average precision 1.0, and base rate 0.666667. Degree average precision on the fixture is 0.583333. Bridge average precision is 1.0. These figures are in `dummy_evaluation.json`. The organization file contains 106 scenario labels covering the cabinet departments, the cyber-relevant federal components, the seventeen DOE national laboratories, IBM research and security units, and a fixed list of universities and research centers.

The public ATT&CK numbers and the fixture numbers are written by different commands into different files. A reader of `evaluation.json` is reading the public graph. A reader of `dummy_evaluation.json` is reading the fixture.

## 11. Software

| Path | Role |
| --- | --- |
| src/dynscigraph/tgnn.py | Snapshot, decay, grid search, calibration, indicator scores |
| src/dynscigraph/attack.py | Cutoff, seven-feature logistic, metric packing |
| src/dynscigraph/metrics.py | Average precision, precision at k, recall at k, F1 |
| src/dynscigraph/epss_kev.py | The unfitted EPSS ranking |
| benchmarks/run_benchmark.py | Writes evaluation.json |
| benchmarks/plot_results.py | Writes docs/figures/results.svg for the 365-day horizon |
| lab/njit/run_lab.py | Seed sweep written for the NJIT Wulver cluster |
| lab/njit/wulver.sbatch | Slurm header for that job |
| data/SOURCES.md | Upstream URLs, catalog version, fetch date |

The public benchmark does not download the STIX bundle on each run. The derived CSV files and the two EPSS gzip files are in the repository.

## 12. Procedure, as executed

The public benchmark calls `run_cutoff` once for each pair of horizon and cutoff. Inside that call the order is fixed.

1. Build G at the cutoff from group–technique edges with `created` on or before the cutoff. Endpoints of that graph are the only legal endpoints.
2. Positives are group–technique edges with cutoff < created ≤ cutoff + horizon and both endpoints legal. Candidates are the legal pairs that are absent at the cutoff.
3. Call `forecast`. It rebuilds a snapshot 365 days earlier, enumerates pairs absent at that date, labels an edge positive if it appears by the cutoff, and searches the 60-point grid.
4. The winning (a, b, λ) is applied at the cutoff snapshot. The no-decay vector uses the same a and b = 0.
5. The tail logistic and the F1 threshold are fit on the training scores. They do not see test labels.
6. Indicator scores are fit on yearly technique counts that stop at the cutoff year.
7. The seven-feature logistic is fit on a class-balanced sample whose features are taken at the start of the training window. Seed 7 draws the negatives.
8. Average precision, precision at 10, precision at 50, recall at 50, and F1 are computed on the candidate list. Lead time uses the top 50 of the selected score.

The random column uses seed 8, because the cutoff seed is 7 and the random generator is constructed as seed + 1. Re-running the benchmark replaces `evaluation.json` with the same figures, because every sample and every sort is seeded and the sort is a stable mergesort.

## 13. Reproduce

python3 -m unittest tests/test_public.py tests/test_dummy.py tests/test_lab_smoke.py

python3 benchmarks/run_benchmark.py

python3 benchmarks/run_dummy.py

python3 benchmarks/plot_results.py

Package version recorded in the result file: 0.2.4.
