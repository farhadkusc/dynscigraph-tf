# DynSciGraph-TF

A temporal-relational score for missing group–technique edges in MITRE ATT&CK, and an unfitted EPSS ranking against later CISA KEV additions.

Md Farhad Kabir

Research draft for package 0.2.4, aligned with `benchmarks/results/evaluation.json` and `benchmarks/results/dummy_evaluation.json`. Repository farhadkusc/dynscigraph-tf.

## Abstract

The forecast is which intrusion-set to attack-pattern edges are absent from an ATT&CK snapshot and appear within 90 days or within 365 days. The time field is the STIX `relationship.created` date. Endpoints that do not exist at the cutoff are excluded. The score is

log(1 + malware bridge) + a · log(1 + technique degree) + b · log(1 + decayed degree).

The decayed degree sums yearly link counts with weight exp(−λ · age). The triple (a, b, λ) is chosen by average precision on the year before the cutoff. The test horizon is not used for that choice. F1 uses a threshold chosen on the last 90 days of the training year. Calibration error is the size-weighted ten-bin gap on that same slice.

On the 365-day horizon the selected average precision is 0.009217, 0.009252, and 0.00688. Degree average precision on the same cutoffs is 0.004899, 0.007158, and 0.004786. Precision@10 is 0.1, 0.0, and 0.0.

A second task ranks CVEs in an EPSS daily file that are not yet in CISA KEV. The score is the EPSS value from that file. Average precision is 0.003101 on the 2024-06-01 file and 0.039463 on the 2025-06-01 file.

## 1. Data

ATT&CK Enterprise STIX, fetched 2026-10-19. The relationship is intrusion-set `uses` attack-pattern. Derived tables are in `data/derived/`. EPSS files are `epss_scores-2024-06-01.csv.gz` and `epss_scores-2025-06-01.csv.gz`. The KEV catalog date in the result file is 2026.10.16, fetched 2026-10-19.

## 2. Score

A snapshot at date T keeps edges with `created` ≤ T. A future edge has T < `created` ≤ T + horizon, and both endpoints already appear at T. The malware bridge between group g and technique t counts malware that g already uses and that already use t, using only edges dated on or before the feature date.

Feature dates are the cutoff for the test ranking and the date 365 days earlier for coefficient selection. The search grid is a in {0, 0.25, 0.5, 1, 2}, b in {0, 0.5, 1}, and λ in {0, 0.5, 1, 2}. The no-decay column sets b = 0 and keeps the selected a.

The probability used for calibration is a one-dimensional logistic fit on the training scores, excluding the last 90 days. Those 90 days supply the F1 threshold and the calibration error. Ranking uses the raw score.

Lead time is the mean number of days from the cutoff to `relationship.created` for hits inside the top 50. A cutoff with no hit in the top 50 records none.

## 3. ATT&CK results

Columns are average precision unless named otherwise. Selected is the score with the chosen (a, b, λ).

### 90 days

| Cutoff | Future | Candidates | Base | Selected | No decay | Bridge | Degree | Logistic | LSTM | Attention | Random | P@10 | P@50 | R@50 | F1 | CalErr | Lead | a | b | lambda | Train AP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 40 | 46376 | 0.000863 | 0.001841 | 0.001962 | 0.001717 | 0.001645 | 0.002664 | 0.001577 | 0.001678 | 0.000977 | 0.0 | 0.0 | 0.0 | 0.0 | 0.049217 | none | 0.25 | 1.0 | 2.0 | 0.020143 |
| 2023-12-31 | 57 | 53923 | 0.001057 | 0.002702 | 0.002131 | 0.002131 | 0.001607 | 0.001459 | 0.001334 | 0.001657 | 0.001095 | 0.0 | 0.02 | 0.0175 | 0.005951 | 0.049568 | 53.0 | 0.0 | 0.5 | 0.5 | 0.010333 |
| 2024-12-31 | 40 | 65689 | 0.000609 | 0.001347 | 0.000726 | 0.000726 | 0.001302 | 0.000535 | 0.000931 | 0.001715 | 0.00061 | 0.0 | 0.0 | 0.0 | 0.002894 | 0.048328 | none | 0.0 | 1.0 | 1.0 | 0.0094 |

### 365 days

| Cutoff | Future | Candidates | Base | Selected | No decay | Bridge | Degree | Logistic | LSTM | Attention | Random | P@10 | P@50 | R@50 | F1 | CalErr | Lead | a | b | lambda | Train AP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 46376 | 0.002027 | 0.009217 | 0.009837 | 0.008235 | 0.004899 | 0.00396 | 0.005543 | 0.005692 | 0.001852 | 0.1 | 0.04 | 0.0213 | 0.017167 | 0.049217 | 224.0 | 0.25 | 1.0 | 2.0 | 0.020143 |
| 2023-12-31 | 187 | 53923 | 0.003468 | 0.009252 | 0.005153 | 0.005153 | 0.007158 | 0.005025 | 0.006949 | 0.008029 | 0.003644 | 0.0 | 0.02 | 0.0053 | 0.022337 | 0.049568 | 53.0 | 0.0 | 0.5 | 0.5 | 0.010333 |
| 2024-12-31 | 145 | 65689 | 0.002207 | 0.00688 | 0.004489 | 0.004489 | 0.004786 | 0.002101 | 0.004242 | 0.005619 | 0.002119 | 0.0 | 0.02 | 0.0069 | 0.01349 | 0.048328 | 192.0 | 0.0 | 1.0 | 1.0 | 0.0094 |

On the 365-day horizon the selected score is above degree at each cutoff. Removing the decay term changes 2022 from 0.009217 to 0.009837, 2023 from 0.009252 to 0.005153, and 2024 from 0.00688 to 0.004489.

## 4. EPSS against later KEV

The universe is every CVE in the EPSS file that is not already in KEV on the score date. The label is KEV addition within 365 days. The score is the EPSS probability in the file. The two June 1 files were fixed before Precision@10 was read.

| Score date | Horizon end | Universe | Later KEV | Base | AP | Lift | P@10 | P@50 | P@100 | R@100 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2024-06-01 | 2025-06-01 | 247899 | 69 | 0.00027834 | 0.003101 | 11.14 | 0.0 | 0.02 | 0.02 | 0.029 |
| 2025-06-01 | 2026-06-01 | 279411 | 92 | 0.00032926 | 0.039463 | 119.85 | 0.3 | 0.14 | 0.08 | 0.087 |

## 5. Grey Harbor

Exercise SYN-EXERCISE-GREY-HARBOR. Adversary SYN-ACTOR-HARBOR. Cutoff 2026-03-31. Held-out techniques are SYN-TH-04, SYN-TH-05. The unbridged technique is SYN-TH-00. The same cutoff function returns n_future 2, n_candidates 3, average precision 1.0, and base rate 0.666667. Degree average precision on that fixture is 0.583333. These figures are in `dummy_evaluation.json`. The organization file has 106 scenario labels.

## 6. Reproduce

python3 benchmarks/run_benchmark.py

python3 benchmarks/run_dummy.py

Code: `src/dynscigraph/tgnn.py`, function `forecast`, called from `run_cutoff` in `src/dynscigraph/attack.py`.
