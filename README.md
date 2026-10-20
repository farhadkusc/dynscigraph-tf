# DynSciGraph-TF

Temporal link prediction for documented cyber relationships, evaluated on public data.

Author: **Md Farhad Kabir**. Package **0.2.4**. The research draft is [docs/PAPER.md](docs/PAPER.md). The same text is `docs/DynSciGraph_Concept_Summary_v3.docx`. Both are generated from `benchmarks/results/evaluation.json`.

Two tasks, both retrospective. Nothing in a test window is used to build features for that window.

## 1. ATT&CK group → technique

Source: MITRE ATT&CK Enterprise STIX (`enterprise-attack.json`, fetched 2026-10-19). The timestamp is the relationship's STIX `created` field: the day the link was **added to ATT&CK**, not the day of an intrusion.

Question: for pairs that are absent on a cutoff, which ones does ATT&CK add in the next 365 days? Endpoints that do not exist yet at the cutoff are excluded. That is the cold-start the knowledge base actually has; it is reported as a smaller positive set, not hidden.

The score of a missing pair is `log(1 + malware bridge) + a · log(1 + degree) + b · log(1 + decayed degree)`. The decayed degree sums earlier yearly link counts with weight `exp(−λ · age)`. The coefficients `a`, `b`, and `λ` are chosen by average precision on the year before the cutoff. The test horizon is not used for that choice. F1 uses a threshold chosen on the last 90 days of the training year. Calibration error is the weighted ten-bin gap on that same held-out slice. Degree, the malware bridge, the score without the decay term, a seven-feature logistic, and two yearly-count baselines are reported beside it.

### 90 days

| Cutoff | Future | Base rate | Selected | No decay | Bridge | Degree | Logistic | P@10 | R@50 | F1 | CalErr | Lead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 40 | 0.000863 | 0.001841 | 0.001962 | 0.001717 | 0.001645 | 0.002664 | 0.00 | 0.0000 | 0.000000 | 0.0492 | |
| 2023-12-31 | 57 | 0.001057 | 0.002702 | 0.002131 | 0.002131 | 0.001607 | 0.001459 | 0.00 | 0.0175 | 0.005951 | 0.0496 | 53 |
| 2024-12-31 | 40 | 0.000609 | 0.001347 | 0.000726 | 0.000726 | 0.001302 | 0.000535 | 0.00 | 0.0000 | 0.002894 | 0.0483 | |

Coefficients selected on the previous year: 2022 uses `a = 0.25`, `b = 1`, `λ = 2`; 2023 uses `a = 0`, `b = 0.5`, `λ = 0.5`; 2024 uses `a = 0`, `b = 1`, `λ = 1`.

### 365 days

| Cutoff | Future | Base rate | Selected | No decay | Bridge | Degree | Logistic | P@10 | R@50 | F1 | CalErr | Lead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 0.002027 | 0.009217 | 0.009837 | 0.008235 | 0.004899 | 0.003960 | 0.10 | 0.0213 | 0.017167 | 0.0492 | 224 |
| 2023-12-31 | 187 | 0.003468 | 0.009252 | 0.005153 | 0.005153 | 0.007158 | 0.005025 | 0.00 | 0.0053 | 0.022337 | 0.0496 | 53 |
| 2024-12-31 | 145 | 0.002207 | 0.006880 | 0.004489 | 0.004489 | 0.004786 | 0.002101 | 0.00 | 0.0069 | 0.013490 | 0.0483 | 192 |

On the 365-day horizon the selected score is ahead of degree at every cutoff and ahead of the logistic at every cutoff. Dropping the decay term raises 2022 average precision from 0.009217 to 0.009837 and lowers 2023 from 0.009252 to 0.005153 and 2024 from 0.006880 to 0.004489. Precision@10 is 0.10 on the 2022 cutoff and 0 on the other two. Recall@50 is 0.0213, 0.0053, and 0.0069. Lead time is the mean number of days from the cutoff to the edge timestamp for the hits inside the top 50.

## 2. EPSS file versus later CISA KEV

Universe: CVEs in the EPSS daily file that are not already in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) on that date. Score: the published EPSS probability, unfitted. Label: KEV `dateAdded` within 365 days.

| Score date | Later KEV adds | Base rate | AP | Lift vs base | P@10 | P@100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2024-06-01 | 69 | 0.000278 | 0.0031 | 11× | 0.00 | 0.02 |
| 2025-06-01 | 92 | 0.000329 | 0.0395 | 120× | 0.30 | 0.08 |

Both windows were chosen as the June 1 files on hand before Precision@10 was inspected. The 2024 window has ranking lift and no hit in the top 10. The 2025 window puts 3 of the next year's KEV entries in the top 10.

## Reproduce

```bash
python3 -m unittest tests/test_public.py
python3 benchmarks/run_benchmark.py
python3 benchmarks/plot_results.py
```

The figure is [docs/figures/results.svg](docs/figures/results.svg). Derived ATT&CK tables and the two EPSS gzip files are in the repository so the benchmark does not download 50 MB on every run. `data/SOURCES.md` has the upstream URLs, the catalog version, and the fetch date.

## Synthetic fixtures

`data/dummy/` is the labeled test corpus. It covers all 15 U.S. cabinet departments, the cyber-relevant federal components, all 17 DOE national laboratories, IBM research and security units, and a fixed list of universities and research centers. The observation graph and `vuln_catalog.csv` use `SYN-` identifiers.

```bash
python3 -m unittest tests/test_dummy.py
python3 benchmarks/run_dummy.py
```

`benchmarks/results/dummy_evaluation.json` is the fixture check.

Grey Harbor (`SYN-EXERCISE-GREY-HARBOR`) is the dummy attack inject in `data/dummy/attack_scenario.json`. The adversary is `SYN-ACTOR-HARBOR`. The sites are `SYN-SITE-RIVER-SWITCH` and `SYN-SITE-LOCK-METER`. The blue cell is DOE, CISA, Idaho National Laboratory, IBM X-Force, IBM Federal, and CMU SEI. The held-out links are `SYN-TH-04` and `SYN-TH-05`. `SYN-TH-00` is the unbridged technique.

## NJIT Wulver

`lab/njit/` is the heavy job: 1,536 cutoff fits (3 cutoffs, 4 horizons, 128 seeds) submitted with `sbatch lab/njit/wulver.sbatch` on the NJIT cluster. Instructions are in [lab/njit/README.md](lab/njit/README.md). Smoke output is `lab/njit/results/smoke.json`.
