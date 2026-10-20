# DynSciGraph-TF

Temporal link prediction for documented cyber relationships, evaluated on public data.

Author: **Md Farhad Kabir**. Package **0.2.3**.

Two tasks, both retrospective. Nothing in a test window is used to build features for that window.

## 1. ATT&CK group → technique

Source: MITRE ATT&CK Enterprise STIX (`enterprise-attack.json`, fetched 2026-10-19). The timestamp is the relationship's STIX `created` field: the day the link was **added to ATT&CK**, not the day of an intrusion.

Question: for pairs that are absent on a cutoff, which ones does ATT&CK add in the next 365 days? Endpoints that do not exist yet at the cutoff are excluded. That is the cold-start the knowledge base actually has; it is reported as a smaller positive set, not hidden.

The model is the temporal encoder in the concept paper. Each year aggregates group–technique neighbors and updates node states. A DistMult decoder is fit on pairs dated on or before the cutoff. The same cutoff also reports a one-step static encoder, an LSTM on yearly link counts, a one-head attention model on those counts, degree, the malware bridge, and a seven-feature logistic. Horizon 90 days is the horizon in the concept paper. Horizon 365 days is the same cutoff code run for a full year.

### 90 days

| Cutoff | Future links | Base rate | Temporal AP | Static AP | LSTM AP | Attention AP | Degree AP | P@10 | R@50 | CalErr |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 40 | 0.000863 | 0.000685 | 0.001062 | 0.001567 | 0.001515 | 0.001645 | 0.00 | 0.0000 | 0.0123 |
| 2023-12-31 | 57 | 0.001057 | 0.002405 | 0.000751 | 0.001584 | 0.001803 | 0.001607 | 0.00 | 0.0000 | 0.0260 |
| 2024-12-31 | 40 | 0.000609 | 0.000634 | 0.000532 | 0.001290 | 0.001353 | 0.001302 | 0.00 | 0.0000 | 0.0006 |

### 365 days

| Cutoff | Future links | Base rate | Temporal AP | Static AP | LSTM AP | Attention AP | Degree AP | P@10 | R@50 | CalErr | Lead time |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 0.002027 | 0.001637 | 0.002133 | 0.005616 | 0.004370 | 0.004899 | 0.00 | 0.0000 | 0.0123 | |
| 2023-12-31 | 187 | 0.003468 | 0.006543 | 0.002205 | 0.008149 | 0.007270 | 0.007158 | 0.00 | 0.0053 | 0.0260 | 136 |
| 2024-12-31 | 145 | 0.002207 | 0.002149 | 0.001763 | 0.005354 | 0.004638 | 0.004786 | 0.00 | 0.0000 | 0.0006 | |

F1 at probability 0.5 is 0 on every cutoff. Lead time is the mean number of days from the cutoff to the edge timestamp for hits inside the top 50. Precision@10 is 0 on every cutoff. On the 90-day horizon the temporal encoder is ahead of the static encoder at the 2023 and 2024 cutoffs. On the 365-day horizon the LSTM and the degree score are ahead of the temporal encoder.

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
