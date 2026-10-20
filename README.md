# DynSciGraph-TF

Temporal link prediction for documented cyber relationships, evaluated on public data.

Author: **Md Farhad Kabir**. Package **0.2.3**.

Two tasks, both retrospective. Nothing in a test window is used to build features for that window.

## 1. ATT&CK group → technique

Source: MITRE ATT&CK Enterprise STIX (`enterprise-attack.json`, fetched 2026-10-19). The timestamp is the relationship's STIX `created` field: the day the link was **added to ATT&CK**, not the day of an intrusion.

Question: for pairs that are absent on a cutoff, which ones does ATT&CK add in the next 365 days? Endpoints that do not exist yet at the cutoff are excluded. That is the cold-start the knowledge base actually has; it is reported as a smaller positive set, not hidden.

The ranker is a fixed graph score: `log(1 + malware-bridge count) + 0.35 * log(1 + technique degree)`. The bridge counts malware that the group already uses and that already use the technique. The 0.35 is a constant, not fit on the test year. A logistic combination of seven features is reported next to it and does not win.

| Cutoff | Future links | Base rate | Graph AP | Logistic AP | Degree AP | Random AP | Graph P@10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 0.0020 | 0.0098 | 0.0040 | 0.0049 | 0.0019 | 0.10 |
| 2023-12-31 | 187 | 0.0035 | 0.0085 | 0.0050 | 0.0072 | 0.0036 | 0.00 |
| 2024-12-31 | 145 | 0.0022 | 0.0066 | 0.0021 | 0.0048 | 0.0021 | 0.00 |

Average precision of the fixed score is about 2–5× the base rate and ahead of degree on every cutoff. The seven-feature logistic, fit only on the prior year, does not beat it, and on 2024 it does not beat random. Precision@10 is 0.10 on one cutoff and 0 on the other two. That is the result. It is not an operational early-warning number.

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

`data/dummy/` is a labeled test corpus, not a feed. It covers all 15 U.S. cabinet departments, the cyber-relevant federal components, all 17 DOE national laboratories, IBM research and security units, and a fixed list of universities and research centers. Names are scenario labels. The observation graph and `vuln_catalog.csv` use `SYN-` identifiers so they cannot be confused with ATT&CK or CVE records.

```bash
python3 -m unittest tests/test_dummy.py
python3 benchmarks/run_dummy.py
```

`benchmarks/results/dummy_evaluation.json` is the fixture check. It is not part of the tables above.

Grey Harbor (`SYN-EXERCISE-GREY-HARBOR`) is the dummy attack inject in `data/dummy/attack_scenario.json`. The adversary `SYN-ACTOR-HARBOR` and the two sites are fictional. Six blue-cell ids are exercise roles, not breach reports. The held-out links are `SYN-TH-04` and `SYN-TH-05`. `SYN-TH-00` is known to the exercise observer and is not on the fictional tool, so the bridge score ranks it last.

## What this is not

Not a trained temporal GNN on live ISAC text. Not a claim about incident lead time. The concept paper's historical-cutoff table stays empty until that experiment is run; this package is the public-data experiment that can be run today.

## NJIT Wulver

`lab/njit/` is the heavy job: 1,536 cutoff fits (3 cutoffs, 4 horizons, 128 seeds) submitted with `sbatch lab/njit/wulver.sbatch` on the NJIT cluster. Instructions are in [lab/njit/README.md](lab/njit/README.md). `lab/njit/results/smoke.json` is only the two-job check.
