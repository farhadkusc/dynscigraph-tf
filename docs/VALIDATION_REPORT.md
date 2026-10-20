# Validation report

**Paper.** DynSciGraph-TF: A Temporal Knowledge Graph Forecasting Framework for Pre-incident Cyber Threat Prediction in U.S. Critical Infrastructure. Research concept paper, Md Farhad Kabir, April 2026.

**Repository.** [farhadkusc/dynscigraph-tf](https://github.com/farhadkusc/dynscigraph-tf), package 0.2.3, commit `bce937e` (`uploaded as public`).

**Checked against.** `benchmarks/results/evaluation.json`, `src/dynscigraph/attack.py`, `src/dynscigraph/kev.py`, README.

**Report date.** 20 October 2026.

## 1. Purpose

This report checks the concept paper against the public repository. It records what the code computes, which paper claims that computation supports, and which paper claims have no corresponding result.

The paper states that empirical results are not yet available and leaves Table 7.3 empty. This report does not fill that table.

## 2. What the paper specifies

Section 3 defines the task as

`P(E_{t+Δ} \ E_t | G_1, …, G_t)`

with edge probabilities from a temporal encoder and a decoder. Section 4 specifies three layers: schema-aligned LLM extraction, a cybersecurity temporal graph neural network, and calibrated predictions with explanations. Section 5 gives pseudocode for extraction, message passing, decoding, and isotonic calibration.

Section 7 plans seven baselines (EPSS-only, CVSS-only, static GNN, LSTM, Transformer, non-LLM extraction, reactive MITRE+EPSS) and four reported columns: Precision@10, Recall@50, lead time in days, and F1. Three tasks are named: emerging techniques, vulnerability chaining, and adversary technique evolution. The timestamp of a correct prediction is supposed to precede first operational observation.

## 3. What the repository computes

Two retrospective ranking tasks. Features for a window are built only from records dated on or before the cutoff.

**Task A.** Group–technique links in MITRE ATT&CK Enterprise STIX. The time field is `relationship.created`, the day the link was written into ATT&CK. Snapshot fetched 19 October 2026. Endpoints that do not yet exist at the cutoff are excluded. Horizon is 365 days. The score is

`log(1 + malware-bridge count) + 0.35 · log(1 + technique degree)`.

The constant 0.35 is fixed. A seven-feature logistic regression is fit on the previous year and reported beside the fixed score. Degree-only, bridge-only, and random scores are also reported.

**Task B.** CVEs present in an EPSS daily file and absent from CISA KEV on that date, ranked by the published EPSS probability. The label is addition to KEV within 365 days. Windows: 1 June 2024 and 1 June 2025. KEV catalog date in the file is 16 October 2026.

`benchmarks/results/evaluation.json` is stamped `version` 0.2.0. The package version in `src/dynscigraph/__init__.py` is 0.2.3. The numbers below are the JSON file.

## 4. Numerical results

### 4.1 ATT&CK group → technique

| Cutoff | Future links | Candidates | Base rate | Graph AP | Lift | P@10 | P@50 | R@50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2022-12-31 | 94 | 46,376 | 0.002027 | 0.009788 | 4.83 | 0.10 | 0.04 | 0.0213 |
| 2023-12-31 | 187 | 53,923 | 0.003468 | 0.008478 | 2.44 | 0.00 | 0.00 | 0.0000 |
| 2024-12-31 | 145 | 65,689 | 0.002207 | 0.006616 | 3.00 | 0.00 | 0.04 | 0.0138 |

Average precision of the other scores:

| Cutoff | Logistic | Degree | Bridge only | Random |
| --- | ---: | ---: | ---: | ---: |
| 2022-12-31 | 0.003960 | 0.004899 | 0.008235 | 0.001852 |
| 2023-12-31 | 0.005025 | 0.007158 | 0.005153 | 0.003644 |
| 2024-12-31 | 0.002101 | 0.004786 | 0.004489 | 0.002119 |

On every cutoff the fixed score is above the base rate, above degree, and above the logistic fit. On the 2024 cutoff the logistic average precision (0.002101) is below random (0.002119). Precision@10 is nonzero on one cutoff only.

Recall@50 is in the JSON. The README table does not show it. Lead time and F1 are not computed.

### 4.2 EPSS file versus later KEV

| Score date | Universe | Later KEV | Base rate | AP | Lift | P@10 | P@100 | R@100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2024-06-01 | 247,899 | 69 | 0.000278 | 0.003101 | 11.14 | 0.00 | 0.02 | 0.029 |
| 2025-06-01 | 279,411 | 92 | 0.000329 | 0.039463 | 119.85 | 0.30 | 0.08 | 0.087 |

The 2025 window places 3 of 92 later KEV entries in the top 10. The 2024 window places none.

## 5. Claim check

| Paper claim | Repository | Result |
| --- | --- | --- |
| Conditional probability of future edges given history | Cutoff ranking of absent group–technique pairs | Partial. Same question, different estimator. |
| Horizon example of 90 days; several cutoffs across at least three years | Three year-end cutoffs, horizon fixed at 365 days in the published JSON. The lab script can sweep 90, 180, 365, and 540 days. That sweep is not in `evaluation.json`. | Partial |
| LLM extraction with an ontology | No extractor, no ontology file, no ISAC text | Absent |
| Temporal GNN encoder and edge decoder | Fixed bridge and degree score; logistic baseline | Absent |
| Calibration error and isotonic map | Not computed | Absent |
| Schema: CVE, technique, group, CISA sector, tool; edges uses, exploits, targets, chains-with | Groups, techniques, malware from ATT&CK STIX | Partial. One edge type of the schema. |
| Precision@10 | Reported | Present |
| Recall@50 | Reported in JSON, omitted from the README table | Present |
| Lead time against first operational observation | Time field is the ATT&CK documentation date | Absent |
| F1 | Not computed for this task | Absent |
| Seven planned baselines, including CVSS, static GNN, LSTM, Transformer | Logistic, degree, bridge, random, and unfitted EPSS | Partial. Two of the seven ideas, in reduced form. |
| EPSS as a 30-day exploitation probability | EPSS used unfitted, label is KEV addition inside 365 days | Different task |
| Vulnerability-chaining task | No vulnerability–vulnerability edges | Absent |
| Section 6 attacks: poisoning, obfuscation, output gaming, prompt injection, model extraction, bias | Not implemented. Grey Harbor is a separate synthetic inject under `data/dummy/`. | Absent |
| Table 7.3 | Still not the table in the paper. Columns and models differ. | Do not copy these numbers into Table 7.3 |

## 6. Arithmetic check

Lifts match the JSON quotients.

- 0.009788 / 0.002027 = 4.83
- 0.008478 / 0.003468 = 2.44
- 0.006616 / 0.002207 = 3.00
- 0.003101 / 0.00027834 = 11.14
- 0.039463 / 0.00032926 = 119.85

Recall@50 on the 2022 cutoff: 0.04 × 50 / 94 = 0.0213. On the 2024 cutoff: 0.04 × 50 / 145 = 0.0138. Both match the file.

## 7. Finding

The repository is a public-data ranking experiment on ATT&CK documentation dates and on EPSS-versus-KEV. It supports the paper's decision to evaluate by historical cutoff, and it supplies Precision@10 and Recall@50 for one non-neural ranker.

It does not implement the LLM, the temporal GNN, the calibration layer, the lead-time definition, or the seven-baseline table. The paper's own statement that those results are not yet available remains accurate after this check.

## 8. Source of the numbers

Regenerate with:

```bash
python3 benchmarks/run_benchmark.py
```

Inputs are listed in `data/SOURCES.md`.
