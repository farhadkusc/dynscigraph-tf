# Technical report

**Version 0.2.3.** Author: Md Farhad Kabir.

## Question

The concept paper writes the forecast as \(P(E_{t+\Delta}\setminus E_t \mid G_1,\ldots,G_t)\). This package instantiates that on two public graphs instead of a planted synthetic process.

## ATT&CK protocol

1. Drop revoked and deprecated objects and relationships.
2. A snapshot at cutoff \(T\) contains group→technique edges with `created` ≤ \(T\).
3. Positives in the next year are edges with \(T <\) `created` ≤ \(T+365\) days whose group and technique both already appear in the snapshot. New techniques are out of the candidate set. They are a different task (cold start) and are not scored as misses.
4. Features at \(T\): technique degree, group degree, collaborative-filtering weight, count of the group's pre-existing malware that use the technique, whether the group already uses the parent technique, the group's historical tactic share, and the technique's link count during the previous year.
5. The reported score uses only the bridge count and the degree, with a fixed coefficient 0.35. A logistic regression on all seven features is fit inside each training year (features taken at the start of that year) and stored under `logistic_combination`. It does not beat the fixed score.

Cutoffs 2022-12-31, 2023-12-31, and 2024-12-31 were fixed as year ends. They were not picked by scanning Precision@10.

## KEV protocol

EPSS files are the publisher's daily gzip. A CVE already in KEV on the score date is removed before ranking. Addition dates come from the CISA catalog of 2026-10-16. The score is the EPSS value from that file.

## Leakage controls

- Test-year ATT&CK edges are not in the degree, the bridge, or the tactic counts.
- Training-year features for the logistic are computed at the start of the training year, so the positive edge is not already in the graph used to describe it.
- EPSS percentiles and scores are taken from the file whose `score_date` is the cutoff.

## Numbers

See `benchmarks/results/evaluation.json`. The README table is that file, rounded.

## Synthetic fixtures

`data/dummy/` replays the same cutoff code on a planted observation graph whose nodes are scenario labels (federal departments, DOE laboratories, IBM units, research centers). Identifiers are `SYN-T` and `SYN-VULN`. Output is `benchmarks/results/dummy_evaluation.json`.

Grey Harbor is a separate six-technique graph. The fictional actor's held-out links are the ones its fictional tool already covers. `SYN-TH-00` is the unbridged negative. Blue-cell organization ids are not nodes in that graph.
