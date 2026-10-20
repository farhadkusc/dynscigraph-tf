# Synthetic institution fixtures

**Kind: synthetic. Not a measurement.**

Organization names are scenario labels for the class of institution a test row stands in for. No record in data/dummy is a measurement, feed, log, advisory, or policy from that organization. This project is not affiliated with and is not endorsed by any of them. benchmarks/results/dummy_evaluation.json is a fixture check. Do not cite it as an experimental result.

## What is in the directory

| File | Role |
| --- | --- |
| `organizations.csv` | One row per scenario label. |
| `attack_scenario.json` | Grey Harbor tabletop inject. Fictional adversary and fictional sites. |
| `MANIFEST.json` | Counts, seed 20261020, and the statement above. |

The observation graph uses the same columns as `data/derived` so `run_cutoff` can score it. Identifiers start with `FED-`, `FEDLAB-`, `IBM-`, `RES-`, `SYN-T`, or `SYN-VULN-`. They are not ATT&CK, CVE, or KEV identifiers. `vuln_catalog.csv` is a separable ranking fixture for the metric code.

## Scope

- All 15 U.S. cabinet departments.
- Cyber-relevant federal components, not every bureau.
- All 17 Department of Energy national laboratories.
- IBM research laboratories, IBM Quantum, IBM X-Force, IBM Security, and an IBM Federal contract-boundary row.
- Universities and research laboratories used as external comparison labels, including three DoD FFRDC-shaped rows (MIT Lincoln Laboratory, CMU SEI, Johns Hopkins APL).

`policy_profile` is an input to a test, not that institution's policy. `assumed_one_way_ms` is not a measured latency. Stack ids (`SYN-STACK-*`) are planted consortia for the graph fixture, not threat groups and not partnerships.

Grey Harbor (`SYN-EXERCISE-GREY-HARBOR`) is the shared attack inject. `SYN-ACTOR-HARBOR` is fictional. The blue-cell ids are exercise roles, not statements that those organizations were compromised. IBM Quantum is listed out of scope so the inject is not read as a device event.

Regenerate with `python3 benchmarks/build_dummy_fixtures.py`. The seed is fixed.
