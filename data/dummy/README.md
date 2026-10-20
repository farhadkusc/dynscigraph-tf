# Synthetic institution fixtures

**Kind: synthetic.**

Organization names are scenario labels for the class of institution a test row stands in for.

## What is in the directory

| File | Role |
| --- | --- |
| `organizations.csv` | One row per scenario label. |
| `attack_scenario.json` | Grey Harbor tabletop inject. |
| `MANIFEST.json` | Counts, seed 20261020, and the statement above. |

The observation graph uses the same columns as `data/derived` so `run_cutoff` can score it. Identifiers start with `FED-`, `FEDLAB-`, `IBM-`, `RES-`, `SYN-T`, or `SYN-VULN-`. `vuln_catalog.csv` is the ranking fixture for the metric code.

## Scope

- All 15 U.S. cabinet departments.
- Cyber-relevant federal components, not every bureau.
- All 17 Department of Energy national laboratories.
- IBM research laboratories, IBM Quantum, IBM X-Force, IBM Security, and an IBM Federal contract-boundary row.
- Universities and research laboratories used as external comparison labels, including three DoD FFRDC-shaped rows (MIT Lincoln Laboratory, CMU SEI, Johns Hopkins APL).

`policy_profile` selects the signature branch. `assumed_one_way_ms` is the delay input. Stack ids (`SYN-STACK-*`) are the planted consortia for the graph fixture.

Grey Harbor (`SYN-EXERCISE-GREY-HARBOR`) is the shared attack inject. The adversary is `SYN-ACTOR-HARBOR`. The blue cell is the exercise roster.

Regenerate with `python3 benchmarks/build_dummy_fixtures.py`. The seed is fixed.
