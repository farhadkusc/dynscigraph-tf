# Data sources

Fetched 2026-10-19. Derived tables are what the benchmark reads. Raw STIX is not committed (53 MB); the extraction keeps identifiers, tactics, and `created` dates.

| File | Upstream | What was kept |
| --- | --- | --- |
| `derived/group_technique.csv` | [MITRE ATT&CK Enterprise STIX](https://github.com/mitre-attack/attack-stix-data) `enterprise-attack.json` | intrusion-set `uses` attack-pattern, not revoked or deprecated. 4,815 rows. |
| `derived/malware_technique.csv` | same | malware `uses` attack-pattern. 10,739 rows. |
| `derived/group_malware.csv` | same | intrusion-set `uses` malware. 691 rows. |
| `derived/subtechnique.csv` | same | `subtechnique-of`. 479 rows. |
| `derived/cisa_kev.csv` | [CISA known exploited vulnerabilities JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | catalog version 2026.10.16, released 2026-10-16. 1,748 CVEs. US government work. |
| `raw/epss_scores-2024-06-01.csv.gz` | `https://epss.empiricalsecurity.com/epss_scores-2024-06-01.csv.gz` | FIRST / Empirical Security daily file. Model comment in the gzip: v2023.03.01, score_date 2024-06-01. |
| `raw/epss_scores-2025-06-01.csv.gz` | `https://epss.empiricalsecurity.com/epss_scores-2025-06-01.csv.gz` | Same publisher. Score date 2025-06-01. |

ATT&CK is a MITRE knowledge base. Cite MITRE ATT&CK and keep the upstream license terms if you redistribute the STIX. EPSS is published by FIRST. KEV is a CISA catalog.

Refresh the derived ATT&CK tables by downloading `enterprise-attack.json` from the `attack-stix-data` repository and rerunning the extractor described in `docs/TECHNICAL_REPORT.md`. Do not treat a newer file as comparable to the numbers in `benchmarks/results/evaluation.json` unless you rerun the benchmark and replace that file.
