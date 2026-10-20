# DynSciGraph-TF technical report

**Package version:** 0.1.0  
**Author:** Md Farhad Kabir  
**Status:** Runnable prototype. Synthetic validation only.

## Problem

Given snapshots \(G_1,\ldots,G_t\), rank typed edges that are absent at \(t\) and present by \(t+\Delta\). Primary operating points match the concept paper: Precision@10, Recall@50, F1, lead time in days, and calibration error

\[
\mathrm{CalErr} = \mathbb{E}_p\big[|\mathrm{accuracy}(C(p)) - p|\big].
\]

## Ontology

| Element | Kind | Constraint |
| --- | --- | --- |
| Vulnerability, Technique, AdversaryGroup, TargetSector, Tool | Node | Typed attributes (CVSS, EPSS, tactic, criticality) |
| uses | Edge | Group → Technique or Group → Tool |
| exploits | Edge | Technique → Vulnerability |
| targets | Edge | Group → Sector |
| chains-with | Edge | Vulnerability → Vulnerability |

Illegal triples are dropped before encoding. That is the schema-aligned extraction constraint from the paper, implemented here as a deterministic filter rather than an LLM call. A later extractor can emit the same triples.

## Training protocol

- 24 monthly snapshots, seed 7.
- Cutoff at month 18. No edge born after the cutoff is used as a positive.
- Negatives are schema-legal pairs absent at the cutoff.
- Horizon is 3 months (90 days). A hit in the top 50 is credited with a 90-day lead, which is the horizon itself, not a claimed operational mean lead time on real incidents.

## Baselines included

EPSS-attribute ranking, CVSS-attribute ranking, static endpoint degree, historical co-activity (an intensity / EMA stand-in for the LSTM baseline), and a reactive baseline that scores every unseen edge at 0.

## What this package does not claim

It does not report the paper's pending historical-cutoff table. It does not call a hosted LLM. It does not ingest live ISAC feeds. Those are Phase 1 and Phase 2 items in the concept paper.

## Reproduce

`python3 benchmarks/run_benchmark.py` rewrites `benchmarks/results/synthetic_validation.json`.
