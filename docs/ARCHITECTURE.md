# Architecture

```mermaid
flowchart LR
  A[ATT&CK STIX relationships] --> B[created timestamp]
  B --> C[Graph at cutoff T]
  C --> D[Bridge count and degree]
  D --> E[Rank absent group-technique pairs]
  F[EPSS daily file] --> H[Drop CVEs already in KEV]
  G[CISA KEV dateAdded] --> I[Label: added within 365 days]
  H --> I
```

The encoder aggregates group–technique neighbors once per year and the decoder is DistMult, fit on pairs dated on or before the cutoff. Static, LSTM, and attention baselines use the same candidates.
