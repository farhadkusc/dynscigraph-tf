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

The encoder in the concept paper is a temporal GNN. The score here is the two graph statistics that survived a comparison with that GNN's obvious stand-in (a seven-feature logistic). Replacing the score with a PyTorch temporal GNN should keep the same cutoff code and the same JSON fields.
