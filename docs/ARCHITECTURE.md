# Architecture

```mermaid
flowchart LR
  A[Structured feeds<br/>MITRE, NVD, EPSS] --> C[Ontology filter]
  B[Unstructured reports] --> C
  C --> D[Monthly snapshots G_1 .. G_t]
  D --> E[Temporal encoder<br/>relation-typed messages + decay]
  E --> F[Edge decoder]
  F --> G[Ranked edges + confidence bins]
```

The checked-in encoder is a NumPy message-passing model with the same interfaces as the TGNN in the concept paper: per-relation aggregation, a temporal state, and an edge head `g(h_u, h_v, r)`. Swapping the encoder for a PyTorch Geometric temporal GNN does not change the benchmark harness.
