#!/usr/bin/env python3
"""Score the synthetic fixtures. Does not touch evaluation.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dynscigraph.dummy import run_dummy  # noqa: E402


def main() -> None:
    report = run_dummy()
    out = ROOT / "benchmarks" / "results" / "dummy_evaluation.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    graph = report["observation_graph"]
    catalog = report["vulnerability_catalog"]
    print(
        f"synthetic graph AP {graph['ap']:.3f} base {graph['base_rate']:.3f} "
        f"catalog AP {catalog['average_precision']:.3f}"
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
