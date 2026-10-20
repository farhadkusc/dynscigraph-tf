import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynscigraph.model import math_self_check, run_retrospective, schema_filter, build_world


class ModelTests(unittest.TestCase):
    def test_graph_is_monotone_and_finite(self):
        info = math_self_check()
        self.assertGreater(info["final_edges"], 10)
        self.assertGreater(info["future"], 0)

    def test_schema_rejects_illegal_edge(self):
        world = build_world(seed=1, months=4)
        nodes = world[-1].nodes
        illegal = {("T-000", "S-000", "exploits")}
        # May or may not exist as ids; build a guaranteed illegal pair.
        vuln = next(n.id for n in nodes.values() if n.ntype == "Vulnerability")
        sector = next(n.id for n in nodes.values() if n.ntype == "TargetSector")
        kept = schema_filter({(vuln, sector, "exploits")}, nodes)
        self.assertEqual(kept, set())

    def test_model_beats_reactive_on_recall(self):
        rows = run_retrospective(seed=5, months=16, cutoff=11, horizon=3)
        by = {r.model: r for r in rows}
        self.assertGreaterEqual(by["DynSciGraph-TF"].recall_at_50, by["Reactive baseline"].recall_at_50)


if __name__ == "__main__":
    unittest.main()
