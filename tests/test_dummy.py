import csv
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynscigraph.dummy import load_dummy_tables, load_organizations, run_dummy

ROOT = Path(__file__).resolve().parents[1]


class DummyFixtureTests(unittest.TestCase):
    def test_registry_covers_the_declared_scope(self):
        orgs = load_organizations()
        counts = {}
        for org in orgs:
            counts[org["klass"]] = counts.get(org["klass"], 0) + 1
        self.assertEqual(counts["federal-department"], 15)
        self.assertEqual(counts["national-laboratory"], 17)
        self.assertGreaterEqual(counts["federal-component"], 15)
        self.assertGreaterEqual(counts["ibm"], 8)
        self.assertGreaterEqual(counts["research-center"], 40)
        ids = {org["org_id"] for org in orgs}
        self.assertIn("FED-CISA", ids)
        self.assertIn("IBM-QUANTUM", ids)
        self.assertIn("RES-MIT-CSAIL", ids)

    def test_identifiers_are_not_real_catalog_ids(self):
        tables = load_dummy_tables()
        org_ids = {org["org_id"] for org in load_organizations()}
        for group, technique, _, _ in tables.gt:
            self.assertIn(group, org_ids)
            self.assertTrue(technique.startswith("SYN-T"))
            self.assertFalse(technique.startswith("T1"))
        for syn, *_ in tables.mt:
            self.assertTrue(syn.startswith("SYN-STACK-"))

    def test_planted_graph_and_catalog_beat_a_flat_ranking(self):
        report = run_dummy()
        self.assertEqual(report["kind"], "synthetic-fixture")
        graph = report["observation_graph"]
        self.assertGreater(graph["n_future"], 50)
        self.assertGreater(graph["ap"], graph["baselines"]["random"]["ap"])
        self.assertGreater(graph["ap"], graph["base_rate"])
        catalog = report["vulnerability_catalog"]
        self.assertGreater(catalog["average_precision"], 0.5)
        self.assertGreater(catalog["precision_at_10"], 0.5)
        with (ROOT / "data" / "dummy" / "vuln_catalog.csv").open(newline="") as f:
            syn_ids = [row["syn_id"] for row in csv.DictReader(f)]
        self.assertGreater(len(syn_ids), 100)
        self.assertTrue(all(syn_id.startswith("SYN-VULN-") for syn_id in syn_ids))

    def test_public_evaluation_is_untouched(self):
        public = json.loads((ROOT / "benchmarks" / "results" / "evaluation.json").read_text())
        self.assertEqual(public["package"], "dynscigraph-tf")
        self.assertIn("MITRE", public["attack"]["source"])
        self.assertNotIn("kind", public)
        saved = json.loads((ROOT / "benchmarks" / "results" / "dummy_evaluation.json").read_text())
        self.assertEqual(saved["kind"], "synthetic-fixture")
        self.assertEqual(saved["n_organizations"], 106)
        self.assertNotIn("MITRE", saved["statement"])


if __name__ == "__main__":
    unittest.main()
