import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynscigraph.attack import load_tables, run_cutoff
from dynscigraph.kev import evaluate_window
from dynscigraph.metrics import average_precision
import numpy as np


class PublicDataTests(unittest.TestCase):
    def test_tables_match_the_fetched_snapshot(self):
        tables = load_tables()
        self.assertGreater(len(tables.gt), 4000)
        self.assertTrue(all(len(row[3]) == 10 for row in tables.gt))

    def test_attack_cutoff_is_sane(self):
        tables = load_tables()
        run = run_cutoff(tables, "2024-12-31", seed=7)
        self.assertGreater(run["n_future"], 50)
        self.assertGreater(run["n_candidates"], 10000)
        self.assertGreaterEqual(run["ap"], 0.0)
        self.assertLessEqual(run["ap"], 1.0)
        self.assertGreater(run["ap"], run["baselines"]["random"]["ap"])
        self.assertGreater(run["baselines"]["malware_bridge"]["ap"], run["base_rate"])

    def test_epss_window_has_the_known_base_rate(self):
        window = evaluate_window("2024-06-01")
        self.assertGreater(window["n_scored_not_yet_kev"], 200000)
        self.assertGreater(window["n_added_to_kev"], 20)
        self.assertGreater(window["lift_ap_vs_base"], 1.0)

    def test_average_precision_perfect(self):
        y = np.array([0, 1, 0, 1])
        self.assertAlmostEqual(average_precision(y, np.array([0, 2, 0, 1])), 1.0)


if __name__ == "__main__":
    unittest.main()
