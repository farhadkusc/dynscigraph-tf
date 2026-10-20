import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WulverSmokeTests(unittest.TestCase):
    def test_smoke_profile_is_labeled_and_finishes(self):
        subprocess.check_call(
            [sys.executable, str(ROOT / "lab" / "njit" / "run_lab.py"), "--profile", "smoke", "--workers", "2"],
            cwd=ROOT,
        )
        report = json.loads((ROOT / "lab" / "njit" / "results" / "smoke.json").read_text())
        self.assertEqual(report["profile"], "smoke")
        self.assertFalse(report["ran_on_wulver"])
        self.assertEqual(report["n_jobs"], 2)
        self.assertEqual(report["summary"][0]["horizon_days"], 365)
        self.assertEqual(report["summary"][0]["graph_ap_span"], 0.0)


if __name__ == "__main__":
    unittest.main()
