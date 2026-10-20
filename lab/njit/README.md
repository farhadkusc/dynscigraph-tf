# NJIT Wulver job

Heavy run for [Wulver](https://hpc.njit.edu/clusters/get_started_on_Wulver). Output of the lab profile is `lab/njit/results/lab.json`.

The lab profile repeats the public ATT&CK cutoff at three year-ends, four horizons (90, 180, 365, 540 days), and 128 negative-sample seeds: 1,536 ranker fits. The graph score ignores the seed. The logistic baseline uses it.

## Smoke, on any machine

```bash
python3 lab/njit/run_lab.py --profile smoke --workers 2
```

Two jobs, cutoff 2024-12-31, horizon 365. Output: `lab/njit/results/smoke.json`.

## Submit

From the clone root, on a Wulver login node:

```bash
# Put your UCID on the account line in lab/njit/wulver.sbatch first.
sbatch lab/njit/wulver.sbatch
squeue -u "$USER"
```

The script requests the `general` partition, QoS `standard`, 8 CPUs, 16 GB, and a two-hour limit. Logs land in `lab/njit/logs/`. The full result is `lab/njit/results/lab.json`.

Login, storage, and the account flag are the steps on the Wulver getting-started page.
