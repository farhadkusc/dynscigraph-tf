#!/bin/bash
# Submit from the repository root, on the NJIT Wulver login node:
#   sbatch lab/njit/wulver.sbatch
# Wulver partitions and QoS are documented at https://hpc.njit.edu/Software/slurm/slurm/
# and https://hpc.njit.edu/clusters/get_started_on_Wulver
#SBATCH --job-name=dynsci-wulver
#SBATCH --partition=general
#SBATCH --qos=standard
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=02:00:00
#SBATCH --output=lab/njit/logs/%x.%j.out
#SBATCH --error=lab/njit/logs/%x.%j.err
##SBATCH --account=YOUR_UCID

set -euo pipefail
cd "${SLURM_SUBMIT_DIR}"
mkdir -p lab/njit/logs lab/njit/results
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export MKL_NUM_THREADS=1

VENV="${HOME}/venvs/dynsci-wulver"
if [[ ! -x "${VENV}/bin/python" ]]; then
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install --upgrade pip
  "${VENV}/bin/pip" install -r requirements.txt
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"
python lab/njit/run_lab.py --profile lab --workers "${SLURM_CPUS_PER_TASK}"
