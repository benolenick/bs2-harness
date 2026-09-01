import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReconDeterminismTests(unittest.TestCase):
    def test_recon_plan_is_stable_across_hash_seeds(self):
        script = """
import json
from ariadne.frontier import recon_plan
from ariadne.loader import load_operators, load_target

target = load_target('scenarios/phantomkernel_mid.yaml')
print(json.dumps(recon_plan(target, load_operators(), max_steps=5), sort_keys=True))
"""
        outputs = []
        for seed in ("1", "2", "5", "8"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outputs.append(subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=ROOT,
                env=env,
                text=True,
            ))
        self.assertEqual(len(set(outputs)), 1, outputs)


if __name__ == "__main__":
    unittest.main()
