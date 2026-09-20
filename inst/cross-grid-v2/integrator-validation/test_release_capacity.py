"""Capacity is descriptive; missing math or lifecycle proof still blocks PASS."""
import copy
import json
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).parent
rescore = runpy.run_path(str(ROOT / 'rescore-release-capacity.py'))['rescore']
POLICY = json.loads((ROOT / 'release-capacity.json').read_text())


class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(status='FAIL', capacity_pass=False, returncode=0,
            oracle_equal=True, cold=True, tamper=True, recovery=True, mode='recovery',
            source_commits={'dsVert': 'original-server', 'dsVertClient': 'original-client'},
            metrics=dict(end_to_end_release_elapsed=900000,
                         end_to_end_serialized_rpc_bytes=300000000000))

    def test_over_reference_and_missing_measurements_do_not_gate(self):
        for metrics in (self.record['metrics'], {}):
            original = dict(self.record, metrics=metrics)
            before = copy.deepcopy(original)
            result = rescore(original, POLICY)
            self.assertEqual(result['status'], 'PASS')
            self.assertFalse(result['capacity_pass'])
            self.assertEqual(result['source_commits'], before['source_commits'])
            self.assertEqual(original, before)
            self.assertEqual(rescore(result, POLICY), result)

    def test_missing_lifecycle_or_process_failure_cannot_pass(self):
        for field in ('oracle_equal', 'cold', 'tamper', 'recovery', 'returncode'):
            record = dict(self.record, **{field: 1 if field == 'returncode' else False})
            self.assertEqual(rescore(record, POLICY)['status'], 'FAIL')

    def test_baseline_does_not_claim_recovery(self):
        result = rescore(dict(self.record, mode='baseline', recovery=None), POLICY)
        self.assertEqual(result['status'], 'PASS')
        self.assertIsNone(result['recovery'])


if __name__ == '__main__':
    unittest.main()
