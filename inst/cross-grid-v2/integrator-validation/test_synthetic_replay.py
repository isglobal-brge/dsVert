"""Short record-validator tests; no DSLite processes or statistical batteries."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).with_name('run-structured-noise-replay.py')
SPEC = importlib.util.spec_from_file_location('synthetic_replay', PATH)
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


class SyntheticReplayRecordTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(
            version='dsvert-public-synthetic-release-replay-v1',
            data_classification='public-synthetic-test-fixture',
            seed_scope='test-harness-only-never-production-secrets',
            exact_coordinates=['4', '9007199254740993'],
            released_coordinates=['4', '9007199254740992'],
            criterion_index_base=1, criterion_indices=[2],
            exact_candidate_criterion_integers=['9007199254740993'],
            exact_coordinates_sha256=hashlib.sha256(b'4\n9007199254740993\n').hexdigest(),
            signed_contract={'signatures': ['a', 'b']},
            signed_schema={'signatures': ['a', 'b']}, native_calls=[],
            peer_draws=[{'garbler_seed': 'synthetic', 'evaluator_seed': 'synthetic'}])

    def test_exact_integer_roundtrip(self):
        self.assertIs(REPLAY.validate_record({'recomputation': self.record}), self.record)
        self.assertEqual(self.record['exact_coordinates'][1], '9007199254740993')

    def test_tampering_and_missing_replay_material_rejected(self):
        for name, value in [('exact_coordinates', ['4', '9007199254740992']),
                            ('criterion_indices', [1]), ('peer_draws', []),
                            ('data_classification', 'production')]:
            with self.subTest(field=name):
                altered = copy.deepcopy(self.record)
                altered[name] = value
                with self.assertRaises(AssertionError):
                    REPLAY.validate_record(altered)


if __name__ == '__main__':
    unittest.main()
