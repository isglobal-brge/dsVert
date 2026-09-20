"""Campaign regression checks: never expand the selection matrix into real jobs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manifest', Path(__file__).with_name('generate-release-manifest.py'))
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


class ManifestTests(unittest.TestCase):
    def generate(self, record=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harnesses = root / manifest.HARNESS_DIR
            harnesses.mkdir(parents=True)
            for family in manifest.FAMILIES:
                (harnesses / f'validate_{family}_dslite.R').write_text('# fixture\n')
            records = root / 'records'
            records.mkdir()
            if record:
                (records / 'record.json').write_text(json.dumps(record))
            out = root / 'out'
            with patch.object(manifest, 'ROOT', root), patch('sys.argv', ['manifest',
                    '--output', str(out), '--oracle-records', str(records)]), \
                    patch.object(manifest.subprocess, 'check_output', return_value='a' * 40), \
                    patch.object(manifest.subprocess, 'run'):
                manifest.main()
            return [[json.loads(line) for line in (out / name).read_text().splitlines()]
                for name in ('RELEASE_MANIFEST.jsonl', 'SELECTION_MANIFEST.jsonl')]

    def test_minimal_real_and_oracle_matrix(self):
        real, selection = self.generate()
        self.assertEqual(len(real), 24)
        self.assertEqual(len(selection), 1080)
        self.assertTrue(all(row['epsilon'] == 8 for row in real))
        self.assertTrue(all('DSVERT_GRID_VALIDATION_ORACLE_ONLY=0' in row['cli'] for row in real))
        self.assertTrue(all('DSVERT_GRID_VALIDATION_ORACLE_ONLY=1' in row['cli'] for row in selection))
        self.assertTrue(all('DSVERT_GRID_VALIDATION_REAL_COUNT=0' in row['cli'] for row in selection))
        self.assertFalse(any(row['fleet_ready'] for row in real))
        for family in manifest.FAMILIES:
            rows = [row for row in real if row['family'] == family]
            self.assertEqual([(r['K'], r['mode']) for r in rows],
                [(2, 'baseline'), (3, 'baseline'), (5, 'baseline'), (2, 'recovery')])
            self.assertEqual(sum(row['capacity_measurement'] for row in rows), 1)
            self.assertTrue(all('DSVERT_RELEASE_TTL_SECONDS=900' in r['cli'] and
                'DSVERT_RELEASE_MAX_RUNTIME_SECONDS=86400' in r['cli'] for r in rows))

    def test_hashes_are_pair_bound_and_enable_only_matching_jobs(self):
        record = dict(oracle_only=True, source_commits={'dsVert': 'a'*40, 'dsVertClient': 'a'*40},
            family='lmm', n=2000, p=3, grid=2, owners=2, instance=1, expected_oracle_sha256='b'*64)
        real, _ = self.generate(record)
        self.assertEqual(sum(r['fleet_ready'] for r in real), 2)
        for row in real:
            if row['fleet_ready']:
                self.assertIn('DSVERT_GRID_VALIDATION_EXPECTED_ORACLE_SHA256=' + 'b'*64, row['cli'])
        record['source_commits']['dsVert'] = 'c'*40
        with self.assertRaisesRegex(AssertionError, 'Stale oracle record'):
            self.generate(record)


if __name__ == '__main__':
    unittest.main()
