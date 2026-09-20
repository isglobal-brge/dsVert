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

    def test_cox_scope_and_oracle_records_are_pair_bound(self):
        real, selection = self.generate()
        for row in real + selection:
            if row['family'] == 'cox':
                self.assertEqual((row['n'], row['p'], row['grid']), (400, 5, 2))
                self.assertIn('DSVERT_GRID_VALIDATION_N=400', row['cli'])
                self.assertIn('DSVERT_GRID_VALIDATION_P=5', row['cli'])
            else:
                self.assertEqual((row['n'], row['p'], row['grid']), (2000, 3, 2))
        record = dict(oracle_only=True, source_commits={'dsVert': 'a'*40, 'dsVertClient': 'a'*40},
            family='cox', n=400, p=5, grid=2, owners=2, instance=1, expected_oracle_sha256='b'*64)
        real, _ = self.generate(record)
        self.assertEqual([(r['K'], r['mode']) for r in real if r['fleet_ready']],
            [(2, 'baseline'), (2, 'recovery')])
        for n, p in ((2000, 5), (400, 3), (2000, 3)):
            with self.subTest(n=n, p=p), self.assertRaises(AssertionError):
                self.generate(dict(record, n=n, p=p))
        for repo in ('dsVert', 'dsVertClient'):
            stale = dict(record, source_commits=dict(record['source_commits'], **{repo: 'c'*40}))
            with self.subTest(repo=repo), self.assertRaisesRegex(AssertionError, 'Stale oracle record'):
                self.generate(stale)

    def test_cox_family_update_preserves_other_release_and_selection_bytes(self):
        real, _ = self.generate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harnesses = root / manifest.HARNESS_DIR
            harnesses.mkdir(parents=True)
            (harnesses / 'validate_cox_dslite.R').write_text('# Cox fixture\n')
            records = root / 'records'
            records.mkdir()
            heads = {'dsVert': 'a'*40, 'dsVertClient': 'a'*40}
            for owners in (2, 3, 5):
                record = dict(oracle_only=True, source_commits=heads, family='cox',
                    n=400, p=5, grid=2, owners=owners, instance=1,
                    expected_oracle_sha256=str(owners)*64)
                (records / f'k{owners}.json').write_text(json.dumps(record))
            out = root / 'out'
            out.mkdir()
            for row in real:
                row['source_commits'] = {'dsVert': 'd'*40, 'dsVertClient': 'e'*40}
                if row['family'] == 'cox':
                    row.update(n=2000, p=3, pending='old Cox lifecycle')
            # Noncanonical whitespace makes accidental decode/re-encode detectable.
            before = [('  ' + json.dumps(row) + ' \n').encode() for row in real]
            release_path = out / 'RELEASE_MANIFEST.jsonl'
            release_path.write_bytes(b''.join(before))
            selection_path = out / 'SELECTION_MANIFEST.jsonl'
            selection_bytes = b' {"family": "lmm", "selection": "untouched"}  \n'
            selection_path.write_bytes(selection_bytes)
            status_path = out / 'RELEASE_MANIFEST_STATUS.json'
            status_path.write_text(json.dumps(dict(pending_families={
                'cox': 'old Cox lifecycle', 'poisson_gee': 'unchanged pending'})))
            with patch.object(manifest, 'ROOT', root), patch('sys.argv', ['manifest',
                    '--output', str(out), '--oracle-records', str(records), '--family', 'cox']), \
                    patch.object(manifest.subprocess, 'check_output', return_value='a'*40), \
                    patch.object(manifest.subprocess, 'run'):
                manifest.main()
            after = release_path.read_bytes().splitlines(keepends=True)
            self.assertEqual(len(after), len(before))
            self.assertEqual(selection_path.read_bytes(), selection_bytes)
            updated = []
            for old, new in zip(before, after):
                if json.loads(old)['family'] != 'cox':
                    self.assertEqual(new, old)
                else:
                    self.assertNotEqual(new, old)
                    updated.append(json.loads(new))
            self.assertEqual([(r['K'], r['mode']) for r in updated],
                [(2, 'baseline'), (3, 'baseline'), (5, 'baseline'), (2, 'recovery')])
            for row in updated:
                self.assertTrue(row['fleet_ready'])
                self.assertEqual((row['n'], row['p'], row['grid'], row['epsilon']), (400, 5, 2, 8))
                self.assertEqual(row['source_commits'], heads)
                self.assertEqual(row['expected_oracle_sha256'], str(row['K'])*64)
                self.assertIn('DSVERT_GRID_VALIDATION_N=400', row['cli'])
                self.assertIn('DSVERT_GRID_VALIDATION_P=5', row['cli'])
                self.assertTrue(row['cli'].endswith(' </dev/null'))
            status = json.loads(status_path.read_text())
            self.assertEqual(status['family_source_commits']['cox'], heads)
            self.assertEqual(status['pending_families'], {'poisson_gee': 'unchanged pending'})


if __name__ == '__main__':
    unittest.main()
