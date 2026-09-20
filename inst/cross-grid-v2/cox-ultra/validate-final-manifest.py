"""Read-only Cox release-manifest and retained proof audit."""
from pathlib import Path
import hashlib
import json
import shlex

base = Path('integrator-evidence')
evidence = base / 'cox-ultra'
pair = {'dsVert': 'c97cd193c06dbae695792b4a03644c05fa733f8f',
        'dsVertClient': '28be3cd6fea312d8f1c2442c810b453ad81080ce'}
oracle = 'ba5d77ddffabca8ce5b9be5f516aee3662b90b6e44a2ef0bfb886da6c8bb950d'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


old = (evidence / 'prior-manifests/RELEASE_MANIFEST.jsonl').read_bytes().splitlines(keepends=True)
new = (base / 'RELEASE_MANIFEST.jsonl').read_bytes().splitlines(keepends=True)
other = lambda rows: [line for line in rows if json.loads(line)['family'] != 'cox']
assert other(old) == other(new) and len(other(new)) == 20
rows = [json.loads(line) for line in new if json.loads(line)['family'] == 'cox']
assert len(rows) == 4
assert {(r['K'], r['mode']) for r in rows} == {(2, 'baseline'), (3, 'baseline'), (5, 'baseline'), (2, 'recovery')}
for row in rows:
    assert (row['n'], row['p'], row['grid'], row['epsilon']) == (400, 5, 2, 8)
    assert row['source_commits'] == pair
    assert row['fleet_ready'] is True and row['promoted'] is False and row['pending'] is None
    assert row['capacity_bytes'] == 256000000000 and row['capacity_seconds'] == 28800
    assert row['expected_oracle_sha256'] == oracle
    bound = json.loads((evidence / f"oracles-bound/cox-k{row['K']}.json").read_text())
    assert bound['source_commits'] == pair and bound['expected_oracle_sha256'] == oracle
    assert row['cli'].endswith('</dev/null')
    args = dict(token.split('=', 1) for token in shlex.split(row['cli']) if '=' in token)
    assert args['DSVERT_GRID_VALIDATION_INTERRUPT'] == str(int(row['mode'] == 'recovery'))
    assert args['DSVERT_GRID_VALIDATION_COLD'] == '1' and args['DSVERT_GRID_VALIDATION_ORACLE_ONLY'] == '0'
    assert args['DSVERT_GRID_VALIDATION_OWNERS'] == str(row['K']) and args['DSVERT_GRID_VALIDATION_N'] == '400'
    assert row['harness_sha256'] == sha(Path('dsVert/inst/cross-grid-v2/integrator-validation/validate_cox_dslite.R'))

proofs = []
for name in ['proof-r3', 'proof-r4-recovery']:
    path = evidence / name / 'logs'
    log = (path / 'proof.log').read_text()
    metrics = json.loads((path / 'metrics.json').read_text())
    assert json.loads((path / 'exit.json').read_text())['exit_code'] == 0
    for marker in ['DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED cox',
                   'DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED',
                   'DSLITE_COX_COLD_EXPORTED_API_EQUAL_AUTHENTICATED']:
        assert marker in log
    assert metrics['loss_gap'] == 0 and metrics['oracle_only'] is False and metrics['n'] == 4
    proofs.append({'path': str(path), 'exit_code': 0,
                   'metrics_sha256': sha(path / 'metrics.json'), 'log_sha256': sha(path / 'proof.log'),
                   'end_to_end_release_elapsed': metrics['end_to_end_release_elapsed'],
                   'end_to_end_serialized_rpc_bytes': metrics['end_to_end_serialized_rpc_bytes'],
                   'certificate_sha256': metrics['certificate_sha256']})
log = (evidence / 'proof-r4-recovery/logs/proof.log').read_text()
boundaries = ['prepared', 'bilateral_prepare', 'unilateral_commit', 'committed', 'unilateral']
for boundary in boundaries:
    assert f'DSLITE_COX_RECOVERY_BOUNDARY {boundary} OBSERVED' in log
assert 'DSLITE_COX_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED' in log
report = {
    'source_commits': pair, 'release_rows': len(new), 'cox_ready_rows': len(rows),
    'job_ids': [r['job_id'] for r in rows], 'other_release_rows_preserved_byte_for_byte': 20,
    'release_manifest_sha256': sha(base / 'RELEASE_MANIFEST.jsonl'),
    'prior_release_manifest_sha256': sha(evidence / 'prior-manifests/RELEASE_MANIFEST.jsonl'),
    'status_sha256': sha(base / 'RELEASE_MANIFEST_STATUS.json'),
    'selection_manifest_current_sha256': sha(base / 'SELECTION_MANIFEST.jsonl'),
    'expected_oracle_sha256': oracle, 'fixture': {'n': 400, 'p': 5, 'grid': 2, 'epsilon': 8},
    'runtime_enabled': True,
    'runtime_evidence': 'server and client authenticated Cox artifacts; focused contract/admission tests and two actual signed releases',
    'small_signed_proofs': proofs, 'recovery_boundaries': boundaries,
    'proof_source_binding': 'SOURCE_PROOF_EQUIVALENCE.json',
    'oracle_source_binding': 'ORACLE_SOURCE_EQUIVALENCE.json',
    'heavy_fleet_jobs_launched': 0, 'capacity_proven': False, 'promoted': False,
}
(evidence / 'MANIFEST_VALIDATION.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'validated': True, 'cox_rows': len(rows), 'other_rows_preserved': 20,
                  'small_proofs_green': len(proofs), 'release_manifest_sha256': report['release_manifest_sha256']}))
