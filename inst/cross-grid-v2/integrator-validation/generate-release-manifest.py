#!/usr/bin/env python3
"""Separate heavy-family selection evidence from minimal fleet lifecycle proofs."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[4]
HARNESS_DIR = 'dsVert/inst/cross-grid-v2/integrator-validation'
CAPACITY = json.loads(Path(__file__).with_name('release-capacity.json').read_text())
FAMILIES = ('lmm', 'binomial_glmm', 'poisson_glmm', 'binomial_gee', 'poisson_gee', 'cox')
PENDING = {'binomial_gee': 'estimated-alpha contract and signed lifecycle',
           'poisson_gee': 'estimated-alpha contract and signed lifecycle'}


def rows_for(family):
    return 400 if family == 'cox' else 2000


def predictors_for(family):
    # Every pinned Cox owner must contribute a signed source column at K5.
    return 5 if family == 'cox' else 3


def command(family, epsilon, owners, instance, mode, expected=None):
    job = f'{family}-e{epsilon}-k{owners}-i{instance:02d}-{mode}'
    env = dict(GOMAXPROCS='2', GOMEMLIMIT='16GiB', OPENBLAS_NUM_THREADS='1',
        OMP_NUM_THREADS='1', NOT_CRAN='true', DSVERT_RELEASE_TTL_SECONDS='900',
        DSVERT_RELEASE_MAX_RUNTIME_SECONDS='604800', DSVERT_GRID_VALIDATION_N=str(rows_for(family)),
        DSVERT_GRID_VALIDATION_P=str(predictors_for(family)), DSVERT_GRID_VALIDATION_GRID='2',
        DSVERT_GRID_VALIDATION_EPSILON=str(epsilon), DSVERT_GRID_VALIDATION_OWNERS=str(owners),
        DSVERT_GRID_VALIDATION_INSTANCE=str(instance), DSVERT_GRID_VALIDATION_INSTANCE_COUNT='1',
        DSVERT_GRID_VALIDATION_REAL_COUNT='0' if mode == 'oracle' else '1',
        DSVERT_GRID_VALIDATION_ORACLE_ONLY='1' if mode == 'oracle' else '0',
        DSVERT_GRID_VALIDATION_COLD='1', DSVERT_GRID_VALIDATION_REPLAY_ONLY='0',
        DSVERT_GRID_VALIDATION_INTERRUPT='1' if mode == 'recovery' else '0',
        DSVERT_GRID_VALIDATION_KEEP_STATE='1', DSVERT_GRID_VALIDATION_PROGRESS='1',
        DSVERT_GRID_VALIDATION_STATE_PARENT=f'/var/lib/dsvert-release-jobs/{job}',
        DSVERT_GRID_VALIDATION_METRICS_PATH=f'logs/{job}.json')
    if expected:
        env['DSVERT_GRID_VALIDATION_EXPECTED_ORACLE_SHA256'] = expected
    return job, shlex.join(['env', *(f'{k}={v}' for k, v in env.items()),
        'Rscript', '--vanilla', f'{HARNESS_DIR}/validate_{family}_dslite.R', '.']) + ' </dev/null'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-records', type=Path,
        help='Directory of retained oracle-only metrics from this committed pair')
    parser.add_argument('--output', type=Path, default=ROOT / 'integrator-evidence')
    parser.add_argument('--family', choices=FAMILIES,
        help='Replace only this family\'s four release rows, preserving other fleet jobs')
    args = parser.parse_args()
    heads = {repo: subprocess.check_output(['git', '-C', str(ROOT / repo),
        'rev-parse', 'HEAD'], text=True).strip() for repo in ('dsVert', 'dsVertClient')}
    for repo in heads:
        subprocess.run(['git', '-C', str(ROOT / repo), 'diff', '--quiet', 'HEAD', '--'], check=True)
    records = {}
    if args.oracle_records:
        for path in sorted(args.oracle_records.glob('*.json')):
            record = json.loads(path.read_text())
            if record.get('oracle_only') is not True:
                continue
            assert record['source_commits'] == heads, f'Stale oracle record: {path}'
            assert (record['n'], record['p'], record['grid']) == (
                rows_for(record['family']), predictors_for(record['family']), 2), path
            digest = record['expected_oracle_sha256']
            assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest), path
            key = (record['family'], record['owners'], record['instance'])
            assert key not in records or records[key] == digest, f'Conflicting oracle: {path}'
            records[key] = digest
    real, selection = [], []
    for family in ((args.family,) if args.family else FAMILIES):
        harness = ROOT / HARNESS_DIR / f'validate_{family}_dslite.R'
        common = dict(family=family, n=rows_for(family), p=predictors_for(family), grid=2, source_commits=heads,
            harness_sha256=hashlib.sha256(harness.read_bytes()).hexdigest(),
            workdir='fresh isolated prepared workspace containing the committed pair',
            promoted=False)
        for epsilon in (1, 4, 8):
            for owners in (2, 3, 5):
                for instance in range(1, 21):
                    job, cli = command(family, epsilon, owners, instance, 'oracle')
                    selection.append(dict(common, job_id=job, epsilon=epsilon, K=owners,
                        instance=instance, cli=cli, real_authenticated_release_required=False,
                        ready=family not in PENDING, pending=PENDING.get(family)))
        for owners, mode in ((2, 'baseline'), (3, 'baseline'), (5, 'baseline'), (2, 'recovery')):
            digest = records.get((family, owners, 1))
            job, cli = command(family, 8, owners, 1, mode, digest)
            real.append(dict(common, job_id=job, epsilon=8, K=owners, instance=1,
                mode=mode, cli=cli, expected_oracle_sha256=digest,
                oracle_hash_scope='UTF-8 count then exact integer coordinates, LF terminated; excludes sticky noise',
                fleet_ready=family not in PENDING and digest is not None,
                pending=PENDING.get(family) or ('exact oracle commitment' if digest is None else None),
                execution_pool='dsvert-fleet', one_real_release_per_pod=True,
                real_authenticated_release_required=True, cold_replay_tamper_required=True,
                bilateral_and_unilateral_recovery_required=mode == 'recovery',
                capacity_measurement=owners == 2 and mode == 'baseline',
                capacity_bytes=CAPACITY['capacity_bytes'], capacity_seconds=CAPACITY['capacity_seconds'],
                capacity_promotion_gate=False))
    args.output.mkdir(parents=True, exist_ok=True)
    if args.family:
        assert len(real) == 4 and all(r['fleet_ready'] for r in real), 'Family readiness/oracle commitments missing'
        manifest = args.output / 'RELEASE_MANIFEST.jsonl'
        original = manifest.read_text().splitlines(keepends=True)
        replacements = {r['job_id']: json.dumps(r, separators=(',', ':')) + '\n' for r in real}
        retained = []
        for line in original:
            row = json.loads(line)
            if row['family'] == args.family:
                retained.append(replacements.pop(row['job_id']))
            else:
                retained.append(line)
        assert not replacements, 'Expected four existing family rows'
        manifest.write_text(''.join(retained))
        status_path = args.output / 'RELEASE_MANIFEST_STATUS.json'
        status = json.loads(status_path.read_text())
        status.setdefault('family_source_commits', {})[args.family] = heads
        status.setdefault('family_prepare_cli', {})[args.family] = shlex.join([
            'bash', f'{HARNESS_DIR}/prepare-release-workspace.sh', *heads.values()])
        status.setdefault('pending_families', {}).pop(args.family, None)
        status['fleet_ready'] = all(json.loads(line)['fleet_ready'] for line in retained)
        status['source_commit_scope'] = 'Each release row pins its own source pair; family updates preserve other rows byte-for-byte.'
        status_path.write_text(json.dumps(status, indent=2) + '\n')
        print(json.dumps({'family': args.family, 'ready_real_jobs': len(real),
            'other_release_rows_unchanged': len(original) - len(real)}))
        return
    for filename, rows in [('RELEASE_MANIFEST.jsonl', real), ('SELECTION_MANIFEST.jsonl', selection)]:
        (args.output / filename).write_text(''.join(json.dumps(r, separators=(',', ':')) + '\n' for r in rows))
    status = dict(source_commits=heads, real_job_count=len(real), oracle_job_count=len(selection),
        fleet_ready=all(r['fleet_ready'] for r in real),
        per_family_real_jobs=4, epsilon=8, lease_seconds=604800, idle_seconds=900,
        existing_frozen_runs='Harvest without restarting; do not launch duplicate active jobs.',
        capacity_scope='Once per family; measured serialized aggregate RPC bytes and complete release time.',
        paired_suite_cli="Rscript --vanilla -e 'testthat::test_local(\"dsVert\", stop_on_failure=TRUE); testthat::test_local(\"dsVertClient\", stop_on_failure=TRUE)' </dev/null",
        paired_suite_review='Retain structured results and review warnings/skips as well as failures.',
        prepare_cli=shlex.join(['bash', f'{HARNESS_DIR}/prepare-release-workspace.sh', *heads.values()]),
        pending_families=PENDING,
        proof_scope='Job definitions are not release evidence. Full selection matrix is ORACLE-ONLY.')
    (args.output / 'RELEASE_MANIFEST_STATUS.json').write_text(json.dumps(status, indent=2) + '\n')
    print(json.dumps({'real_jobs': len(real), 'oracle_jobs': len(selection),
        'ready_real_jobs': sum(r['fleet_ready'] for r in real)}))


if __name__ == '__main__':
    main()
