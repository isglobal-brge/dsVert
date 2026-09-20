#!/usr/bin/env python3
"""Audit retained Cox oracle bytes; bind copies only after both trees are clean."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
TRANSPORT = 'dsVertClient/R/exact_gc_transport.R'
OLD_TRANSPORT = '120ba2dee374ba9e8fb24c282685c9763f07b294ebfaffdd57bbd4a3ebbfaa3c'
NEW_TRANSPORT = '5d4051d36028fd4a16fe2f6797cbf7c86cb41b470742829ceb8342766d4611fd'
RATIONALE = (
    'The sole production difference for K2/K3 adds cox-loss-staged-v1 to the '
    'client exact-run operation/output allowlists and validates its ring, scale '
    'and purpose. ORACLE_ONLY=1 and REAL_COUNT=0 bypass invoke() and the Cox '
    'staged executor. PSI uses the unchanged existing operations. '
    'grid_oracle_noise(..., synthetic_staged=TRUE) compiles the signed noise '
    'plan without invoking the Cox exact runner. The independent integer '
    'risk-set oracle, profile, sampler oracle, harness and all remaining '
    'production dependencies are byte-identical. This is source-equivalence '
    'attribution of retained results, not recomputation on the target commits.'
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(ROOT / repo), *args], text=True).strip()


def dependency(path):
    relative = path.split('/', 1)[1]
    if relative == 'inst/cross-grid-v2/integrator-validation/test_release_manifest.py':
        return False  # Manifest-generator regression; never loaded by the oracle harness.
    return (relative in ('DESCRIPTION', 'NAMESPACE') or
            relative.startswith(('R/', 'src/', 'inst/')) or
            relative.startswith('tests/testthat/helper'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-only', action='store_true',
                        help='Record current-byte audit; permit dirty HEADs; do not create bound copies')
    args = parser.parse_args()
    summary_path = OUT / 'ORACLE_SUMMARY.json'
    summary = json.loads(summary_path.read_text())
    heads = {repo: git(repo, 'rev-parse', 'HEAD') for repo in ('dsVert', 'dsVertClient')}
    tracked = {f'{repo}/{name}' for repo in heads
               for name in git(repo, 'ls-files').splitlines()}
    dirty = {repo: git(repo, 'diff', '--name-only', 'HEAD', '--').splitlines() for repo in heads}
    untracked = {repo: [name for name in git(repo, 'ls-files', '--others', '--exclude-standard').splitlines()
                       if '/__pycache__/' not in name and dependency(f'{repo}/{name}')]
                 for repo in heads}
    clean = not any(dirty.values()) and not any(untracked.values())
    if not args.audit_only and not clean:
        raise SystemExit(f'Refusing committed-pair binding with dirty source: {dirty}; {untracked}')
    destination = OUT / 'oracles-bound'
    if not args.audit_only and destination.exists():
        raise SystemExit(f'Refusing to overwrite retained bound records: {destination}')
    current = {path: sha(ROOT / path) for path in sorted(tracked) if dependency(path)}
    audits = []
    for row in summary['rows']:
        snapshot = ROOT / row['snapshot']
        manifest_path = snapshot / 'source-manifest.json'
        assert sha(manifest_path) == row['snapshot_source_manifest_sha256'], snapshot
        manifest = json.loads(manifest_path.read_text())
        original = manifest['sha256']
        metrics_path = ROOT / row['metrics']
        assert sha(metrics_path) == row['metrics_sha256'], metrics_path
        assert sha(ROOT / row['log']) == row['log_sha256'], row['log']
        assert json.loads((snapshot / 'logs/exit.json').read_text())['exit_code'] == 0
        binary = snapshot / 'dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test'
        assert sha(binary) == row['oracle_binary_sha256'], binary
        differences = []
        scope = sorted(set(current) | {path for path in original if dependency(path)})
        for path in scope:
            old, new = original.get(path), current.get(path)
            if old is not None:
                assert sha(snapshot / path) == old, f'Snapshot changed: {snapshot}/{path}'
            if old == new:
                continue
            assert (row['owners'] in (2, 3) and path == TRANSPORT and
                    old == OLD_TRANSPORT and new == NEW_TRANSPORT), f'Unaudited dependency change: {path}'
            differences.append(dict(path=path, executed_sha256=old, target_sha256=new,
                                    rationale=RATIONALE))
        metrics = json.loads(metrics_path.read_text())
        assert metrics['oracle_only'] is True and metrics['real_authenticated_release'] is False
        assert metrics['expected_oracle_sha256'] == summary['expected_oracle_sha256']
        audits.append(dict(owners=row['owners'], snapshot=row['snapshot'],
            original_metrics=row['metrics'], original_metrics_sha256=row['metrics_sha256'],
            original_log=row['log'], original_log_sha256=row['log_sha256'],
            original_base_commits=row['snapshot_base_commits'],
            snapshot_source_manifest_sha256=row['snapshot_source_manifest_sha256'],
            oracle_binary_sha256=row['oracle_binary_sha256'], checked_dependency_count=len(scope),
            differences=differences, executed_named_dependencies=row['code_dependencies_sha256']))
    audit = dict(version='cox-oracle-source-equivalence-v1',
        audited_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        mode='current-byte-audit-only' if args.audit_only else 'clean-committed-pair-binding',
        target_commits=heads, target_source_clean=clean, dirty_tracked=dirty,
        untracked_source=untracked, original_summary_sha256=sha(summary_path),
        scope='All tracked package R/src/inst bytes, DESCRIPTION, NAMESPACE and test helpers, excluding the never-invoked test_release_manifest.py generator regression; original snapshots rehashed.',
        claim=RATIONALE, target_dependency_sha256=current, rows=audits,
        recomputation_performed=False, original_metrics_modified=False,
        release_manifest_modified=False)
    audit_path = OUT / ('ORACLE_SOURCE_EQUIVALENCE_DRAFT.json' if args.audit_only else
                        'ORACLE_SOURCE_EQUIVALENCE.json')
    if not args.audit_only:
        for repo, commit in heads.items():
            assert git(repo, 'rev-parse', 'HEAD') == commit, 'HEAD changed during audit'
            assert not git(repo, 'diff', '--name-only', 'HEAD', '--'), 'Source changed during audit'
    audit_path.write_text(json.dumps(audit, indent=2) + '\n')
    if not args.audit_only:
        destination.mkdir(exist_ok=False)
        for row in audits:
            metrics = json.loads((ROOT / row['original_metrics']).read_text())
            metrics['original_source_commits'] = metrics['source_commits']
            metrics['source_commits'] = heads
            metrics['source_attribution'] = dict(method='retained_oracle_source_equivalence',
                original_metrics=row['original_metrics'], original_sha256=row['original_metrics_sha256'],
                audit=str(audit_path.relative_to(ROOT)), audit_sha256=sha(audit_path),
                recomputed=False)
            (destination / f'cox-k{row["owners"]}.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(dict(audit=str(audit_path.relative_to(ROOT)), clean=clean,
        target_commits=heads, topologies=[row['owners'] for row in audits],
        copies_created=0 if args.audit_only else len(audits))))


if __name__ == '__main__':
    main()
