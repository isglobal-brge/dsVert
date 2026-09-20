#!/usr/bin/env python3
"""Gate and run eight fixed-rho GEE proofs, at most two at once; never promote."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--oracle-records', type=Path, required=True,
                    help='Directory containing both precommitted n2000 oracle JSON records')
parser.add_argument('--native-evidence-root', type=Path,
                    help='Native focused-test snapshot; defaults to current snapshot')
parser.add_argument('--readiness-evidence-root', type=Path,
                    help='Focused R and successful n4 smoke snapshot; defaults to current snapshot')
args = parser.parse_args()
root = Path.cwd().resolve()
output = root / 'logs/gee-campaign'
output.mkdir(parents=True, exist_ok=False)
state = dict(status='checking_gates', promoted=False, root=str(root),
             maximum_concurrent_jobs=2, started_unix=time.time(), gates={}, jobs=[])


def save(event):
    (output / 'campaign.json').write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps(event), flush=True)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_manifest(directory):
    path = directory / 'frozen-source-manifest.json'
    return json.loads(path.read_text()), digest(path)


def require_exit(directory, name):
    path = directory / 'logs' / (name + '.exit')
    require(path.read_text().strip() == '0', 'Required successful proof: ' + str(path))
    return dict(path=str(path), sha256=digest(path), exit_code=0)


try:
    manifest, manifest_hash = read_manifest(root)
    state['source_manifest_sha256'] = manifest_hash
    native_root = (args.native_evidence_root or root).resolve()
    readiness_root = (args.readiness_evidence_root or root).resolve()
    native, native_hash = read_manifest(native_root)
    readiness, readiness_hash = read_manifest(readiness_root)
    native_prefix = 'dsVert/inst/dsvert-mpc/'
    native_names = {name for name in manifest['sha256']
                    if name.startswith(native_prefix) and
                    (name.endswith('.go') or name.endswith(('/go.mod', '/go.sum')))}
    actual_go = {str(path.relative_to(root)) for path in
                 (root / native_prefix).glob('*.go')}
    require(actual_go == {name for name in native_names if name.endswith('.go')},
            'Current native Go file set differs from its frozen manifest')
    prior_names = {name for name in native['sha256']
                   if name.startswith(native_prefix) and
                   (name.endswith('.go') or name.endswith(('/go.mod', '/go.sum')))}
    require(native_names and native_names == prior_names, 'Native evidence source set changed')
    for name in sorted(native_names):
        require(manifest['sha256'][name] == native['sha256'][name] == digest(root / name),
                'Native evidence source mismatch: ' + name)
    state['gates']['native'] = dict(require_exit(native_root, 'gee-native-focused'),
                                    source_manifest_sha256=native_hash,
                                    matching_source_files=len(native_names))
    readiness_names = {name for name in manifest['sha256'] if
                       name.endswith(('.R', '.go', '/go.mod', '/go.sum')) or
                       '/inst/certificates/' in name or '/inst/bin/' in name}
    prior_readiness_names = {name for name in readiness['sha256'] if
                            name.endswith(('.R', '.go', '/go.mod', '/go.sum')) or
                            '/inst/certificates/' in name or '/inst/bin/' in name}
    require(readiness_names == prior_readiness_names, 'R/smoke evidence source set changed')
    for name in sorted(readiness_names):
        require(manifest['sha256'][name] == readiness['sha256'][name] == digest(root / name),
                'R/smoke evidence source mismatch: ' + name)
    state['gates']['focused_r'] = dict(require_exit(readiness_root, 'gee-r-focused'),
                                       source_manifest_sha256=readiness_hash)
    families = ('binomial_gee', 'poisson_gee')
    for family in families:
        path = readiness_root / 'logs/gee-fixed-rho' / (
            family + '-n4-k2-exchangeable-rho0.25-baseline-resources.json')
        proof = json.loads(path.read_text())
        require(proof.get('proof_passed') is True and proof.get('exit_code') == 0 and
                proof.get('source_manifest_sha256') == readiness_hash,
                'Missing successful source-bound n4 smoke: ' + str(path))
        state['gates'][family + '_smoke'] = dict(path=str(path), sha256=digest(path))
    lane = root / 'dsVert/inst/cross-grid-v2/gee-fixed-rho'
    plan = output / 'release-plan.jsonl'
    command = [sys.executable, str(lane / 'generate-manifest.py'), '--root', str(root),
               '--oracle-records', str(args.oracle_records.resolve()),
               '--source-manifest', str(root / 'frozen-source-manifest.json'),
               '--output', str(plan)]
    with (output / 'oracle-gate.log').open('x') as log:
        checked = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT)
    require(checked.returncode == 0, 'Oracle commitment gate failed; see oracle-gate.log')
    rows = [json.loads(line) for line in plan.read_text().splitlines()]
    require(len(rows) == 8 and all(row['fleet_ready'] for row in rows), 'Incomplete release plan')
    state['gates']['oracle_commitments'] = dict(path=str(plan), sha256=digest(plan))
    state['status'] = 'running'
    save(dict(event='all_gates_passed', gates=state['gates']))

    # Both K2 baselines finish successfully before any larger-topology work.
    for owners, mode in ((2, 'baseline'), (3, 'baseline'), (5, 'baseline'), (2, 'recovery')):
        active = []
        for family in families:
            row = next(row for row in rows if
                       (row['family'], row['K'], row['mode']) == (family, owners, mode))
            command = [sys.executable, str(lane / 'run-release.py'), family, str(owners),
                       '--expected-oracle-sha256', row['expected_oracle_sha256']]
            if mode == 'recovery':
                command.append('--recovery')
            log = (output / (row['job_id'] + '.log')).open('x')
            child = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT)
            record = dict(job_id=row['job_id'], family=family, K=owners, mode=mode,
                          command=command, pid=child.pid, started_unix=time.time(),
                          exit_code=None, proof_passed=False, log=str(log.name))
            state['jobs'].append(record)
            active.append((child, log, record))
            save(dict(event='job_started', **record))
        while active:
            for child, log, record in list(active):
                code = child.poll()
                if code is None:
                    continue
                log.close()
                label = (record['family'] + '-n2000-k' + str(owners) +
                         '-exchangeable-rho0.25-' + mode)
                path = root / 'logs/gee-fixed-rho' / (label + '-resources.json')
                proof = json.loads(path.read_text()) if path.exists() else {}
                record.update(exit_code=code, finished_unix=time.time(),
                              resources=str(path), resources_sha256=digest(path) if path.exists() else None,
                              proof_passed=code == 0 and proof.get('proof_passed') is True and
                              proof.get('source_manifest_sha256') == manifest_hash)
                active.remove((child, log, record))
                save(dict(event='job_finished', **record))
            if active:
                time.sleep(1)
        require(all(job['proof_passed'] for job in state['jobs']),
                'Release proof failed; remaining jobs were not started')
    state['status'] = 'completed_proofs_pending_review'
    state['finished_unix'] = time.time()
    save(dict(event=state['status'], promoted=False))
except Exception as error:
    state['status'] = 'failed'
    state['error'] = str(error)
    state['finished_unix'] = time.time()
    save(dict(event='campaign_failed', error=str(error), promoted=False))
    sys.exit(1)
