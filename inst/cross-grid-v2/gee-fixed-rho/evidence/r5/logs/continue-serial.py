"""Run fresh focused R, wait for our earlier jobs, then prove GEE serially."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

root = Path.cwd().resolve()
assert root == Path('/workspace/dsvert/gee-fixed-rho-r5')
logs = root / 'logs'
lane = root / 'dsVert/inst/cross-grid-v2/gee-fixed-rho'
r4 = Path('/workspace/dsvert/gee-fixed-rho-r4')
manifest_path = root / 'frozen-source-manifest.json'
manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
state = dict(status='starting', promoted=False, started_unix=time.time(), steps=[],
             source_manifest_sha256=manifest_hash)
manifest = json.loads(manifest_path.read_text())

def save(status):
    state['status'] = status
    state['updated_unix'] = time.time()
    (logs / 'continuation-state.json').write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps(dict(status=status, time=state['updated_unix'])), flush=True)

def verify():
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == manifest_hash, 'Frozen manifest changed'
    for name, expected in manifest['sha256'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name

def run(name, command):
    verify()
    save('running_' + name)
    record = dict(name=name, command=command, started_unix=time.time())
    with (logs / (name + '.log')).open('x') as output:
        child = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=subprocess.STDOUT)
        record['pid'] = child.pid
        state['steps'].append(record)
        save('running_' + name)
        code = child.wait()
    record.update(exit_code=code, finished_unix=time.time())
    (logs / (name + '.exit')).write_text(str(code) + '\n')
    verify()
    save('finished_' + name)
    assert code == 0, name + ' failed; no remaining jobs launched'

def wait_for(path, pid, required_fragment):
    save('waiting_for_' + path.name)
    while not path.exists():
        proc = Path('/proc') / str(pid) / 'cmdline'
        assert proc.exists(), 'Earlier controller exited without result: ' + str(path)
        assert required_fragment.encode() in proc.read_bytes(), 'Earlier PID no longer identifies our job'
        time.sleep(30)
    state['steps'].append(dict(name='prior_result', path=str(path), exit_code=int(path.read_text())))

def wait_for_worker_exit(pid):
    save('waiting_for_prior_sampler_' + str(pid))
    proc = Path('/proc') / str(pid) / 'cmdline'
    while proc.exists():
        try:
            command = proc.read_bytes()
        except FileNotFoundError:
            break
        if not command:  # An exited zombie has released its sampler memory.
            break
        assert (str(r4 / 'dsVert/inst/bin/linux-amd64/dsvert-mpc').encode() +
                b'\x00exact-gc-worker\x00') in command, 'Prior sampler PID changed identity'
        time.sleep(30)
    state['steps'].append(dict(name='prior_sampler_exited', pid=pid))

status = 1
try:
    run('gee-r-focused', ['Rscript', '--vanilla', str(lane / 'run-focused.R'), str(root)])
    wait_for(r4 / 'logs/gee-fixed-rho/poisson_gee-n4-k2-exchangeable-rho0.25-baseline.exit',
             2390942, 'run-release.py')
    wait_for(r4 / 'logs/paired-driver.exit', 2390940, 'run-paired.py')
    for pid in (2496615, 2496655):
        wait_for_worker_exit(pid)
    assert (r4 / 'logs/paired-driver.exit').read_text().strip() == '0', 'Paired suite requires review before releases'
    for package in ('dsVert', 'dsVertClient'):
        assert (r4 / 'logs' / (package + '-paired.exit')).read_text().strip() == '0'
    reuse_path = logs / 'paired-source-reuse.json'
    reuse = json.loads(reuse_path.read_text())
    assert reuse['current_manifest_sha256'] == manifest_hash
    assert hashlib.sha256((r4 / 'frozen-source-manifest.json').read_bytes()).hexdigest() == reuse['paired_manifest_sha256'], 'Paired evidence manifest changed'
    reuse.update(paired_pass=True, final_driver_exit=0,
                 paired_results_sha256=hashlib.sha256((r4 / 'logs/paired-results.json').read_bytes()).hexdigest())
    reuse_path.write_text(json.dumps(reuse, indent=2) + '\n')
    commitments = {
        'binomial_gee': 'f4d286b8316e3d61e4dd3cb1d9fe02b5746cdaa390cec897bab7020a2cd52f54',
        'poisson_gee': 'b57466c45e0053949928414e98affb57ddb4804300137f23adc21bfbab622076',
    }
    for family, expected in commitments.items():
        run(family + '-n4-controller', ['python3', str(lane / 'run-release.py'), family,
            '2', '--n', '4', '--expected-oracle-sha256', expected])
    run('gee-campaign-controller', ['python3', str(lane / 'run-campaign.py'),
        '--oracle-records', '/workspace/dsvert/gee-oracle-20260920-r2',
        '--native-evidence-root', '/workspace/dsvert/gee-fixed-rho-dev-r3'])
    save('completed_proofs_pending_review')
    status = 0
except BaseException as error:
    state['error'] = str(error)
    traceback.print_exc()
    save('failed_no_remaining_jobs_launched')
finally:
    (logs / 'continuation.exit').write_text(str(status) + '\n')
sys.exit(status)
