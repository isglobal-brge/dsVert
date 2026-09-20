"""Freeze only our new GEE snapshot and install its detached continuation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

root = Path('/workspace/dsvert/gee-fixed-rho-r5')
archive = root.with_suffix('.tar.gz')
expected = '6c9a9ff03916819f17110866ae65df92a3e367cad2aa2128202506f5d4d3649e'
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert digest(archive) == expected, 'Incomplete or changed source archive'
root.mkdir(exist_ok=False)
with tarfile.open(archive) as source:
    source.extractall(root, filter='data')
logs = root / 'logs'
logs.mkdir()
prior = Path('/workspace/dsvert/gee-fixed-rho-dev-r3')
prior_manifest = json.loads((prior / 'frozen-source-manifest.json').read_text())
names = sorted(name for name in prior_manifest['sha256']
               if name.startswith('dsVert/inst/dsvert-mpc/') and
               (name.endswith('.go') or name.endswith(('/go.mod', '/go.sum'))))
assert len(names) == 614
for name in names:
    assert digest(root / name) == prior_manifest['sha256'][name] == digest(prior / name), name
actual = {str(p.relative_to(root)) for p in (root / 'dsVert/inst/dsvert-mpc').glob('*.go')}
assert actual == {name for name in names if name.endswith('.go')}
assert (prior / 'logs/gee-native-focused.exit').read_text().strip() == '0'
for relative in ('dsVert/inst/bin', 'dsVert/inst/cross-grid-v2/build'):
    copied = [p for p in (prior / relative).rglob('*') if p.is_file()]
    for path in copied:
        assert digest(path) == prior_manifest['sha256'][str(path.relative_to(prior))], str(path)
    shutil.copytree(prior / relative, root / relative, dirs_exist_ok=True)
    for path in copied:
        name = str(path.relative_to(prior))
        assert digest(root / name) == prior_manifest['sha256'][name], name
assert digest(prior / 'logs/structured-oracle.test') == prior_manifest['oracle_sha256']
shutil.copy2(prior / 'logs/structured-oracle.test', logs / 'structured-oracle.test')
assert digest(logs / 'structured-oracle.test') == prior_manifest['oracle_sha256']
(root / 'integrator-validation').symlink_to('dsVert/inst/cross-grid-v2/integrator-validation')
files = sorted(p for package in ('dsVert', 'dsVertClient') for p in (root / package).rglob('*') if p.is_file())
manifest = dict(repositories=json.loads((root / 'base-commits.json').read_text()),
                sha256={str(p.relative_to(root)): digest(p) for p in files},
                oracle_sha256=digest(logs / 'structured-oracle.test'),
                go_toolchain='go1.25.7', runtime_build_snapshot=str(prior),
                runtime_build_manifest_sha256=digest(prior / 'frozen-source-manifest.json'),
                matching_native_source_files=len(names), source_archive_sha256=expected)
(root / 'frozen-source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

# The paired suite's package code, tests, native inputs and certified runtimes
# are unchanged. Only the standalone GEE failure-reporting harness differs.
r4 = Path('/workspace/dsvert/gee-fixed-rho-r4')
old = json.loads((r4 / 'frozen-source-manifest.json').read_text())
select = lambda name: name.endswith(('.R', '.go', '/go.mod', '/go.sum')) or '/inst/certificates/' in name or '/inst/bin/' in name
selected = {name for name in manifest['sha256'] if select(name)}
assert selected == {name for name in old['sha256'] if select(name)}
changed = sorted(name for name in selected if manifest['sha256'][name] != old['sha256'][name])
assert changed == ['dsVert/inst/cross-grid-v2/integrator-validation/validate_structured_dslite.R'], changed
reuse = dict(paired_snapshot=str(r4), paired_manifest_sha256=digest(r4 / 'frozen-source-manifest.json'),
             current_manifest_sha256=digest(root / 'frozen-source-manifest.json'),
             matching_source_files=len(selected) - len(changed), changed_files=changed,
             reason='Only standalone GEE main/recovery failure diagnostics changed; package code, tests, native sources and runtimes unchanged',
             paired_pass=False, note='A final paired exit zero is required by the continuation before signed smokes or the campaign')
(logs / 'paired-source-reuse.json').write_text(json.dumps(reuse, indent=2) + '\n')
controller_source = Path('/workspace/dsvert/gee-fixed-rho-r5-continue.py')
controller = logs / 'continue-serial.py'
shutil.copy2(controller_source, controller)
env = dict(os.environ, GOMAXPROCS='2', GOMEMLIMIT='8GiB',
           R_LIBS_USER='/workspace/dsvert/gobase/R-library', OPENBLAS_NUM_THREADS='1',
           OMP_NUM_THREADS='1', NOT_CRAN='true', PROCESSX_NOTIFY_OLD_SIGCHLD='true')
with (logs / 'continuation-controller.log').open('x') as output:
    child = subprocess.Popen(['python3', str(controller)], cwd=root, env=env,
                             stdin=subprocess.DEVNULL, stdout=output,
                             stderr=subprocess.STDOUT, start_new_session=True)
launch = dict(pid=child.pid, stdin=os.readlink(f'/proc/{child.pid}/fd/0'),
              started_unix=time.time(), controller_sha256=digest(controller),
              source_manifest_sha256=digest(root / 'frozen-source-manifest.json'),
              repositories=manifest['repositories'])
(logs / 'continuation-launch.json').write_text(json.dumps(launch, indent=2) + '\n')
print(json.dumps(launch))
