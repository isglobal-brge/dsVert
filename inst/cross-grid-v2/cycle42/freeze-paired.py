"""Archive committed sources into a new isolated pod snapshot; never overwrite."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
name = 'executor-cycle42-lmm-paired-r1'
repositories = {}
sha256 = {}
with tempfile.TemporaryDirectory(prefix='cycle42-freeze-') as temp:
    archive = Path(temp) / 'source.tar.gz'
    with tarfile.open(archive, 'w:gz') as combined:
        for package in ('dsVert', 'dsVertClient'):
            repo = root / package
            subprocess.run(['git', '-C', str(repo), 'diff', '--quiet', 'HEAD', '--'], check=True)
            commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
            repositories[package] = commit
            data = subprocess.check_output(['git', '-C', str(repo), 'archive', '--prefix=' + package + '/', commit])
            with tarfile.open(fileobj=io.BytesIO(data)) as source:
                for entry in source:
                    body = source.extractfile(entry) if entry.isfile() else None
                    if body is not None:
                        blob = body.read()
                        sha256[entry.name] = hashlib.sha256(blob).hexdigest()
                        body = io.BytesIO(blob)
                    combined.addfile(entry, body)
    manifest = dict(repositories=repositories, sha256=sha256)
    manifest_path = Path(temp) / 'initial-source-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run([str(root / 'pod4'), 'mkdir /workspace/dsvert/' + name], check=True)
    subprocess.run([str(root / 'pod4cp'), str(archive), str(manifest_path), 'pod:/workspace/dsvert/' + name + '/'], check=True)
remote = r'''
import datetime,hashlib,json,os,subprocess
from pathlib import Path
root=Path('/workspace/dsvert/executor-cycle42-lmm-paired-r1')
subprocess.run(['tar','-xzf','source.tar.gz'],cwd=root,check=True)
manifest=json.loads((root/'initial-source-manifest.json').read_text())
for name,digest in manifest['sha256'].items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,name
(root/'integrator-validation').symlink_to('dsVert/inst/cross-grid-v2/integrator-validation',target_is_directory=True)
(root/'logs').mkdir()
for line in (root/'dsVert/inst/bin/SHA256SUMS').read_text().splitlines():
    digest,name=line.split()
    assert hashlib.sha256((root/'dsVert/inst/bin'/name).read_bytes()).hexdigest()==digest,name
env=dict(os.environ,PATH='/usr/local/go/bin:'+os.environ['PATH'],GOMAXPROCS='2',R_LIBS_USER='/workspace/dsvert/gobase/R-library')
oracle=root/'dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test'
oracle.parent.mkdir(exist_ok=True)
with (root/'logs/oracle-build.log').open('x') as log:
    subprocess.run(['go','test','-c','-tags=grouped_reference_test,dsvert_cox_plaintext_test','-o',str(oracle),'.'],cwd=root/'dsVert/inst/dsvert-mpc',env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
import shutil
shutil.copy2(oracle,root/'logs/structured-oracle.test')
for path in (oracle,root/'logs/structured-oracle.test'):
    manifest['sha256'][str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
manifest.update(snapshot=str(root),frozen_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),transport_policy=dict(ttl_seconds=900,max_runtime_seconds=86400),capacity_gate=dict(bytes=256000000000,seconds=21600))
(root/'frozen-source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
command=['python3','-u','dsVert/inst/cross-grid-v2/cycle18/run-paired.py']
with (root/'logs/launch.log').open('x') as log:
    child=subprocess.Popen(command,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
record=dict(snapshot=str(root),pid=child.pid,stat=Path(f'/proc/{child.pid}/stat').read_text(),stdin=os.readlink(f'/proc/{child.pid}/fd/0'),command=command,repositories=manifest['repositories'],manifest_sha256=hashlib.sha256((root/'frozen-source-manifest.json').read_bytes()).hexdigest(),source_files=len(manifest['sha256']),promoted=False)
(root/'logs/launch.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
'''
result=subprocess.run([str(root/'pod4'),'python3 -'],input=remote,text=True,capture_output=True)
(out/'freeze.stdout').write_text(result.stdout)
(out/'freeze.stderr').write_text(result.stderr)
result.check_returncode()
(out/'launch.json').write_text(result.stdout)
print(result.stdout)
