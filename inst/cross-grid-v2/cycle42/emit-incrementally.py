import datetime,hashlib,json,shutil,subprocess,time
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1];base=out.parent
prior=out/'prior-manifests';prior.mkdir(exist_ok=True)
names=('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json')
for name in names:
 if not (prior/name).exists():shutil.copy2(base/name,prior/name)
previous=0
while previous<9:
 try:
  paths=list((out/'manifest/oracle-records').glob('*.json'))
  for p in paths:json.loads(p.read_text())
  count=len(paths)
  if count>previous:
   subprocess.run(['python3',str(root/'dsVert/inst/cross-grid-v2/integrator-validation/generate-release-manifest.py'),'--oracle-records',str(out/'manifest/oracle-records')],check=True)
   capture=out/f'manifest-incremental-{count:02d}';capture.mkdir()
   for name in names:shutil.copy2(base/name,capture/name)
   rows=[json.loads(x) for x in (base/names[0]).read_text().splitlines()]
   record=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),oracle_records=count,ready_jobs=[r['job_id'] for r in rows if r['fleet_ready']],source_commits=rows[0]['source_commits'],manifest_sha256=hashlib.sha256((base/names[0]).read_bytes()).hexdigest())
   (capture/'EMISSION.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True);previous=count
 except (json.JSONDecodeError,subprocess.CalledProcessError):pass
 if previous<9:time.sleep(2)
