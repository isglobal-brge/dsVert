"""Read-only observations of cycle42 smoke/paired work; never restart or promote."""
import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
smoke=out/'release-r1';log=smoke/'logs/lmm-smoke.log';text=log.read_text(errors='replace')
markers=['DSLITE_LMM_RECOVERY_BOUNDARY '+mode+' OBSERVED' for mode in ('prepared','bilateral_prepare','unilateral_commit','committed','unilateral')]+['DSLITE_LMM_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED','DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED lmm','DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED','DSLITE_LMM_COLD_EXPORTED_API_EQUAL_AUTHENTICATED']
manifest=json.loads((smoke/'frozen-source-manifest.json').read_text())
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),launch=json.loads((smoke/'logs/launch.json').read_text()),markers={m:m in text for m in markers},exit_code=int((smoke/'logs/lmm-smoke.exit').read_text()) if (smoke/'logs/lmm-smoke.exit').exists() else None,log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),log_bytes=log.stat().st_size,source_files=len(manifest['sha256']),source_mismatches=[n for n,h in manifest['sha256'].items() if hashlib.sha256((smoke/n).read_bytes()).hexdigest()!=h],metrics=json.loads((smoke/'logs/lmm-smoke.json').read_text()) if (smoke/'logs/lmm-smoke.json').exists() else None,scope='n4/K2 precommit frozen-source smoke. Native and R executable sources match 7ff811c/55f4793; historical base identity in source-manifest.json is not the tested runtime identity. No n2000 capacity claim.')
assert not r['source_mismatches']
(out/'SMOKE_CURRENT.json').write_text(json.dumps(r,indent=2)+'\n')
remote=r'''import datetime,hashlib,json,os
from pathlib import Path
root=Path('/workspace/dsvert/executor-cycle42-lmm-paired-r1')
manifest=json.loads((root/'frozen-source-manifest.json').read_text());launch=json.loads((root/'logs/launch.json').read_text());proc=Path('/proc')/str(launch['pid'])
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=manifest['repositories'],launch=launch,source_files=len(manifest['sha256']),source_mismatches=[n for n,h in manifest['sha256'].items() if hashlib.sha256((root/n).read_bytes()).hexdigest()!=h],files={})
if proc.exists():
 try:r['controller']=dict(command=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(),stat=(proc/'stat').read_text(),stdin=os.readlink(proc/'fd/0'))
 except OSError:pass
for p in (root/'logs').iterdir():
 if p.suffix in ('.exit','.json') or p.name in ('launch.log','dsVert-paired.log','dsVertClient-paired.log'):
  blob=p.read_bytes();r['files'][p.name]=dict(sha256=hashlib.sha256(blob).hexdigest(),bytes=len(blob),text=blob.decode(errors='replace')[-20000:])
print(json.dumps(r))'''
p=subprocess.run([str(root/'pod4'),'python3 -'],input=remote,text=True,capture_output=True,check=True);paired=json.loads(p.stdout);assert not paired['source_mismatches'];(out/'PAIRED_CURRENT.json').write_text(json.dumps(paired,indent=2)+'\n')
print(json.dumps(dict(smoke_exit=r['exit_code'],smoke_markers=r['markers'],paired_exits={n:v['text'] for n,v in paired['files'].items() if n.endswith('.exit')},paired_source_files=paired['source_files']),indent=2))
