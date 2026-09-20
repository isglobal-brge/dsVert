import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
heads={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}
def native(name):
 p=out/name; rows=[json.loads(line) for line in p.read_text().splitlines()]
 assert rows[-1]['Action']=='pass' and 'Test' not in rows[-1],name
 assert not any(r['Action'] in ('fail','skip') for r in rows),name
 return dict(log=name,sha256=hashlib.sha256(p.read_bytes()).hexdigest(),tests=[r['Test'] for r in rows if r['Action']=='pass' and r.get('Test') and '/' not in r['Test']],elapsed_seconds=rows[-1]['Elapsed'],equality_markers=[r['Output'].strip() for r in rows if 'opened_sha256=' in r.get('Output','')])
report=dict(source_commits=heads,baseline=native('baseline/native.jsonl'),patched=[native(x) for x in ('proof-r1/native.jsonl','proof-r2/outcome.jsonl','proof-r3/equality.jsonl','proof-r3/worker.jsonl','proof-r3/ml.jsonl')])
report['baseline_ml']=native('baseline/ml.jsonl')
report['patched_tests']=sum(len(x['tests']) for x in report['patched'])
report['scope']='Real two-authority native source/router/conversion/loss, recovery/cold/tamper and differential reconstructed routing/outcome equality. Not serialized-RPC capacity or full package paired suites.'
rproof=[]
for p in sorted((out/'r-tests').glob('*.csv')):
 rows=list(csv.DictReader(p.open()));assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows)
 rproof.append(dict(file=p.name,tests=len(rows),assertions=sum(int(r['nb']) for r in rows),sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
assert len(rproof)==6
report['r']=dict(files=rproof,tests=sum(r['tests'] for r in rproof),assertions=sum(r['assertions'] for r in rproof))
checks=[]
for name in ('baseline','proof-r1','proof-r2','proof-r3','release-r1'):
 snap=out/name;manifest=json.loads((snap/'source-manifest.json').read_text());mismatches=[p for p,h in manifest['sha256'].items() if hashlib.sha256((snap/p).read_bytes()).hexdigest()!=h];assert not mismatches,(name,mismatches)
 if name!='baseline':
  production=[p for p in manifest['sha256'] if p.startswith('dsVert/inst/dsvert-mpc/') and (p.endswith('.go') and not p.endswith('_test.go') or p.endswith(('go.mod','go.sum')))]
  assert all(manifest['sha256'][p]==hashlib.sha256((root/p).read_bytes()).hexdigest() for p in production),name
 checks.append(dict(snapshot=name,source_files=len(manifest['sha256']),mismatches=mismatches,manifest_sha256=hashlib.sha256((snap/'source-manifest.json').read_bytes()).hexdigest()))
baseline=out/'baseline/dsVert/inst/dsvert-mpc'
gee=list(baseline.glob('k2_exact_gc_gee_*'))
assert all(p.read_bytes()==(root/'dsVert/inst/dsvert-mpc'/p.name).read_bytes() for p in gee)
assert (out/'baseline/dsVert/R/crossgrid_grouped.R').read_bytes()==(root/'dsVert/R/crossgrid_grouped.R').read_bytes()
report['gee_owned_files_unchanged']=len(gee)+1
report['snapshots']=checks
report['runtime_build']=json.loads((out/'BUILD.json').read_text())
report['observed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(out/'PROOF.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('source_commits','patched_tests','gee_owned_files_unchanged','observed_utc')},indent=2))
