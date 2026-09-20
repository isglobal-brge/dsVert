import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
checks={}
for name in ('reader-r1','reader-r2'):
 snap=out/name;m=json.loads((snap/'source-manifest.json').read_text())
 changed=[n for n,h in m['sha256'].items() if sha(snap/n)!=h]
 assert not changed
 checks[name]=dict(source_files=len(m['sha256']),frozen_source_changed=changed,manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'])
m=json.loads((out/'reader-r2/source-manifest.json').read_text())
diff=[n for n,h in m['sha256'].items() if sha(root/n)!=h]
assert diff==['dsVertClient/STATUS_COX.md'],diff
rows=[]
for f in sorted(out.glob('test-*.csv')):rows.extend(csv.DictReader(f.open()))
assert len(rows)==16 and sum(int(x['nb']) for x in rows)==496
assert all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in rows)
p=list(csv.DictReader((out/'preflight-tests.csv').open()))
assert len(p)==1 and p[0]['passed']=='10' and p[0]['failed']=='0' and p[0]['error']=='FALSE' and p[0]['skipped']=='FALSE' and p[0]['warning']=='0'
report=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,snapshots=checks,tests=len(rows),assertions=sum(int(x['nb']) for x in rows),failures=0,errors=0,warnings=0,skips=0,gaussian_preflight_assertions=10,source_differences=diff,source_equivalence='All executable R/tests and native runtime bytes equal final committed source. Only client STATUS_COX.md changed after final snapshot.',scope='Internal Cox cold vector reader, assuming previously authenticated bundle/compilation. Real Ed25519 RELEASE/publication signatures and hashed bilateral REPLAY K2/K3/K5. Synthetic compilation/DP-vector fixtures, not real DP releases, native recovery or capacity proof; public compilation/orchestration/dispatch remain closed.',log_hashes={n:sha(out/n) for n in ('reader-r1.log','reader-r2.log','preflight.log')},tested_source_hashes={n:sha(root/n) for n in ('dsVertClient/R/dp_cox_grid_cross_release.R','dsVertClient/tests/testthat/test-dp-cox-cross-public-evidence.R')})
(out/'R_PROOF.json').write_text(json.dumps(report,indent=2)+'\n')
logs=sorted((root/'integrator-evidence/cycle21-20260920/simple-paired').glob('harvest-partial-*/logs'))[-1]
paired=dict(capture=str(logs.relative_to(root)),verification=json.loads((logs/'paired-harvest-verification.json').read_text()),analysis=json.loads((logs/'paired-analysis.json').read_text()))
assert not paired['verification']['source_changed']
(out/'SIMPLE_PAIRED.json').write_text(json.dumps(paired,indent=2)+'\n')
print(json.dumps(report,indent=2))
