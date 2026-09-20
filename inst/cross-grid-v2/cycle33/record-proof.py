import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
checks={}
for name in ('baseline','fixed'):
 snap=out/name;m=json.loads((snap/'source-manifest.json').read_text())
 changed=[n for n,h in m['sha256'].items() if sha(snap/n)!=h]
 assert not changed
 checks[name]=dict(source_files=len(m['sha256']),frozen_source_changed=changed,manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'])
m=json.loads((out/'fixed/source-manifest.json').read_text())
diff=[n for n,h in m['sha256'].items() if sha(root/n)!=h]
assert set(diff)=={'dsVertClient/R/dp_cox_grid_cross.R','dsVertClient/man/dp_cox_grid.Rd'},diff
code=lambda p:'\n'.join(x for x in p.read_text().splitlines() if not x.startswith("#'"))
assert code(out/'fixed/dsVertClient/R/dp_cox_grid_cross.R')==code(root/'dsVertClient/R/dp_cox_grid_cross.R')
rows=[]
for f in sorted(out.glob('test*.csv')):rows.extend(csv.DictReader(f.open()))
assert len(rows)==16
assert all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in rows)
p=list(csv.DictReader((out/'preflight-tests.csv').open()))
assert len(p)==1 and p[0]['passed']=='10' and p[0]['failed']=='0' and p[0]['error']=='FALSE' and p[0]['skipped']=='FALSE' and p[0]['warning']=='0'
report=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,snapshots=checks,tests=len(rows),assertions=sum(int(x['nb']) for x in rows),failures=0,errors=0,warnings=0,skips=0,gaussian_preflight_assertions=10,baseline='New source-owner result regression errors on valid K3 with original implementation; baseline.log retained.',source_differences=diff,source_equivalence='Only roxygen wording and matching Rd documentation differ after the fixed snapshot. Executable R and all tests match committed source; server/native bytes identical.',scope='Internal Cox result processing with a fixture release provider. Real signed contracts K2/K3/K5; no authenticated DP-vector reader or real Cox release claim.',log_hashes={n:sha(out/n) for n in ('baseline.log','fixed.log','preflight.log')})
(out/'R_PROOF.json').write_text(json.dumps(report,indent=2)+'\n')
(out/'LMM_HARVEST.json').write_bytes((root/'integrator-evidence/cycle16-20260920/latest.json').read_bytes())
logs=root/'integrator-evidence/cycle21-20260920/simple-paired/harvest-partial-20260920T122041Z/logs'
paired=dict(capture=str(logs.relative_to(root)),verification=json.loads((logs/'paired-harvest-verification.json').read_text()),analysis=json.loads((logs/'paired-analysis.json').read_text()))
assert not paired['verification']['source_changed']
(out/'SIMPLE_PAIRED.json').write_text(json.dumps(paired,indent=2)+'\n')
print(json.dumps(report,indent=2))
