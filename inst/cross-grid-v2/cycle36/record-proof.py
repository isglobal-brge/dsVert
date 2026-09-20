import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1];snap=out/'remote-r1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((snap/'source-manifest.json').read_text())
assert not [n for n,h in m['sha256'].items() if sha(snap/n)!=h]
assert not [n for n,h in m['sha256'].items() if sha(root/n)!=h]
files=sorted(out.glob('test-*.csv'));assert len(files)==9
rows=[row for f in files for row in csv.DictReader(f.open())]
assert all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in rows)
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')},tests=len(rows),assertions=sum(int(x['nb']) for x in rows),failures=0,errors=0,warnings=0,skips=0,frozen_source_files=len(m['sha256']),frozen_source_changed=[],final_source_differences=[],manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'],scope='Internal authenticated Cox remote-bind adapter, with upstream Synopsis context/cache and snapshot resolver test doubles, real signed Cox source/route checks, durable source store and native worker preparation for K2/K3/K5; shared LMM/GLMM/Synopsis regressions and current-native Gaussian fallback. No public Cox dispatch, complete DP release, capacity or promotion.',test_results={f.name:sha(f) for f in files},log_sha256=sha(out/'remote-r1.log'))
(out/'R_PROOF.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
