import csv, datetime, hashlib, json, subprocess
from pathlib import Path
out=Path(__file__).resolve().parent; root=out.parents[1]; snap=out/'proof-r1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((snap/'source-manifest.json').read_text())
assert not [n for n,h in m['sha256'].items() if sha(snap/n)!=h]
assert not [n for n,h in m['sha256'].items() if sha(root/n)!=h]
baseline=out/'baseline-r1'; bm=json.loads((baseline/'source-manifest.json').read_text())
assert not [n for n,h in bm['sha256'].items() if sha(baseline/n)!=h]
old=list(csv.DictReader((baseline/'test-crossgrid-cox.R.csv').open()))
assert len(old)==1 and int(old[0]['failed'])>0
files=sorted(out.glob('test-*.csv')); assert len(files)==10
rows=[r for p in files for r in csv.DictReader(p.open())]
assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows)
proof=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), source_commits={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}, tests=len(rows), assertions=sum(int(r['nb']) for r in rows), failures=0, errors=0, warnings=0, skips=0, frozen_source_files=len(m['sha256']), frozen_source_changed=[],final_source_differences=[],manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'],baseline_reproduced=True,baseline_manifest_sha256=sha(baseline/'source-manifest.json'),scope='Cox shared source layout/contract equality and Synopsis namespace at K2/K3/K5, exported cold publication-evidence dispatch with real Cox signatures and durable terminal store. Upstream materializer/catalog, publication lookup, compilation decode and signed-schema lookup are test doubles in the new tests; no complete DP release, public catalog admission, capacity or promotion. Existing Cox private/native worker and GLM/LMM/shared source/Synopsis regressions included.',test_results={p.name:sha(p) for p in files},log_sha256={p.name:sha(p) for p in [out/'cox-r1.log',out/'shared.log',out/'source-regressions.log',out/'baseline.log']})
(out/'R_PROOF.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
