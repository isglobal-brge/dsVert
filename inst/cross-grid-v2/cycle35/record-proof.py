import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
checks={}
for name in ('hooks-r1','hooks-r2','hooks-r3'):
 snap=out/name;m=json.loads((snap/'source-manifest.json').read_text())
 changed=[n for n,h in m['sha256'].items() if sha(snap/n)!=h]
 assert not changed,changed
 checks[name]=dict(source_files=len(m['sha256']),frozen_source_changed=changed,manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'])
m=json.loads((out/'hooks-r3/source-manifest.json').read_text())
diff=[n for n,h in m['sha256'].items() if sha(root/n)!=h]
assert not diff,diff
previous=json.loads((out/'hooks-r2/source-manifest.json').read_text())
changed=[n for n,h in previous['sha256'].items() if sha(root/n)!=h]
assert changed==['dsVert/tests/testthat/test-dp-synopsis-exact-gc.R'],changed
for file in (out/'r3-results').glob('test-*.csv'):(out/file.name).write_bytes(file.read_bytes())
rows=[]
files=sorted(out.glob('test-*.csv'))
assert len(files)==9,len(files)
for f in files:rows.extend(csv.DictReader(f.open()))
assert all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in rows),[x for x in rows if x['failed']!='0' or x['error']!='FALSE']
report=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,snapshots=checks,tests=len(rows),assertions=sum(int(x['nb']) for x in rows),failures=0,errors=0,warnings=0,skips=0,source_differences=diff,source_equivalence='All final snapshot tracked source bytes equal committed source, including R/tests/native runtimes.',scope='Cox shared pre-START public binding and post-START durable injection, authenticated cold schema cache, validity guards, existing native Cox/transport and LMM/GLMM/shared Synopsis regressions. Synthetic release/compilation fixtures; no complete authenticated Cox DP release, recovery, capacity or promotion. Public admission/orchestration/certificate dispatch remain closed.',native_sampler_changed=False,iteration_note='r1/r2 exact-GC test double omitted the required returned stage digest and was correctly rejected. r3 repairs only that test double, retains a negative assertion, and reruns exact-GC plus native Gaussian preflight. All production bytes equal r2 and r3.',log_hashes={n:sha(out/n) for n in ('hooks-r1.log','hooks-r2.log','hooks-r3.log','cache-selected.log')},test_results={f.name:sha(f) for f in files})
(out/'R_PROOF.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
