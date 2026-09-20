import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1];snap=out/'remote-r4'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((snap/'source-manifest.json').read_text())
assert not [n for n,h in m['sha256'].items() if sha(snap/n)!=h]
assert not [n for n,h in m['sha256'].items() if sha(root/n)!=h]
prior=json.loads((out/'remote-r2/source-manifest.json').read_text())
prior_diff=[n for n,h in prior['sha256'].items() if sha(root/n)!=h]
assert prior_diff==['dsVert/tests/testthat/test-crossgrid-cox.R'],prior_diff
assert not [n for n,h in prior['sha256'].items() if sha(out/'remote-r2'/n)!=h]
files=sorted(out.glob('test-*.csv'));files += sorted(out.glob('client-test-*.csv')); assert len(files)==12
rows=[row for f in files for row in csv.DictReader(f.open())]
assert all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in rows)
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')},tests=len(rows),assertions=sum(int(x['nb']) for x in rows),failures=0,errors=0,warnings=0,skips=0,frozen_source_files=len(m['sha256']),frozen_source_changed=[],final_source_differences=[],manifest_sha256=sha(snap/'source-manifest.json'),base_commits=m['base_commits'],scope='Exported stage endpoint Cox bind routing-receipt handoff and shared prepare, with upstream Synopsis context/cache and snapshot resolver test doubles; real signed Cox source/route checks, durable source store and native worker preparation for K2/K3/K5. Client framing, shared GLM/LMM/GLMM/Synopsis regressions and current-native Gaussian fallback. No public catalog or client runner admission, complete DP release, capacity or promotion.',test_results={f.name:sha(f) for f in files},log_sha256={name:sha(out/name) for name in ('remote-r3.log','cox-endpoint-final.log','shared-final.log','endpoint-regressions.log','client-r2.log')})
prior3=json.loads((out/'remote-r3/source-manifest.json').read_text())
assert [n for n,h in prior3['sha256'].items() if sha(root/n)!=h]==['dsVert/tests/testthat/test-crossgrid-cox.R']
assert not [n for n,h in prior3['sha256'].items() if sha(out/'remote-r3'/n)!=h]
r['result_assembly']='RESULT_ASSEMBLY.json'
r['snapshot_scope']={'remote-r4':'Updated Cox endpoint test plus eight shared server files; all final source bytes match.', 'remote-r3':'Remaining Cox tests; final difference only canonical comparison assertions in the updated endpoint test, excluded from this snapshot result.', 'remote-r2':'Client framing and two existing endpoint regression files; all source bytes unchanged, final difference only Cox test response decoding/comparison, which these tests do not source.'}
r['superseded_attempts']='SUPERSEDED_ATTEMPTS.json'
(out/'R_PROOF.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
