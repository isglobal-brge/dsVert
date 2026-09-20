import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
changed=subprocess.check_output(['git','-C',str(root/'dsVert'),'diff-tree','--no-commit-id','--name-only','-r','391742c'],text=True).splitlines()
assert changed==['R/dpCapsuleManifestDS.R','R/dpCapsuleWorkload.R','tests/testthat/test-crossgrid-cox.R']
checks={}
for name in ('proof-r1','proof-r2','proof-r3'):
 snap=out/name;m=json.loads((snap/'source-manifest.json').read_text())
 assert all(sha(snap/n)==h for n,h in m['sha256'].items())
 differences=[n for n,h in m['sha256'].items() if sha(root/n)!=h]
 assert differences==([] if name=='proof-r3' else ['dsVert/tests/testthat/test-crossgrid-cox.R']),differences
 checks[name]=dict(files=len(m['sha256']),source_manifest_sha256=sha(snap/'source-manifest.json'),unchanged=True,final_differences=differences)
baseline=out/'baseline'
bm=json.loads((baseline/'source-manifest.json').read_text())
overlay={}
for n,h in bm['sha256'].items():
 if n in ('dsVert/R/dpCapsuleManifestDS.R','dsVert/R/dpCapsuleWorkload.R'):
  expected=subprocess.check_output(['git','-C',str(root/'dsVert'),'show','391742c^:'+n.split('/',1)[1]])
  assert (baseline/n).read_bytes()==expected
  overlay[n]=sha(baseline/n)
 else: assert sha(baseline/n)==h
checks['prior_code_control']=dict(source_overlay=overlay,other_files_unchanged=True,expected_rejection='A custodian Gaussian specification is not locally owned')
assert checks['prior_code_control']['expected_rejection'] in (out/'baseline.log').read_text()
load=lambda p:list(csv.DictReader(p.open()))
cox=load(out/'test-crossgrid-cox.R.csv')
assert len(cox)>1
new='Cox catalog preserves time/event ownership and its signed contract'
old=[r for r in cox if r['test']!=new]
rows=old+load(out/'catalog-r3/test-crossgrid-cox.R.csv')
for name in ('test-dp-glm-grid-cross-contract.R.csv','test-dp-capsule-manifest-bootstrap.R.csv','test-crossgrid-glmm-gaussian-preflight.R.csv'):
 rows+=load(out/name)
assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows)
# All unchanged tests and executable R files are byte-identical across snapshots.
a=(out/'proof-r1/dsVert/tests/testthat/test-crossgrid-cox.R').read_text().split('test_that("'+new)[0]
b=(out/'proof-r3/dsVert/tests/testthat/test-crossgrid-cox.R').read_text().split('test_that("'+new)[0]
assert a==b
proof=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,changed_files=changed,tests=len(rows),assertions=sum(int(r['nb']) for r in rows),failures=0,errors=0,warnings=0,skips=0,snapshots=checks,scope='Real Cox catalog parser/local custodian normalization/global raw-contract normalization and column resolution at K2/K3/K5, without catalog or schema test doubles in the new test. Existing Cox/native/durable, shared GLM/manifest and current-native Gaussian fallback regressions. Public Cox release admission remains explicitly closed. Not a complete Cox DP release or capacity proof.',assembly='Existing Cox tests and shared regressions from proof-r1; new catalog test from proof-r3 (51 assertions). Two earlier new-test runs failed due to incomplete scope fixture and noncanonical workload JSON; retained logs. The prior-code control rejects Cox at local ownership normalization. No production fix was needed after the initial patch.')
(out/'R_PROOF.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
