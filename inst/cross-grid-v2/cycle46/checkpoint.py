import csv,datetime,hashlib,json,re,shutil,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
last='Cox workload admission authenticates schema and accounts for signed sensitivity'
suites=[]
for p in sorted(out.glob('test*.csv')):
 rows=list(csv.DictReader(p.open()))
 if p.name=='test-crossgrid-cox.R.csv':
  superseded=[r for r in rows if r['test']==last]
  assert len(superseded)==1 and superseded[0]['failed']=='3' and superseded[0]['error']=='FALSE',superseded
  rows=[r for r in rows if r['test']!=last]
 assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows),p
 suites.append(dict(file=p.name,tests=len(rows),assertions=sum(int(r['passed']) for r in rows),snapshot='proof-r1' if p.name in ('test-crossgrid-cox.R.csv','test-dp-glm-grid-cross-contract.R.csv') else 'proof-r3'))
assert 'Test passed with 82 successes' in (out/'admission-frozen-final.log').read_text()
suites.append(dict(file='admission-frozen-final.log',tests=1,assertions=82,snapshot='proof-r3'))
manifests={}
for snap in ('proof-r1','proof-r2','proof-r3'):
 m=json.loads((out/snap/'source-manifest.json').read_text())
 assert all(hashlib.sha256((out/snap/p).read_bytes()).hexdigest()==h for p,h in m['sha256'].items()),snap
 manifests[snap]=m
changed_snapshots=[p for p,h in manifests['proof-r1']['sha256'].items() if manifests['proof-r3']['sha256'].get(p)!=h]
assert changed_snapshots==['dsVert/tests/testthat/test-crossgrid-cox.R'],changed_snapshots
changed=subprocess.check_output(['git','-C',str(root/'dsVert'),'diff','--name-only','37eb462','HEAD'],text=True).splitlines()
assert set(changed)=={'R/dpCapsuleWorkload.R','R/dpGLMGridCrossProfile.R','tests/testthat/test-crossgrid-cox.R'}
assert all(hashlib.sha256((root/'dsVert'/p).read_bytes()).hexdigest()==manifests['proof-r3']['sha256']['dsVert/'+p] for p in changed)
assert all(r['source_commits']==heads for r in [json.loads(p.read_text()) for p in (out/'manifest/oracle-records').glob('*.json')])
oracles=json.loads((out/'manifest/ORACLE_VALIDATION.json').read_text());assert oracles['records']==9 and oracles['all_equal_previous_exact']
proof=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),execution_source_commits=heads,suites=suites,tests=sum(x['tests'] for x in suites),assertions=sum(x['assertions'] for x in suites),final_nonpasses=0,snapshots={k:len(v['sha256']) for k,v in manifests.items()},source_mismatches=[],changed_file_sha256={p:manifests['proof-r3']['sha256']['dsVert/'+p] for p in changed},scope='Real signed K2/K3/K5 workload -> canonical manifest -> release lattice -> source transport contract -> authenticated Cox context; no schema/catalog/source-contract doubles. Existing broader source/executor/client tests retain their original doubles. No actual Cox DP release, native recovery or capacity claim.',superseded='Initial fixture used epsilon8 twice and failed lifetime composition. Corrected fixture in proof-r1 rejects re-signed conflicting schema at the earlier local-bound check, producing 3 assertion-class failures. All prior tests in that snapshot pass. Proof-r3 corrects the expected error, adds 6 real source-contract/context assertions and passes all82. All executable files and other tests are identical across snapshots; raw first failures retained.')
(out/'PROOF.json').write_text(json.dumps(proof,indent=2)+'\n')
(out/'SOURCE_HASHES.json').write_text(json.dumps(manifests,indent=2)+'\n')
resume=f'''# Cycle46 checkpoint — 2026-09-20

Execution source **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. The later server
checkpoint is evidence/documentation only; MANIFEST_VALIDATION.json records the
final committed manifest pair. **4/10 promoted**, unchanged at f3795a2/e748f05.
NB remains resolved. Uniform admitted release envelope: **256 GB / 8 h**.

Cox server workload admission now verifies the complete signed schema/contract,
uses its existing artifact projection, and accumulates signed raw/natural L1/L2
sensitivities through the shared grid branch. The full workload manifest round-
trips canonically; release coordinates use exact signed maxima without a second
lattice shift. The actual source contract and authenticated Cox source context
agree on the private padded layout at K2/K3/K5; no catalog/schema/source-contract
doubles in the new test. Owner-local times stay private. N<=400 remains enforced.

**{proof['tests']} tests / {proof['assertions']:,} assertions PASS**, zero final nonpasses.
The new test passes82 assertions in immutable proof-r3. Existing server regression
proof is from proof-r1; client regressions are from proof-r3. Executable sources
and all other tests are identical. Earlier lifetime-policy and expected-error-
class fixture failures are retained, explicitly superseded in PROOF.json.
All three snapshots rehash exactly. No new native or packaged runtime changes.

**Cox is not fleet-ready.** Runtime states and public support remain disabled.
Publication/certificate/public-reader integration and signed small source-to-
native-to-DP lifecycle proof remain pending. See NEXT_COX.md for exact sites,
including the need to exclude Cox from legacy GLM injection when enabling generic
server discovery. No real Cox release, recovery/capacity claim or promotion.

Fleet remains **10 running / 2 terminal** at the fresh observation. Original-pair
retained results remain **1 PASS / 1 FAIL**, already re-scored against8h. No rerun,
source reattribution or new heavy promotion. Measured capacity is unchanged from
cycle43. Deferred-batching paired suite remains incomplete; all3025 frozen files
match. Its separate small smoke remains PASS on its own runtime. Frozen jobs
were not modified or restarted.

Nine independent oracle commitments were freshly recomputed at the execution
pair and equal the retained exact integers. Manifest retains12 ready LMM/GLMM
rows, four/family; Cox/GEE placeholders and1080 separate oracle-only rows.
Final-pair dependency equivalence retains the computation source pins.
Instruction remains **harvest/re-score the existing wave; do not rerun it**.
Shared optional-Gaussian handling remains integration-owned and unchanged;
GEE must not duplicate or fork that sampler fix. No GEE-owned file, batching,
simple-release, tag, push or thesis change. No new math blocker.
'''
(out/'RESUME.md').write_text(resume)
progress=dict(cycle=46,observed_utc=proof['observed_utc'],execution_source_commits=heads,promoted=4,promotion_source_commits=dict(dsVert='f3795a2',dsVertClient='e748f05'),cox_workload_admission=True,cox_public_ready=False,tests=proof['tests'],assertions=proof['assertions'],final_nonpasses=0,capacity_seconds=28800,capacity_bytes=256000000000,heavy_running=10,heavy_terminal=2,heavy_pass=1,heavy_fail=1,next='Cox publication/certificate/public reader and coordinated runtime admission, then signed lifecycle and first fleet jobs',gee_files_changed=False)
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
dest=root/'dsVert/inst/cross-grid-v2/cycle46';dest.mkdir(exist_ok=True)
for p in [out/n for n in ('RESUME.md','NEXT_COX.md','PROOF.json','progress.json','run-tests.R','run-client-tests.R','run-admission.R','frozen-tests.log','admission-frozen-final.log','client-tests.log','FLEET_LIVE_STATUS.json','FLEET_RESCORED.jsonl','harvest-current.log','checkpoint.py')]+list(out.glob('test*.csv')):shutil.copy2(p,dest/p.name)
print(json.dumps({k:proof[k] for k in ('tests','assertions','final_nonpasses')}))
