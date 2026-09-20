import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
load=lambda n:json.loads((out/n).read_text())
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
proof=load('R_PROOF.json');manifest=load('MANIFEST_VALIDATION.json')
assert proof['source_commits']==heads==manifest['source_commits']
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',simple_paired='SIMPLE_PAIRED.json',lmm='LMM_HARVEST.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',selection='SELECTION_SUMMARY.json',nb_resolution='../cycle32-20260920/NB_PROOF.json',production_server_changed=True,native_runtime_changed=False,native_sampler_changed=False,gee_files_edited=False,pending=['Cox source registration/remote orchestration and authenticated client compile/certificate dispatch','LMM relay batching and fresh output/recovery/capacity proof','heavy lifecycle/capacity gates','confirmatory simple client paired completion','pod16 native alignment-mask startup cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle35 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. Shared R lifecycle
changed; native runtimes/sampler and client unchanged. **4/10 promoted**,
exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal.

Cox is connected to shared pre-START public terminal binding and post-START
source injection, retaining Ring128 shares/private validity. Automatic context
lookup authenticates the cached signed schema; cache retention includes Cox.
Non-exact Synopsis and legacy vector paths reject Cox before private use.
Fresh source-verified regressions: **{proof['tests']} tests/{proof['assertions']} assertions PASS**,
zero nonpasses; all three frozen snapshots unchanged and final bytes equal code.
Includes cold schema MAC/signature tamper, production release-range checks,
Cox native/transport and LMM/GLMM/shared Synopsis regressions. Public admission,
source orchestration and certificate dispatch remain closed; N<=400 unchanged.
No complete Cox DP release/recovery/capacity/promotion claim.

Current-native Gaussian fallback regression passes. Optional Gaussian support
gap remains live for base/recovery; both select the same certified Laplace.
Pod16 terminal worker-readiness cause unresolved. Shared DP owned here; GEE
must not fork a sampler fix for the handled diagnostic.

Frozen LMM and confirmatory simple client paired incomplete at12:49 UTC;
all2553/2504 source hashes unchanged. Stopped LMM queue and reviewer jobs untouched.
Minimal manifest:24 epsilon8 real jobs,4/family,12 LMM/GLMM ready;1080 separate
oracle-only definitions. All9 regenerated exact commitments unchanged.

Pending: Cox public lifecycle; LMM relay batching and fresh equality/capacity;
heavy promotion gates. No GEE-owned edit, new real release, frozen mutation,
tag, push, thesis edit or math blocker. See **integrator-evidence/cycle35-20260920/RESUME.md**,
`R_PROOF.json`, `COX_WIRING_NEXT.md`, `MANIFEST_VALIDATION.json`, `progress.json`.

---

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name;old=p.read_text();assert not old.startswith('# Cycle35');p.write_text(header+old)
resume=out/'RESUME.md';resume.write_text(resume.read_text()+f'\nExecution pair: {heads["dsVert"]}/{heads["dsVertClient"]}.\nFinal source-verified proof: {proof["tests"]} tests/{proof["assertions"]} assertions, zero nonpasses;\nall {proof["snapshots"]["hooks-r3"]["source_files"]} final source hashes unchanged and equal committed source.\nMinimal manifests: 24 real / 1080 oracle-only definitions; all nine exact\ncommitments independently regenerated and equal prior integers.\n')
target=root/'dsVert/inst/cross-grid-v2/cycle35';target.mkdir()
names=['RESUME.md','COX_WIRING_NEXT.md','LMM_BATCHING_NEXT.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','SIMPLE_PAIRED.json','LMM_HARVEST.json','REVIEWER_FLEET_OBSERVATION.json','SELECTION_SUMMARY.json','hooks-r1.log','hooks-r2.log','hooks-r3.log','cache-selected.log','manifest-tests.log','record-proof.py','checkpoint.py','prepare-proof.py','run-tests.R','check-cache.R','run-oracles.py','finalize-manifest.py']
names+=sorted(p.name for p in out.glob('test-*.csv'))
for name in names:(target/name).write_bytes((out/name).read_bytes())
(target/'STATUS.md').write_text(header.rstrip()+'\n')
(target/'README.md').write_text('Cycle35 evidence. Scripts run at the original workspace path\nintegrator-evidence/cycle35-20260920, not from this archival copy.\nExecution pins precede this evidence-only commit. Fresh snapshots and raw\nobservations remain at the original path. See RESUME.md for proof limits.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
