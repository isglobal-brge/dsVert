import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
load=lambda n:json.loads((out/n).read_text())
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
assert load('R_PROOF.json')['source_commits']==heads==load('MANIFEST_VALIDATION.json')['source_commits']
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',simple_paired='SIMPLE_PAIRED.json',lmm='LMM_HARVEST.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',nb_resolution='../cycle32-20260920/NB_PROOF.json',production_server_changed=False,native_runtime_changed=False,shared_sampler_changed=False,gee_files_edited=False,pending=['Cox source orchestration and DP-vector reader','LMM relay batching and fresh output/recovery/capacity proof','heavy lifecycle/capacity gates','confirmatory simple client paired completion','pod16 native alignment-mask startup cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle33 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**; server/native/sampler unchanged.
**4/10 promoted**, exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial,
ordinal. NB's assembly fix predates all nine passing fleet cells; no new NB gate.

Fixed Cox result processing rejecting valid K3/K5 source-owner sets by checking
all signed participating peers separately from its two computation authorities.
Fresh baseline reproduces the defect; fixed snapshot **16 tests/436 assertions
PASS**, no nonpasses, including Cox evidence and LMM public-release regression.
Both 2621-file snapshots unchanged; final executable R/tests match tested bytes,
with subsequent documentation-only wording changes. This is fixture-backed
result processing, not an authenticated Cox DP-vector reader or real release.
Public dispatch remains closed and staged N<=400 scope unchanged.

Fresh current-native Gaussian fallback regression:10 assertions PASS. Optional
Gaussian coverage gap remains live in base/recovery, both choose certified
Laplace. Pod16 terminal native readiness cause unresolved; shared DP owned here,
GEE must not fork a sampler fix for the handled Gaussian message.

Simple client paired still active at12:20 UTC, all2504 source hashes unchanged.
Frozen cycle16 LMM K2 incomplete at12:21 UTC, all2553 source hashes unchanged.
Historical cycle10/11 failed runs were also harvested, not confused with cycle16.
Reviewer jobs observed only. Minimal manifest refreshed:24 real epsilon8 jobs,
4/family,12 LMM/GLMM ready,1080 separate oracle-only jobs; all9 exact commitments
regenerated and unchanged. Promotion rows retain their exact fleet pins.

Cox orchestration/DP reader, LMM batching, and heavy promotion gates remain
pending. No GEE edit, new real release, frozen mutation, tag, push, thesis edit
or math blocker. See **integrator-evidence/cycle33-20260920/RESUME.md**,
`R_PROOF.json`, `MANIFEST_VALIDATION.json` and `progress.json`.

---

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name;old=p.read_text();assert not old.startswith('# Cycle33');p.write_text(header+old)
# Keep a compact immutable checkpoint in the server repository, excluding snapshots.
target=root/'dsVert/inst/cross-grid-v2/cycle33';target.mkdir()
names=['PRIORITY_F_G_H.json','RESUME.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','SIMPLE_PAIRED.json','SIMPLE_PAIRED_HEALTH.json','LMM_HARVEST.json','REVIEWER_FLEET_OBSERVATION.json','baseline.log','fixed.log','preflight.log','manifest-tests.log','record-proof.py','checkpoint.py','prepare-proof.py','run-client.R','run-preflight.R']
names+=sorted(p.name for p in out.glob('test*.csv'))
for name in names:(target/name).write_bytes((out/name).read_bytes())
(target/'STATUS.md').write_text(header)
(target/'README.md').write_text('Cycle33 evidence checkpoint. Original scripts execute from the shared workspace\n`integrator-evidence/cycle33-20260920/`; copies here retain provenance, not a\nrelocated runnable harness. Fresh baseline/fixed source snapshots and full logs\nremain at that original path. Execution pins precede this documentation commit.\nSee RESUME.md and R_PROOF.json for proof boundaries and remaining work.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
