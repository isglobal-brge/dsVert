import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
load=lambda n:json.loads((out/n).read_text())
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
assert load('R_PROOF.json')['source_commits']==heads==load('MANIFEST_VALIDATION.json')['source_commits']
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',simple_paired='SIMPLE_PAIRED.json',lmm='LMM_HARVEST.json',lmm_health='LMM_HEALTH_SUMMARY.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',nb_resolution='../cycle32-20260920/NB_PROOF.json',production_server_changed=False,native_runtime_changed=False,shared_sampler_changed=False,gee_files_edited=False,pending=['Cox source orchestration and authenticated compile/certificate reader dispatch','LMM relay batching and fresh output/recovery/capacity proof','heavy lifecycle/capacity gates','confirmatory simple client paired completion','pod16 native alignment-mask startup cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle34 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**; server/native/sampler unchanged.
**4/10 promoted**, exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial,
ordinal. NB's resolved math gate remains closed.

Cox now has an internal authenticated cold vector reader: real two-authority
RELEASE signatures + bilateral REPLAY hashes/Merkle proof + signed Cox terminal
publication binding, preserving the exact integer lattice and N<=400 scope.
Fresh snapshot: **16 tests/496 assertions PASS**, zero nonpasses; all2646 hashes
unchanged. Final R/tests match tested bytes; only client documentation differs.
Synthetic compilation/DP-vector fixtures exercise the reader; authenticated
bundle/compilation is a required input. Public compile/orchestration/certificate
dispatch stays closed. No actual Cox DP release/capacity/promotion claim.

Fresh current-native Gaussian fallback regression:10 assertions PASS. Optional
Gaussian support gap remains live in base/recovery; both choose certified
Laplace. Pod16 native-readiness cause unresolved; shared DP owned here, GEE
must not fork a sampler patch for the caught diagnostic.

Simple client paired still active at12:36 UTC, all2504 hashes unchanged.
Frozen cycle16 LMM incomplete at12:32 UTC, all2553 hashes unchanged. Later
read-only descendant samples establish live native/R CPU activity; a sampled
FUSE wait does not establish a stall. Stopped queue controller untouched.
Reviewer fleet observed only. Minimal manifest refreshed:24 real epsilon8
jobs,4/family,12 LMM/GLMM ready,1080 separate oracle jobs; all9 regenerated
exact commitments unchanged. Promotion rows retain exact fleet source pins.

Cox public lifecycle wiring, LMM batching and heavy promotion gates remain
pending. No GEE edit, new real release, frozen mutation, tag, push, thesis edit
or math blocker. See **integrator-evidence/cycle34-20260920/RESUME.md**,
`R_PROOF.json`, `MANIFEST_VALIDATION.json`, `LMM_HEALTH_SUMMARY.json`, `progress.json`.

---

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name;old=p.read_text();assert not old.startswith('# Cycle34');p.write_text(header+old)
target=root/'dsVert/inst/cross-grid-v2/cycle34';target.mkdir()
names=['COX_WIRING_NEXT.md','RESUME.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','SIMPLE_PAIRED.json','SIMPLE_PAIRED_HEALTH.json','LMM_HARVEST.json','LMM_HEALTH_SUMMARY.json','REVIEWER_FLEET_OBSERVATION.json','reader-r1.log','reader-r2.log','preflight.log','manifest-tests.log','record-proof.py','checkpoint.py','prepare-proof.py','run-client.R','run-preflight.R','observe-lmm-health.py','observe-lmm-wait.py']
names+=sorted(p.name for p in out.glob('test*.csv'))
for name in names:(target/name).write_bytes((out/name).read_bytes())
(target/'STATUS.md').write_text(header.rstrip()+'\n')
(target/'README.md').write_text('Cycle34 evidence checkpoint. Scripts execute from the shared workspace\n`integrator-evidence/cycle34-20260920/`; copies here preserve provenance, not a\nrelocated runnable harness. Fresh snapshots and raw process metadata remain\nat that original path. Execution pins precede this documentation commit.\nSee RESUME.md and R_PROOF.json for proof boundaries and pending gates.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
