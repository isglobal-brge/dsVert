import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
proof=json.loads((out/'R_PROOF.json').read_text());manifest=json.loads((out/'MANIFEST_VALIDATION.json').read_text())
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
assert heads==proof['source_commits']==manifest['source_commits']
lmm=json.loads((out/'LMM_HARVEST.json').read_text());paired=json.loads((out/'SIMPLE_PAIRED_HEALTH.json').read_text())
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',lmm='LMM_HARVEST.json',simple_paired='SIMPLE_PAIRED.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',production_server_changed=True,native_runtime_changed=False,native_sampler_changed=False,gee_files_edited=False,pending=['Cox public source catalog/claim/transport registration, exported routing-receipt handoff and client compilation/certificate dispatch','LMM authenticated relay batching with fresh output/recovery equality and capacity measurement','Heavy complete lifecycle/promotion gates','Confirmatory simple client paired completion','Pod16 native worker readiness cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle36 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted**, exclusively
at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB remains resolved.

Cox now has an internal authenticated remote-binding adapter. It revalidates
Synopsis source context, manifest hash and signed schema before owner snapshot
resolution, checks computation authority and immutable admission, then calls
the existing durable source/route/native binding. The evaluator resolves no
snapshots and requires the owner's signed routing receipt. Public catalog and
exported endpoint/client dispatch remain closed; N<=400 unchanged.

Fresh snapshot: **{proof['tests']} tests/{proof['assertions']} assertions PASS**, zero nonpasses;
all {proof['frozen_source_files']} hashes unchanged and equal committed source. Includes K2/K3/K5
real Cox worker preparation and signed routing/durable source checks. Upstream
Synopsis context/cache and snapshot resolver are test doubles for the new
adapter. No complete Cox DP release, recovery, capacity or promotion claim.

Current-native Gaussian fallback regression passes. Optional Gaussian coverage
gap remains live in base/recovery; both select certified Laplace. Pod16's
terminal worker-readiness cause remains unresolved. Shared DP is owned here;
GEE must not fork a patch for the handled Gaussian diagnostic.

Frozen LMM incomplete at {lmm['observed_utc']}; all 2553 source hashes unchanged.
Confirmatory simple client paired remains active at {paired['observed_utc']}.
Reviewer jobs observed only; no frozen/controller modification or new release.
Minimal manifest: 24 real epsilon8 jobs, four/family; 12 LMM/GLMM ready;
1080 separate oracle-only definitions, nine regenerated exact commitments equal.

Pending: Cox public lifecycle, LMM batching/fresh equality/capacity and heavy
gates. No GEE edit, tag, push, thesis edit or new math blocker.
See **integrator-evidence/cycle36-20260920/RESUME.md**, `R_PROOF.json`,
`COX_WIRING_NEXT.md`, `MANIFEST_VALIDATION.json`, `progress.json`.

---

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name;old=p.read_text();assert not old.startswith('# Cycle36');p.write_text(header+old)
(out/'RESUME.md').write_text(header.split('\n---\n')[0]+f'\nFull execution pins: {heads["dsVert"]}/{heads["dsVertClient"]}.\n\nNext implementation steps are COX_WIRING_NEXT.md. LMM batching boundary remains\n../cycle35-20260920/LMM_BATCHING_NEXT.md. Keep exact arithmetic/privacy and\nfrozen snapshots unchanged. The current code adds no exported endpoint or\nclient argument for Cox routing receipts; do not call it fleet-ready.\n')
target=root/'dsVert/inst/cross-grid-v2/cycle36';target.mkdir()
names=['RESUME.md','COX_WIRING_NEXT.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','LMM_HARVEST.json','SIMPLE_PAIRED_HEALTH.json','SIMPLE_PAIRED.json','REVIEWER_FLEET_OBSERVATION.json','remote-r1.log','manifest-tests.log','record-proof.py','checkpoint.py','prepare-proof.py','run-tests.R','run-oracles.py','finalize-manifest.py']
names+=sorted(p.name for p in out.glob('test-*.csv'))
for name in names:(target/name).write_bytes((out/name).read_bytes())
(target/'STATUS.md').write_text(header.rstrip()+'\n')
(target/'README.md').write_text('Cycle36 evidence. Scripts run from integrator-evidence/cycle36-20260920,\nnot this archival directory. The execution pins precede this evidence-only\ncommit. Fresh snapshot and raw observations remain in the original workspace.\nSee RESUME.md and R_PROOF.json for fixture limits and pending gates.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
for record in (out/'manifest/oracle-records').glob('*.json'):
 (target/('oracle-'+record.name)).write_bytes(record.read_bytes())
(target/'ORACLE_VALIDATION.json').write_bytes((out/'manifest/ORACLE_VALIDATION.json').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
