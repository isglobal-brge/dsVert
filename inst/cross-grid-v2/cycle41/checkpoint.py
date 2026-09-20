import datetime,json,shutil,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
p=json.loads((out/'R_PROOF.json').read_text());m=json.loads((out/'MANIFEST_VALIDATION.json').read_text());heads=p['source_commits'];assert m['source_commits']==heads
lmm=json.loads((out/'LMM_HARVEST.json').read_text());paired=json.loads((out/'SIMPLE_PAIRED_HEALTH.json').read_text())
assert lmm['sequence_exit'] is None and not lmm['source']['mismatches'] and not paired['completed']
header=f'''# Cycle41 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted**,
exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB resolved.

Cox client catalog preflight now binds its wrapper version/dataset/analysis,
common time/event owner, descriptor dataset/reference and advertising peer.
Both capsule and Synopsis bootstrap draft parsers apply the owner check.
K2/K3/K5 signed drafts preserve the contract; wrong advertising owners and
modified signed bytes reject. Prior-code control rejects a valid signed draft.
Full contract/schema authentication remains required downstream; public server
artifact admission stays closed. No arithmetic, N<=400, runtime or sampler change.

Verified **{p['tests']} tests/{p['assertions']} assertions PASS**, zero nonpasses in
assembled final coverage, including current-native optional-Gaussian fallback.
All four proof snapshots retain their original hashes. New tests use real
Ed25519 signatures and no catalog/schema mocks. Existing regressions retain their
documented doubles. Initial assertion-order and test-harness package-selection
failures are retained, with scope in R_PROOF.json. No complete Cox source-sharing,
DP release, recovery or capacity claim.

Minimal manifest refreshed at this execution pair: **12 LMM/GLMM fleet-ready
jobs**, four/family; 24 heavy definitions, Cox/GEE not ready here, plus 1080
separate oracle-only definitions. Nine freshly regenerated exact commitments
match previous integers. This is not a new real-release or selection-grid proof.

Shared DP remains owned here: optional Gaussian certified-support gap remains
live and selects certified Laplace; GEE must not fork a patch. Pod16 terminal
worker-readiness cause remains unresolved. OLD 502b005/4c6c562 LMM K5 exceeds
6h; cycle40 capacity evidence stays on that old source pair.

Frozen LMM incomplete at {lmm['observed_utc']}; all {lmm['source']['files']} source
hashes unchanged. Confirmatory simple client paired incomplete at
{paired['observed_utc']}. Frozen jobs untouched.

Pending: Cox workload artifact/source/client orchestration and complete lifecycle;
LMM authenticated relay batching plus fresh output/recovery equality and capacity;
heavy promotion gates. No GEE edit, new real release, tag, push, thesis edit or
new math blocker. See **integrator-evidence/cycle41-20260920/RESUME.md**,
`COX_WIRING_NEXT.md`, `R_PROOF.json`, `MANIFEST_VALIDATION.json`, `progress.json`.

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 path=root/name;old=path.read_text();assert not old.startswith('# Cycle41');path.write_text(header+'---\n\n'+old)
(out/'RESUME.md').write_text(header+f'Full execution pins: {heads["dsVert"]}/{heads["dsVertClient"]}.\n')
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',lmm='LMM_HARVEST.json',simple_paired='SIMPLE_PAIRED_HEALTH.json',production_client_changed=True,production_server_changed=False,native_runtime_changed=False,gee_files_edited=False,pending=['Cox artifact admission/source orchestration/complete DP lifecycle','LMM relay batching and fresh equality/capacity','Heavy promotion gates','Confirmatory simple paired completion','Pod16 worker readiness diagnosis'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
target=root/'dsVert/inst/cross-grid-v2/cycle41';target.mkdir()
for path in out.iterdir():
 if path.is_file() and path.suffix in ('.md','.json','.py','.R','.csv','.log'):shutil.copy2(path,target/path.name)
for name in ('final','regression','manifest'):shutil.copytree(out/name,target/name)
for name in ('proof-r1','proof-r2','proof-r3','baseline'):shutil.copy2(out/name/'source-manifest.json',target/(name+'-source-manifest.json'))
for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json'):shutil.copy2(out.parent/name,target/name)
print(header)
