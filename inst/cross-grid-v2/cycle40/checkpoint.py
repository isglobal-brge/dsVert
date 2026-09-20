import datetime,hashlib,json,shutil,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
p=json.loads((out/'R_PROOF.json').read_text());m=json.loads((out/'MANIFEST_VALIDATION.json').read_text())
assert p['source_commits']==m['source_commits']==heads
lmm=json.loads((out/'LMM_HARVEST.json').read_text());paired=json.loads((out/'SIMPLE_PAIRED_HEALTH.json').read_text())
assert lmm['source']['mismatches']==[]
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',lmm='LMM_HARVEST.json',simple_paired='SIMPLE_PAIRED_HEALTH.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',production_server_changed=True,production_client_changed=False,native_runtime_changed=False,native_sampler_changed=False,gee_files_edited=False,pending=['Cox client catalog, server workload artifact admission, complete signed sharing/persistence, owner-first bind handoff, compilation/certificate dispatch and actual DP lifecycle','LMM authenticated relay batching with fresh output/recovery equality and measured capacity','Heavy promotion gates','Confirmatory simple client paired completion','Pod16 native worker readiness root cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle40 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted**, exclusively
at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB remains resolved.

Cox server catalog normalization now preserves its signed contract and uses
explicit time/event descriptors. Both must belong to the advertising custodian
and dataset; all time/event/predictor columns resolve by owner+column+dataset.
No implicit public moments are added. Public workload artifact admission stays
explicitly closed until the remaining client/source/release integration is proved.
No arithmetic, N<=400 scope, native runtime or sampler change.

Verified **{p['tests']} tests/{p['assertions']} assertions PASS**, zero nonpasses in the
assembled final coverage. Existing tests use proof-r1; the new real catalog
K2/K3/K5 test uses proof-r3 (51 assertions). Executable R and unchanged tests
are identical; all three snapshots remain unchanged. Earlier new-test fixture
errors and the prior-code rejection are retained and described in R_PROOF.json.
New catalog tests use no catalog/schema test doubles; existing broader tests
retain their documented doubles. This is not a complete signed Cox draft,
sharing/persistence transaction, DP release, recovery or capacity proof.

New retained reviewer result: OLD pair **502b005/4c6c562** LMM epsilon8 K5
passes oracle/sticky/cold/tamper but **FAILS capacity**: 22,774.592 release seconds
>21,600, with 24,036,925,468 serialized-RPC bytes. Native unique payload is
8,838,064,187 bytes; these are different accounting bases. Recovery not exercised.
Raw log markers and metrics verified and retained in CAPACITY_LMM_OLD_PAIR.json;
no current-source attribution.

Current-native optional Gaussian fallback regression passes: the live optional
coverage gap selects certified Laplace consistently. Shared DP remains owned
here; GEE must not fork a patch for this handled diagnostic. Pod16 terminal
worker-readiness cause remains unresolved; no new real-release claim.

Frozen LMM K2 incomplete at {lmm['observed_utc']}; all {lmm['source']['files']} source hashes
unchanged. Confirmatory simple client paired incomplete at {paired['observed_utc']}.
Frozen jobs untouched. Manifest refreshed at the execution pair: **12 LMM/GLMM
fleet-ready jobs**, four/family; 24 total heavy definitions, with Cox/GEE not ready
here, plus 1080 separate oracle-only definitions. All nine regenerated exact
commitments match previous integers.

Pending: Cox public lifecycle, LMM relay batching and fresh equality/capacity,
heavy gates. No GEE edits, new real release, tag, push, thesis edit or math blocker.
See **integrator-evidence/cycle40-20260920/RESUME.md**, `COX_WIRING_NEXT.md`,
`R_PROOF.json`, `MANIFEST_VALIDATION.json`, `progress.json`.

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 path=root/name;old=path.read_text();assert not old.startswith('# Cycle40');path.write_text(header+'---\n\n'+old)
(out/'RESUME.md').write_text(header+f'Full execution pins: {heads["dsVert"]}/{heads["dsVertClient"]}.\n')
target=root/'dsVert/inst/cross-grid-v2/cycle40';target.mkdir()
for path in out.iterdir():
 if path.is_file() and path.suffix in ('.md','.json','.py','.R','.csv','.log'):
  shutil.copy2(path,target/path.name)
for name in ('catalog-r2','catalog-r3','fleet-observed'):
 shutil.copytree(out/name,target/name)
for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json'):
 shutil.copy2(out.parent/name,target/name)
for name in ('proof-r1','proof-r2','proof-r3','baseline'):
 shutil.copy2(out/name/'source-manifest.json',target/(name+'-source-manifest.json'))
shutil.copytree(out/'manifest',target/'manifest')
print(header)
