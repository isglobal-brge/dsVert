import datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
proof=json.loads((out/'R_PROOF.json').read_text());manifest=json.loads((out/'MANIFEST_VALIDATION.json').read_text())
assert heads==proof['source_commits']==manifest['source_commits']
lmm=json.loads((out/'LMM_HARVEST.json').read_text());paired=json.loads((out/'SIMPLE_PAIRED_HEALTH.json').read_text())
assert lmm['source']['mismatches']==[]
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',lmm='LMM_HARVEST.json',simple_paired='SIMPLE_PAIRED_HEALTH.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',production_server_changed=True,production_client_changed=False,native_runtime_changed=False,native_sampler_changed=False,gee_files_edited=False,pending=['Cox workload catalog admission, complete signed Claim/sharing transaction, client owner-first handoff and compilation/certificate dispatch','LMM authenticated relay batching with fresh output/recovery equality and capacity','Heavy lifecycle and promotion gates','Confirmatory simple client paired completion','Pod16 native worker readiness cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle39 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted** at
**f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB remains resolved.

Cox Claim and source-sharing materializers now select the same exact
binary64-rational producer after signed-schema and source-context validation.
The artifact namespace changes durable storage identity; source commitments
retain the original manifest identity. Private routing stays owner-local and
is reconstructed by the existing authenticated bind. N<=400 unchanged.

Fresh immutable snapshot: **{proof['tests']} tests/{proof['assertions']} assertions PASS**,
zero nonpasses; all {proof['frozen_source_files']} source hashes unchanged and equal committed
source. New K2/K3/K5 tests compare all owners' exact bytes and commitments,
reject altered contracts/version and schema lookup failures. Catalog, schema
lookup and transport context are test doubles in the new test. Existing signed
Cox/native/durable and shared Synopsis regressions included. No complete signed
Cox sharing/persistence transaction, DP release, capacity or promotion claim.
Additional fixture-catalog K2 Ed25519 Claims match the real sharing validator;
altered source bytes and signed commitments reject.

Current-native Gaussian fallback regression passes. Shared DP remains owned
here: the live optional Gaussian gap uses certified Laplace for base/recovery.
Pod16 terminal worker-readiness cause remains unresolved; GEE must not fork a
patch for the handled Gaussian diagnostic.

Frozen LMM incomplete at {lmm['observed_utc']}; all 2553 source hashes unchanged.
Confirmatory simple client paired incomplete at {paired['observed_utc']}.
Observed pod12/14/15 jobs still pin OLD 502b005/4c6c562; their measurements are
not attributed to the current pair. Frozen jobs untouched.

Refreshed manifest: 24 real epsilon8 definitions, four/family, **12 LMM/GLMM
fleet-ready jobs**; 1080 separate oracle-only definitions. All nine regenerated
exact commitments match prior integers. Cox/GEE remain not fleet-ready here.
Pending: Cox public lifecycle, LMM batching/fresh equality/capacity, heavy gates.
No GEE edits, new real release, tag, push, thesis edit or new math blocker.
See **integrator-evidence/cycle39-20260920/RESUME.md**, `COX_WIRING_NEXT.md`,
`R_PROOF.json`, `MANIFEST_VALIDATION.json`, `progress.json`.

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name;old=p.read_text();assert not old.startswith('# Cycle39');p.write_text(header+'---\n\n'+old)
(out/'RESUME.md').write_text(header+f'Full execution pins: {heads["dsVert"]}/{heads["dsVertClient"]}.\n')
target=root/'dsVert/inst/cross-grid-v2/cycle39';target.mkdir()
names=['RESUME.md','COX_WIRING_NEXT.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','LMM_HARVEST.json','SIMPLE_PAIRED_HEALTH.json','REVIEWER_FLEET_OBSERVATION.json','proof.log','claim-regressions.log','targeted.log','signed-claim.log','signed-claim.R','test-signed-claim.R','record-proof.py','checkpoint.py','prepare-proof.py','run-tests.R','run-oracles.py','finalize-manifest.py']
names+=sorted(p.name for p in out.glob('test-*.csv'))
for n in names:(target/n).write_bytes((out/n).read_bytes())
(target/'STATUS.md').write_text(header)
(target/'README.md').write_text('Cycle39 evidence. Scripts run from integrator-evidence/cycle39-20260920, not this archive. Execution pins precede this evidence-only commit. Frozen snapshots remain in the original workspace.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
for p in (out/'manifest/oracle-records').glob('*.json'):(target/('oracle-'+p.name)).write_bytes(p.read_bytes())
(target/'ORACLE_VALIDATION.json').write_bytes((out/'manifest/ORACLE_VALIDATION.json').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
