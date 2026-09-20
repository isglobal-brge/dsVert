import datetime, hashlib, json, subprocess
from pathlib import Path
out=Path(__file__).resolve().parent; root=out.parents[1]
heads={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')}
proof=json.loads((out/'R_PROOF.json').read_text()); manifest=json.loads((out/'MANIFEST_VALIDATION.json').read_text())
assert heads==proof['source_commits']==manifest['source_commits']
lmm=json.loads((out/'LMM_HARVEST.json').read_text()); paired=json.loads((out/'SIMPLE_PAIRED_HEALTH.json').read_text())
assert lmm['source']['mismatches']==[]
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',proof='R_PROOF.json',manifest='MANIFEST_VALIDATION.json',lmm='LMM_HARVEST.json',simple_paired='SIMPLE_PAIRED_HEALTH.json',reviewer_fleet='REVIEWER_FLEET_OBSERVATION.json',production_server_changed=True,production_client_changed=False,native_runtime_changed=False,native_sampler_changed=False,gee_files_edited=False,pending=['Cox signed workload catalog and Claim/transport producer registration, client owner-first handoff and compilation/certificate dispatch','LMM authenticated relay batching with fresh output/recovery equality and capacity','Heavy full lifecycle and promotion gates','Confirmatory simple client paired completion','Pod16 native worker readiness cause'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
header=f'''# Cycle38 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted**, exclusively
at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB remains resolved.

Shared capsule/Synopsis source construction now uses Cox's exact private layout
and namespaced contract. K2/K3/K5 match the existing authenticated Cox context.
The exported evidence action now verifies publication/compilation equality,
reconstructs the source namespace, loads the signed schema and dispatches the
Cox public terminal reader without a live session or private candidate rows.
Catalog/producer and client orchestration remain pending; N<=400 unchanged.

Fresh immutable snapshot: **{proof['tests']} tests/{proof['assertions']} assertions PASS**, zero nonpasses;
all {proof['frozen_source_files']} source hashes unchanged and equal committed source. Prior-code
control reproduces the source-contract gap. New tests use upstream catalog/
materializer and publication/compilation/schema lookup test doubles; real signed
Cox validation, SQLite terminal authentication and cold evidence dispatch are
exercised. Includes existing Cox native worker and shared source/Synopsis/LMM/
GLM regressions. No complete Cox DP release, capacity or promotion claim.

Current-native Gaussian fallback regression passes. The optional Gaussian gap
remains live for base/recovery; both select certified Laplace. Pod16 terminal
worker-readiness cause remains unresolved. Shared DP is owned here; GEE must
not fork a patch for the handled Gaussian diagnostic.

Frozen LMM incomplete at {lmm['observed_utc']}; all 2553 source hashes unchanged.
Confirmatory simple client paired incomplete at {paired['observed_utc']}.
Observed pod12/14/15 jobs remain on OLD 502b005/4c6c562, separately recorded;
no result is attributed to the new execution pair. Frozen jobs left untouched.
Refreshed manifest: 24 real epsilon8 definitions, four/family, **12 LMM/GLMM
fleet-ready jobs**; 1080 separate oracle-only definitions. All nine regenerated
exact commitments match previous integers. Cox/GEE remain not fleet-ready here.

Pending: Cox public lifecycle, LMM batching/fresh equality/capacity, heavy gates.
No GEE-owned edit, tag, push, thesis edit or new math blocker. See
**integrator-evidence/cycle38-20260920/RESUME.md**, `COX_WIRING_NEXT.md`,
`R_PROOF.json`, `MANIFEST_VALIDATION.json`, `progress.json`.

---

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 p=root/name; old=p.read_text(); assert not old.startswith('# Cycle38'); p.write_text(header+old)
(out/'RESUME.md').write_text(header.split('\n---\n')[0]+f'\nFull execution pins: {heads["dsVert"]}/{heads["dsVertClient"]}.\n\nLMM batching boundary remains ../cycle35-20260920/LMM_BATCHING_NEXT.md.\nNext Cox steps: COX_WIRING_NEXT.md. Do not enable fleet readiness from these\nfixture-backed contract/reader tests. Preserve all frozen jobs and GEE ownership.\n')
target=root/'dsVert/inst/cross-grid-v2/cycle38'; target.mkdir()
names=['RESUME.md','COX_WIRING_NEXT.md','progress.json','R_PROOF.json','MANIFEST_VALIDATION.json','LMM_HARVEST.json','SIMPLE_PAIRED_HEALTH.json','REVIEWER_FLEET_OBSERVATION.json','cox-r1.log','shared.log','source-regressions.log','baseline.log','record-proof.py','checkpoint.py','prepare-proof.py','run-tests.R','run-oracles.py','finalize-manifest.py','manifest-tests.log']
names+=sorted(p.name for p in out.glob('test-*.csv'))
for name in names:(target/name).write_bytes((out/name).read_bytes())
(target/'baseline-test-crossgrid-cox.R.csv').write_bytes((out/'baseline-r1/test-crossgrid-cox.R.csv').read_bytes())
(target/'STATUS.md').write_text(header.rstrip()+'\n')
(target/'README.md').write_text('Cycle38 evidence. Run scripts from integrator-evidence/cycle38-20260920, not this archive. Execution/manifest pins precede this documentation-only checkpoint. Full snapshots remain in the original workspace.\n')
(target/'RELEASE_MANIFEST.jsonl').write_bytes((root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_bytes())
for record in (out/'manifest/oracle-records').glob('*.json'):(target/('oracle-'+record.name)).write_bytes(record.read_bytes())
(target/'ORACLE_VALIDATION.json').write_bytes((out/'manifest/ORACLE_VALIDATION.json').read_bytes())
(target/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir())},indent=2)+'\n')
print(json.dumps(progress,indent=2))
