import csv,datetime,hashlib,json,shutil,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
heads=json.loads((out/'MANIFEST_VALIDATION.json').read_text())['source_commits']
frames=[]
for p in [*out.glob('test*.csv'),*(out/'server-tests').glob('test*.csv')]:
 rows=list(csv.DictReader(p.open()))
 assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows),p
 frames.append(dict(file=str(p.relative_to(out)),tests=len(rows),assertions=sum(int(r['passed']) for r in rows)))
assert (out/'server-tests/test-crossgrid-cox.R.csv').exists()
proof=dict(source_commits=heads,suites=frames,tests=sum(r['tests'] for r in frames),assertions=sum(r['assertions'] for r in frames),nonpasses=0,scope='Live local focused R tests; production sources equal committed pair. Client transport is a test double; signatures, source projection, route binding and cold receipt validation are real. No complete Cox release or capacity proof. Client skip-if-companion-absent guards were added after the passing run; no production change followed it.',capacity='CAPACITY_VERIFICATION.json',native_reversion='REVERT_VERIFICATION.json')
(out/'PROOF.json').write_text(json.dumps(proof,indent=2)+'\n')
measured=json.loads((out/'MEASURED_CAPACITY.json').read_text())['samples']
lines=['| Family | Promoted | Measured serialized RPC bytes | Measured release seconds | Evidence scope |','|---|---|---:|---:|---|']
for fam in ('nb','lasso','multinomial','ordinal','lmm','binomial_glmm','poisson_glmm','binomial_gee','poisson_gee','cox'):
 m=measured.get(fam,{})
 scope='Nine retained simple cells' if fam in ('nb','lasso','multinomial','ordinal') else 'Old-pair epsilon8 K5 baseline only' if fam=='lmm' else 'Pending; GEE owned separately' if 'gee' in fam else 'No completed authenticated measurement here'
 lines.append(f"| {fam} | {'Yes' if fam in ('nb','lasso','multinomial','ordinal') else 'No'} | {m.get('serialized_rpc_bytes','—')} | {m.get('release_seconds','—')} | {scope} |")
text=f'''# Cycle43 checkpoint — 2026-09-20

Execution/manifest pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**.
**4/10 promoted**, still at **f3795a2/e748f05**. NB remains resolved.
The latest David directive J supersedes cycle42's batching/rerun/6-hour prose.

**Admitted release envelope: 256,000,000,000 serialized-RPC bytes / 28,800 seconds (8 h).**
Shared `inst/cross-grid-v2/integrator-validation/release-capacity.json` drives the
manifest and sequential release driver for future snapshots. Existing frozen jobs
retain their original code/config. The retained fleet finalizer now re-scores
measured records using this policy and archives original inputs by SHA256.
No heavy release was restarted or re-executed. Repeated scoring preserves the
original verdict and never changes source, oracle, cold, tamper or recovery facts.

The two collected fleet records now score **1 PASS / 1 FAIL** on their ORIGINAL
**502b005/4c6c562** pair. **LMM epsilon8 K5 PASS**: oracle/cold/tamper, exit0,
**22,774.592 end-to-end seconds / 24,036,925,468 serialized-RPC bytes**.
Its inner elapsed22607.515 is not the end-to-end capacity measurement. Native
unique payload8,838,064,187 is recorded separately. Recovery was not requested.
Old GLMM K2 recovery still FAILS before oracle validation; changing capacity
cannot clear that failure. Ten fleet jobs remained running at the latest harvest.
No heavy family has complete topology/recovery evidence, so no new promotion.
The older cycle16 epsilon4 LMM K2 at45,958.299s still fails the8-hour ceiling.

**Batching deferred from this line.** Preserved `7ff811c` on
`post-tag/lmm-glmm-relay-batching`; reverted it with `24da71f`.
All native source and packaged runtimes are byte-identical to pre-batching
`99886d2`. Frozen batch-proof/release/paired snapshots were untouched. Their
results belong to that separate runtime and cannot be attributed to this pair.
The separate signed n4 LMM smoke has now completed exit0: all oracle, recovery,
cold and tamper markers PASS; all3024 frozen hashes match. Its full paired suite
remains incomplete (3025 hashes match). This is no n2000 capacity claim.
The eventual tag/source decision remains separate; old fleet metrics do not
establish measured capacity of new source commits. No tags or pushes.

**Cox client integration advanced:** exact source lane projection now agrees
with server K2/K3/K5 layouts; time values/routes remain owner-local, with only
private time-presence validity in transport. The owner-first bind helper checks
the pinned owner's real signature and source/semantic/artifact/profile/certificate
bindings before forwarding its public routing receipt; it then checks bilateral
bound-stage equality. No private routes enter the client. N<=400 retained.
Public discovery/admission stays closed: runner/certificate/workload dispatch,
full signed DP lifecycle proof and the FIRST Cox fleet run remain pending.

Focused R proof: **{proof['tests']} tests / {proof['assertions']} assertions PASS**,
zero nonpasses. New client transport tests use a fan-out test double, real Ed25519
signatures, and the actual server source projection/key. Existing Cox server and
public cold evidence tests are included. This is not full paired or real Cox DP
release proof. Capacity boundary/nonfinite/missing-data/lifecycle tests pass.
Shared optional-Gaussian fallback passes against the restored native runtime;
shared DP remains owned here, and the GEE lane must not fork a fix.
GEE-owned native/certificate/oracle files and crossgrid_grouped.R are unchanged.

Manifest refreshed: **12 ready LMM/GLMM definitions**, four per family, plus
Cox/GEE placeholders and1080 separate oracle-only definitions. Nine commitments
were regenerated at29a9921/55f4793 and match retained exact integers. Their
origin records remain immutable. Final-pair projections verify identical oracle
dependencies (all server R/native/helper/oracle inputs, and the sole client
integer helper); no computation at a different pair is silently relabeled.
`RELEASE_MANIFEST_STATUS.json` explicitly says **harvest/re-score the existing
wave; do not rerun it**. Ready definitions are not an instruction to duplicate it.

Measured capacity below is separate from promotion. Envelope **256 GB / 8 h**
applies uniformly; simple rows report maxima across their nine retained cells.
No missing measurements are treated as zero or extrapolated from kernel costs.

{chr(10).join(lines)}

Simple confirmatory paired suite now COMPLETE on f3795a2/e748f05: client
1150 tests /33908 passing assertions, zero failures/errors/warnings,5 test-level
skips plus the separate module-level DSLite exclusion. All2504 frozen source
hashes matched the existing collector. The server retained1164 tests/21062
assertions with zero nonpasses. Skips are reviewed and retained in
SIMPLE_PAIRED_CONFIRMATION.json; no family-specific defect was reported.
The promotion manifest records this confirmation without changing source pins.

Pending: finish Cox workload/client runner/certificate integration and signed
small lifecycle, then emit its first fleet rows; harvest/re-score remaining heavy
jobs and promote only complete proven family/source sets; harvest full paired
evidence. No new math blocker, simple release,
GEE edit, thesis edit, tag, push, or frozen-worker mutation.

Evidence: **integrator-evidence/cycle43-20260920/RESUME.md**, `PROOF.json`,
`FLEET_RESCORED.jsonl`, `MEASURED_CAPACITY.json`, `MANIFEST_VALIDATION.json`,
`ORACLE_DEPENDENCY_EQUIVALENCE.json`, `REVERT_VERIFICATION.json`, `progress.json`.
'''
(out/'RESUME.md').write_text(text+'''
Resume collectors (read-only for running workloads):
- `python3 ../dsvert-fleet-heavy/poll.py`
- `python3 ../dsvert-fleet-heavy/finalize_results.py` re-scores collected records;
  originals are retained in fleet-heavy/artifacts/capacity-rescore-inputs/.
- `python3 integrator-evidence/cycle42-20260920/collect-current.py` harvests the
  SEPARATE deferred-batching smoke/paired snapshots, never promotes/restarts.
- `python3 integrator-evidence/cycle42-20260920/observe-paired.py` observes the
  confirmatory simple client suite.
Cox map: cycle41 COX_WIRING_NEXT.md remains applicable except the source-block
projection and authenticated owner-first bind helper now exist in client
`dp_cox_grid_cross_release.R`; public dispatch has deliberately not been enabled.
Do not restore batching from the preserved branch before the release tag.
''')
for p in (root/'STATUS_INTEGRATOR.md',root/'integrator-evidence/PROMOTION_TABLE.md'):
 p.write_text(text+'\n---\n\n'+p.read_text())
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,capacity_bytes=256000000000,capacity_seconds=28800,fleet_collected=2,fleet_rescored_pass=1,fleet_rescored_fail=1,fleet_observed_running=10,batching_on_release_line=False,batching_branch='post-tag/lmm-glmm-relay-batching',cox_public_ready=False,cox_first_release_launched=False,simple_confirmatory_client_complete=True,gee_owned_files_edited=False,real_releases_launched=0,proof='PROOF.json',manifest='MANIFEST_VALIDATION.json',pending=['Cox artifact/client runner/certificate dispatch and full lifecycle','Remaining old-pair heavy jobs and family recovery/topology gates','Paired suite completion and review'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
target=root/'dsVert/inst/cross-grid-v2/cycle43';target.mkdir(exist_ok=True)
for p in out.iterdir():
 if p.is_file() and p.suffix in ('.json','.jsonl','.md','.py','.csv','.log'):shutil.copy2(p,target/p.name)
for sub in ('server-tests','manifest','simple-paired'):
 shutil.copytree(out/sub,target/sub,dirs_exist_ok=True)
for name in ('RELEASE_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json','CAPACITY_ENVELOPES.json','PROMOTION_MANIFEST.jsonl'):
 shutil.copy2(root/'integrator-evidence'/name,target/name)
shutil.copy2(root/'EXECUTOR_SPEC.md',target/'EXECUTOR_SPEC.md')
print(json.dumps(proof,indent=2))
