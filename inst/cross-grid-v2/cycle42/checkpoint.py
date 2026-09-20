import datetime,json,shutil
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
p=json.loads((out/'PROOF.json').read_text());m=json.loads((out/'MANIFEST_VALIDATION.json').read_text());heads=p['source_commits'];assert m['source_commits']==heads and m['ready_real_jobs']==12
smoke=json.loads((out/'SMOKE_CURRENT.json').read_text());paired=json.loads((out/'PAIRED_CURRENT.json').read_text());old=json.loads((out/'CAPACITY_LMM_FROZEN_K2.json').read_text())
assert paired['source_commits']==heads and not paired['source_mismatches']
header=f'''# Cycle42 checkpoint — 2026-09-20

Execution pair **{heads['dsVert'][:7]}/{heads['dsVertClient'][:7]}**. **4/10 promoted**,
exclusively at **f3795a2/e748f05**: NB, LASSO, multinomial, ordinal. NB resolved.

**LMM/GLMM authenticated relay batching is implemented**, ahead of further Cox
wiring as directed. Source complete-case normalization batches up to 128 rows,
bounded by the existing typed-input ceiling. Ring128->192 conversion batches
256 coordinates; GLMM q0 outcome normalization batches 256 rows and reuses its
public program per shape. At n2000/p3: normalization stages 125->16, conversion
chunks 313->40, GLMM outcome exchanges 63->8. This is schedule reduction, not
a measured 2–3h release claim. Integer expressions, rounding, caps, epsilon/delta,
private validity and fresh per-attempt cryptography are unchanged. Public stage
bounds bind the new schedule; use fresh state, never retrofit frozen workers.
Default GEE batching is unchanged; 21 GEE-owned files verified unchanged.

Verified **{p['patched_tests']} patched native tests + {len(p['baseline']['tests'])+len(p['baseline_ml']['tests'])} frozen-baseline tests PASS**,
including complete source-to-loss oracles, retained ML, private carry/sign,
large full/tail batches, bilateral remasking, unilateral persisted replay,
cold/tamper and actual spool workers. Differential routing/outcome opened bytes
match legacy batching. **{p['r']['tests']} focused R tests/{p['r']['assertions']} assertions PASS**,
including current-runtime Gaussian fallback. No native/R nonpasses. All five
local snapshots retain their original pinned hashes; executable native source
matches the execution commit. Four Go1.25.7 runtimes rebuilt; Linux SHA256:
`24908f68b63c830f716f04ffe18ee845608b4f97cb1f3487868436082b280081`.

**Manifest re-emitted incrementally and finalized: 12 ready LMM/GLMM jobs**,
four/family at the execution pair, with exact CLI and oracle hashes. Nine newly
regenerated commitments match retained exact integers. There are 24 heavy
definitions (Cox/GEE not ready here) and 1080 separate oracle-only definitions.
This is not a new selection campaign or n2000 release/capacity result. The
256GB/21,600-second ceiling is unchanged; fleet capacity reruns are required.

The original cycle16 **LMM n2000 epsilon4 K2 release has finished** on
**bc59147/6ba11a0**: oracle/sticky/cold/tamper PASS, process exit0; capacity FAIL
at **45,958.299 end-to-end seconds**, **24,001,151,241 serialized-RPC bytes**.
Native unique payload was 8,836,356,126 bytes (a different accounting basis).
Recovery was NOT exercised. Its gate exit is1. All2553 frozen source hashes
match. The outer controller still reports stale release_start with no sequence
exit; do not mistake that for an unfinished K2 release. Controller untouched.
Old 502b005/4c6c562 K5 capacity failure remains on its own pair.

Fresh signed n4/K2 LMM recovery smoke: `release-r1/logs/launch.json`, local
PID{smoke['launch']['pid']}, stdin /dev/null, 24h/15min leases, active at
{smoke['observed_utc']}. Prepared, bilateral PREPARE and unilateral COMMIT
boundaries observed; complete oracle/recovery/cold/tamper proof still pending.
This precommit snapshot's executable native/R sources match the execution pair;
its frozen manifest records the earlier base plus exact patched hashes.
No n2000 smoke-capacity inference.

Full server->client paired suites launched in the new immutable pod4 snapshot
`/workspace/dsvert/executor-cycle42-lmm-paired-r1`, PID{paired['launch']['pid']},
stdin /dev/null, exact execution pair, all3025 source/oracle hashes verified.
No terminal paired exit yet. Existing frozen jobs were untouched. The separate
simple client paired suite remains confirmatory and was incomplete when observed.

Shared DP remains owned here: the optional Gaussian certified-support gap retains
the certified-Laplace fallback; GEE must not fork it. No new Gaussian patch,
GEE-owned edit, Cox arithmetic/lifecycle change, tag, push, thesis edit, promotion
or new math blocker. Cox remains N<=400 and publicly gated pending lifecycle.

Pending: harvest current smoke and full paired suites; fleet n2000 serialized-RPC
capacity reruns and remaining heavy promotion gates; then resume Cox artifact/
source/client orchestration. **Batching is no longer pending implementation.**
Evidence: **integrator-evidence/cycle42-20260920/RESUME.md**, `PROOF.json`,
`MANIFEST_VALIDATION.json`, `CAPACITY_LMM_FROZEN_K2.json`, `progress.json`.

'''
for name in ('STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md'):
 path=root/name;text=path.read_text();assert text.startswith('# Cycle42');old_text=text.split('\n---\n\n',1)[1];path.write_text(header+'---\n\n'+old_text)
resume=header+f'''Full execution pins: {heads['dsVert']}/{heads['dsVertClient']}.

Resume read-only collectors:

```sh
python3 integrator-evidence/cycle42-20260920/collect-current.py
python3 integrator-evidence/cycle42-20260920/observe-paired.py
```

The first verifies hashes and captures current smoke/paired observations; it
never restarts or promotes. Review structured paired results, including warnings
and skips, when complete. Smoke terminal code/metrics are written by its detached
wrapper. Preserve all snapshots. Do not relaunch the completed old K2 release or
modify its still-live outer controller. Its raw result is in frozen-lmm-k2/.

Manifest prepare commands use the execution commits, not a later evidence-only
checkpoint commit. The current native proof is assembled from proof-r1/r2/r3;
r2 adds the outcome differential test, r3 adds the routing differential test.
Production native source is identical across those snapshots and the commit.
The frozen baseline is pre-batching 99886d2/55f4793 (server code equivalent to
6dbbf52); ML and complete source-to-loss oracle/recovery tests pass on both sides.
No n2000 wall-time speedup is yet measured on the patched pair.
'''
(out/'RESUME.md').write_text(resume)
progress=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,promoted_count=4,promoted_source_pair='f3795a2/e748f05',batching_implemented=True,proof='PROOF.json',manifest='MANIFEST_VALIDATION.json',old_lmm_k2='CAPACITY_LMM_FROZEN_K2.json',current_smoke='SMOKE_CURRENT.json',current_paired='PAIRED_CURRENT.json',simple_paired='SIMPLE_PAIRED_HEALTH.json',production_server_changed=True,production_client_changed=False,native_runtime_changed=True,gee_owned_files_edited=False,pending=['Current signed n4 recovery smoke completion','Current full paired completion and review','Fleet n2000 capacity reruns and heavy promotion gates','Cox artifact admission/source orchestration/complete DP lifecycle','Confirmatory simple client paired completion'])
(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
target=root/'dsVert/inst/cross-grid-v2/cycle42';target.mkdir()
for name in ('RESUME.md','PROOF.json','BUILD.json','MANIFEST_VALIDATION.json','CAPACITY_LMM_FROZEN_K2.json','SMOKE_CURRENT.json','PAIRED_CURRENT.json','SIMPLE_PAIRED_HEALTH.json','LMM_HARVEST.json','progress.json','launch.json','checkpoint.py','record-proof.py','record-frozen-k2.py','collect-current.py','observe-paired.py','freeze-paired.py','prepare-proof.py','emit-incrementally.py','run-oracles.py','finalize-manifest.py','run-tests.R','r-tests.log','manifest-incremental.log','manifest-finalize.log','oracles.log'):
 shutil.copy2(out/name,target/name)
for name in ('r-tests','manifest','frozen-lmm-k2'):
 shutil.copytree(out/name,target/name)
for name in ('baseline','proof-r1','proof-r2','proof-r3','release-r1'):
 shutil.copy2(out/name/'source-manifest.json',target/(name+'-source-manifest.json'))
 (target/name).mkdir()
 for path in (out/name).glob('*.jsonl'):shutil.copy2(path,target/name/path.name)
 for path in (out/name).glob('*.stderr'):shutil.copy2(path,target/name/path.name)
shutil.copy2(out/'proof-r2/build.log',target/'runtime-build.log')
for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json'):
 shutil.copy2(out.parent/name,target/name)
print(header)
