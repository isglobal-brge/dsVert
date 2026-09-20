from pathlib import Path
import collections, datetime, hashlib, json, shutil
root=Path(__file__).resolve().parents[2]
out=Path(__file__).resolve().parent
fleet=root.parent/'dsvert-fleet-heavy'
policy=json.loads((root/'dsVert/inst/cross-grid-v2/integrator-validation/release-capacity.json').read_text())
inputs={'FLEET_RESCORED.jsonl':fleet/'RESULTS.jsonl','COX_RESULTS.jsonl':fleet/'cox-pods/RESULTS.jsonl','FLEET_LIVE_STATUS.json':fleet/'artifacts/live-status.json','COX_CHECKPOINT.json':fleet/'cox-pods/CHECKPOINT_COX_PODS.json','GEE_CHECKPOINT.json':fleet/'gee-pods/CHECKPOINT_GEE_PODS.json','GEE_COLLECTION_STATE.json':root.parent/'dsvert-gee/dsVert/inst/cross-grid-v2/gee-fixed-rho/evidence/r7-fleet/collection-state.json'}
for name,p in inputs.items():shutil.copy2(p,out/name)
rows=[json.loads(x) for x in (out/'FLEET_RESCORED.jsonl').read_text().splitlines()]
metrics=[dict(job_id=r['job_id'],source_commits=r['source_commits'],status=r['status'],seconds=r.get('seconds'),serialized_rpc_bytes=(r.get('bytes') or {}).get('serialized_rpc'),peak_rss_bytes=r.get('peak_rss_bytes'),peak_rss_scope='Unavailable in collected record; not inferred',capacity_pass=r['capacity_pass'],recovery=r.get('recovery')) for r in rows]
(out/'MEASURED_CAPACITY.json').write_text(json.dumps(metrics,indent=2)+'\n')
# Update only scheduling policy; retain per-row computation/source/oracle identities.
p=root/'integrator-evidence/RELEASE_MANIFEST.jsonl'
shutil.copy2(p,out/'RELEASE_MANIFEST_BEFORE.jsonl')
manifest=[json.loads(x) for x in p.read_text().splitlines()]
for r in manifest:
 r['cli']=r['cli'].replace('DSVERT_RELEASE_MAX_RUNTIME_SECONDS=86400','DSVERT_RELEASE_MAX_RUNTIME_SECONDS=604800')
 r['capacity_promotion_gate']=False
p.write_text(''.join(json.dumps(r)+'\n' for r in manifest))
p=root/'integrator-evidence/RELEASE_MANIFEST_STATUS.json';d=json.loads(p.read_text());d.update(lease_seconds=604800,capacity_policy=policy,capacity_scope='Descriptive only: elapsed seconds, serialized-RPC bytes, peak RSS when available; never a promotion gate.',existing_wave_instruction='Harvest existing LMM/GLMM/Cox and GEE waves; do not rerun or duplicate. Per-row source pins remain authoritative; seven-day lease applies only to future launches.')
d['pending_families']={f:'Separate GEE lane: eight-release wave running; promotion evidence pending' for f in ('binomial_gee','poisson_gee')}
p.write_text(json.dumps(d,indent=2)+'\n')
before=[json.loads(x) for x in (out/'RELEASE_MANIFEST_BEFORE.jsonl').read_text().splitlines()]
for a,b in zip(before,manifest):
 for key in a:
  if key not in ('cli','capacity_promotion_gate'):assert a[key]==b[key],key
assert len(manifest)==24 and sum(r['fleet_ready'] for r in manifest)==16
assert all('DSVERT_RELEASE_MAX_RUNTIME_SECONDS=604800' in r['cli'] for r in manifest)
state=dict(cycle=48,observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),promoted_count=4,fleet_terminal=len(rows),fleet_pass=sum(r['status']=='PASS' for r in rows),fleet_fail=sum(r['status']=='FAIL' for r in rows),fleet_running=12,cox_running=4,gee_running=8,capacity_promotion_gate=False,frozen_runs_restarted=0,runtime_changes=False,source_attribution='All results retain original per-job source pins',inputs_sha256={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in inputs})
(out/'progress.json').write_text(json.dumps(state,indent=2)+'\n')
report='''# Cycle48 harvest checkpoint — 2026-09-20

**4/10 promoted**: NB, LASSO, multinomial, ordinal remain Yes at
f3795a2/e748f05. No heavy family yet has all four completed math/lifecycle jobs.
This checkpoint supersedes the stale cycle46 Cox and capacity status below.

Capacity NEVER gates promotion. The 256 GB / 8 h reference remains descriptive;
report measured elapsed seconds, serialized-RPC bytes and peak RSS (unavailable
in the four collected records). Future manifest leases are 604800 seconds;
existing frozen leases and execution sources are untouched.

| Family | Promoted | Current evidence / remaining gate |
|---|---|---|
| nb | Yes | Corrected loss and retained simple evidence; resolved |
| lasso | Yes | Retained simple promotion |
| multinomial | Yes | Retained simple promotion |
| ordinal | Yes | Retained simple promotion |
| lmm | No | K2/K3/K5 baseline PASS; K2 recovery pending |
| binomial_glmm | No | Old-pair recovery FAIL; current wave evidence pending |
| poisson_glmm | No | Four-job math/lifecycle evidence pending |
| cox | No | Fleet-ready; four dedicated releases running, zero results |
| binomial_gee | No | Separate dedicated GEE wave running |
| poisson_gee | No | Separate dedicated GEE wave running |

Fleet harvest: **4 terminal / 12 running**. Re-scored terminal records:
**3 PASS / 1 FAIL**, retaining 502b005/4c6c562 provenance. LMM baseline
K2: **31,727.797 s / 24,009,522,847 RPC bytes**; K3:
**29,890.088 s / 24,030,965,558 bytes**; K5:
**22,774.592 s / 24,036,925,468 bytes**. All three have oracle_equal,
cold and tamper true with exit0; none exercises recovery. K2/K3 capacity-only
FAILs are now PASS without re-execution. The old binomial GLMM recovery remains
FAIL (oracle/cold/tamper/recovery false); no capacity policy can clear it.

Cox wiring is DONE, not a remaining task. Four rows retain the execution pair
c97cd19/28be3cd and N<=400 scope; evidence-only archive 02d7619. Dedicated
controller reports four releases running. No Cox wiring was changed.
GEE dedicated controller reports eight releases running. Its older shared-pool
collector says stopped_requires_review with AssertionError and no releases;
this is retained as separate evidence, not a failure of the dedicated wave.
No completed GEE promotion report was found. GEE-owned files were not edited.

Manifest: 24 definitions, 16 ready (four each LMM, binomial GLMM, Poisson GLMM,
Cox); existing source pins/oracle commitments preserved. Seven-day future lease
and descriptive capacity policy applied. No oracle recomputation or frozen hash
audit. Do not rerun or duplicate active waves. Shared optional-Gaussian handling
remains integration-owned and unchanged; GEE must not fork a sampler fix.
Relay batching stays deferred. No runtime/native/client change, new release,
tag, push or thesis edit.

Validation: seven focused manifest/scoring tests PASS, including over-reference
and missing capacity measurements, preserved source provenance, idempotent
re-scoring, and rejection of missing math/lifecycle proof. Fleet original inputs
remain archived by its finalizer. Resume by harvesting the same result sources
and promoting only complete family/source evidence; do not idle-wait or re-audit.

Evidence: integrator-evidence/cycle48-20260920/{FLEET_RESCORED.jsonl,
MEASURED_CAPACITY.json, FLEET_LIVE_STATUS.json, COX_CHECKPOINT.json,
GEE_CHECKPOINT.json, GEE_COLLECTION_STATE.json, progress.json, tests.log}.
'''
(out/'RESUME.md').write_text(report)
for name in ['STATUS_INTEGRATOR.md','integrator-evidence/PROMOTION_TABLE.md']:
 p=root/name;p.write_text(report+'\n---\n\n'+p.read_text())
for name in ['RELEASE_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json']:shutil.copy2(root/'integrator-evidence'/name,out/name)
shutil.copy2('/tmp/cycle48-tests.log',out/'tests.log')
print(json.dumps(state))
