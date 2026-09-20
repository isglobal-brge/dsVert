"""Read-only reconciliation of collected fleet lifecycle evidence."""
import datetime, hashlib, json, subprocess
from pathlib import Path
out=Path(__file__).resolve().parent
root=out.parents[1]
fleet=root.parent/'dsvert-fleet'
proof=json.loads((fleet/'fleet2-artifacts/provenance.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
archives={name:sha(fleet/'fleet2-artifacts'/name)==digest for name,digest in proof['sha256'].items()}
rows=[]
for path in sorted((out.parent/'cycle26-20260920/fleet-final').glob('pod*/fleet-simple/RESULTS.jsonl')):
 for line in path.read_text().splitlines():
  r=json.loads(line)
  family=r['family'];prefix={'nb':'NB','lasso':'LASSO','multinomial':'CATEGORICAL','ordinal':'CATEGORICAL'}[family]
  harness={'nb':'nb','lasso':'lasso','multinomial':'categorical','ordinal':'categorical'}[family]
  hpath=f'inst/cross-grid-v2/integrator-validation/validate_{harness}_dslite.R'
  original=subprocess.check_output(['git','-C',str(root/'dsVert'),'show',proof['server_commit']+':'+hpath])
  log=path.parent/(r['cell_id']+'.log'); text=log.read_text()
  instrumented=path.parent/(r['cell_id']+'.instrumented.R')
  checks=dict(source_pair=proof['server_commit'].startswith(r['server_commit']) and proof['client_commit'].startswith(r['client_commit']),
   harness=hashlib.sha256(original).hexdigest()==r['harness_sha256'],
   instrumented_harness=sha(instrumented)==r['instrumented_harness_sha256'],
   oracle_sticky_tamper=f'DSLITE_{prefix}_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED' in text,
   cold_tamper='DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED' in text,
   recovery='DSLITE_INTERRUPTED_AFTER_DURABLE_BATCHES' in text and r['recovery_marker'] is True,
   capacity=r['capacity_metrics']['end_to_end_serialized_rpc_bytes']<=256000000000 and r['capacity_metrics']['end_to_end_release_elapsed']<=21600,
   shape=(r['n'],r['p'],r['grid'])==(2000,6,2), exit_zero=r['returncode']==0)
  rows.append(dict(family=family,epsilon=r['epsilon'],K=r['K'],cell_id=r['cell_id'],checks=checks,passed=all(checks.values()),
   record=r,log_sha256=sha(log),result_file_sha256=sha(path),result_file=str(path)))
summary={}
for family in ('nb','lasso','multinomial','ordinal'):
 cells=[r for r in rows if r['family']==family]
 summary[family]=dict(passed_cells=sum(r['passed'] for r in cells),epsilon8_passed_topologies=sorted(r['K'] for r in cells if r['epsilon']==8 and r['passed']),
  promoted=False,paired_gate='No completed full paired-suite evidence found for fleet source pair; must close or document applicable source equivalence before promotion.')
report=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_provenance=proof,archives_verified=archives,rows=rows,families=summary,
 scope='Read-only reconciliation of retained local fleet captures; no releases launched. Source archives/harness hashes checked; not a live remote source rehash. Recovery is simple durable-batch recovery, not heavy PREPARE/COMMIT.')
(out/'SIMPLE_RECONCILIATION.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(archives=archives,families=summary,failed_checks=[r['cell_id'] for r in rows if not r['passed']]),indent=2))
