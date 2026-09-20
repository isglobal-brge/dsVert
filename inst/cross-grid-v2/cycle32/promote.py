"""Record source-pinned simple promotions under David's cycle32 G/H decision."""
import datetime, hashlib, json
from pathlib import Path
out=Path(__file__).resolve().parent
root=out.parents[1]
x=json.loads((out/'SIMPLE_RECONCILIATION.json').read_text())
nb=json.loads((out/'NB_PROOF.json').read_text())
paired=json.loads((out/'SIMPLE_PAIRED.json').read_text())
assert all(x['archives_verified'].values())
assert nb['exit_code']==0 and nb['old_expression_control_exit']==1
assert nb['fixed_expression_losses']==[117694,173378] and not nb['frozen_source_changed']
assert not paired['verification']['source_changed']
server=paired['analysis']['dsVert']
assert server['tests']==1164 and server['totals']['passed']==21062 and not server['nonpass']
rows=[]
for family in ('nb','lasso','multinomial','ordinal'):
 cells=[r for r in x['rows'] if r['family']==family]
 assert len(cells)==9 and all(r['passed'] for r in cells)
 assert sorted((r['epsilon'],r['K']) for r in cells)==[(e,k) for e in (1,4,8) for k in (2,3,5)]
 row=dict(family=family,promoted=True,source_commits={'dsVert':x['source_provenance']['server_commit'],'dsVertClient':x['source_provenance']['client_commit']},n=2000,p=6,grid=2,epsilon=[1,4,8],K=[2,3,5],oracle_equal_cells=9,lifecycle='sticky replay, durable-batch recovery, direct R cold replay, source/certificate tamper rejection',server_paired='1164 tests / 21062 assertions PASS',client_validation='Generic v1.2.0/v1.2.1 exported-client validation accepted by David in cycle32 G; per-family client suite confirmatory and pending',evidence='cycle32-20260920/SIMPLE_RECONCILIATION.json',cell_ids=[r['cell_id'] for r in cells],max_serialized_rpc_bytes=max(r['record']['capacity_metrics']['end_to_end_serialized_rpc_bytes'] for r in cells),max_release_elapsed_seconds=max(r['record']['capacity_metrics']['end_to_end_release_elapsed'] for r in cells),execution_requested=False)
 if family=='nb':row['math_resolution']='cycle32-20260920/NB_PROOF.json; corrected assembly present before all nine fleet releases'
 rows.append(row)
 x['families'][family].update(promoted=True,paired_gate=row['client_validation'])
(out/'SIMPLE_RECONCILIATION.json').write_text(json.dumps(x,indent=2)+'\n')
(root/'integrator-evidence/PROMOTION_MANIFEST.jsonl').write_text(''.join(json.dumps(r,separators=(',',':'))+'\n' for r in rows))
report=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),promoted_count=4,families=rows,scope='Completed evidence records, not fleet launch jobs. Existing 24-job heavy RELEASE_MANIFEST.jsonl remains unchanged.',sha256={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ('SIMPLE_RECONCILIATION.json','SIMPLE_PAIRED.json','NB_PROOF.json')})
(out/'PROMOTIONS.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'promoted_count':4,'families':[r['family'] for r in rows]},indent=2))
