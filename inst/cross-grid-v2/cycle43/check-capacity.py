import importlib.util,json
from pathlib import Path
root=Path(__file__).resolve().parents[2]
p=root/'dsVert/inst/cross-grid-v2/integrator-validation'
spec=importlib.util.spec_from_file_location('rescore',p/'rescore-release-capacity.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
policy=json.loads((p/'release-capacity.json').read_text())
base=dict(mode='baseline',returncode=0,oracle_equal=True,cold=True,tamper=True,metrics=dict(end_to_end_serialized_rpc_bytes=256000000000,end_to_end_release_elapsed=28800),source_commits={'dsVert':'frozen'})
assert m.rescore(base,policy)['status']=='PASS'
for field,value in [('end_to_end_serialized_rpc_bytes',256000000001),('end_to_end_release_elapsed',28800.001),('end_to_end_release_elapsed',None),('end_to_end_release_elapsed',float('nan')),('end_to_end_release_elapsed',-1)]:
 r=dict(base,metrics=dict(base['metrics'],**{field:value}));assert not m.rescore(r,policy)['capacity_pass']
for field,value in [('oracle_equal',False),('cold',False),('tamper',False),('returncode',1),('mode','recovery')]:
 assert m.rescore(dict(base,**{field:value}),policy)['status']=='FAIL'
assert m.rescore(dict(base,mode='recovery',recovery=True),policy)['status']=='PASS'
assert m.rescore(base,policy)['source_commits']==base['source_commits']
assert 'capacity_pass' not in base
scored=m.rescore(dict(base,status='FAIL',capacity_pass=False),policy)
assert m.rescore(scored,policy)['original_scoring']==scored['original_scoring']
print('PASS capacity boundaries, missing/nonfinite measurements, lifecycle and recovery gates, immutable source pins')
