import hashlib,json,shutil
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
harvest=json.loads((out/'LMM_HARVEST.json').read_text());capture=root/'integrator-evidence/cycle16-20260920'/harvest['capture']
dst=out/'frozen-lmm-k2';dst.mkdir(exist_ok=True)
for name in ('lmm-n2000-k2-baseline.exit','lmm-n2000-k2-baseline-resources.json','lmm-n2000-k2-baseline-metrics.json','lmm-n2000-k2-baseline.log'):
 p=capture/name;assert hashlib.sha256(p.read_bytes()).hexdigest()==harvest['files'][name]['sha256'];shutil.copy2(p,dst/name)
r=json.loads((dst/'lmm-n2000-k2-baseline-resources.json').read_text());m=r['release_metrics'];log=(dst/'lmm-n2000-k2-baseline.log').read_text()
assert r['process_exit_code']==0 and all(r['markers'].values())
assert all(marker in log for marker in r['markers'])
assert r['exit_code']==1 and not r['capacity_gate']['passed'] and m['recovery']=='not_exercised'
record=dict(source_commits=harvest['source']['repositories'],observed_utc=harvest['observed_utc'],family='lmm',n=m['n'],K=m['owners'],epsilon=m['epsilon'],oracle_equal=True,cold=True,tamper=True,recovery_exercised=False,process_exit_code=r['process_exit_code'],gate_exit_code=r['exit_code'],capacity=r['capacity_gate'],native_unique_payload_bytes=m['protocol_payload']['exact_gc_unique_payload_bytes'],max_child_rss_kib_linux=r['max_child_rss_kib_linux'],source_files_verified=harvest['source']['files'],source_mismatches=harvest['source']['mismatches'],raw_evidence='frozen-lmm-k2/',controller=harvest['controller'],sequence_exit=harvest['sequence_exit'],sequence_progress=harvest['progress'],scope='Completed OLD-pair K2 release; stale outer sequence progress is not a running K2 release. No source attribution to cycle42 and no controller mutation.')
(out/'CAPACITY_LMM_FROZEN_K2.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
