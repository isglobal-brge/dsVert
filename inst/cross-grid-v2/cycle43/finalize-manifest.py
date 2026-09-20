"""Record source-pinned proof and minimal release manifest, without promotion."""
import collections, datetime, hashlib, json, subprocess
from pathlib import Path
out=Path(__file__).resolve().parent; root=out.parents[1]; base=out.parent
heads={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}
oracle=json.loads((out/'manifest/ORACLE_VALIDATION.json').read_text())
assert oracle['source_commits']==heads and oracle['records']==9 and oracle['all_equal_previous_exact']
prior=out/'prior-manifests'; prior.mkdir(exist_ok=True)
for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json'):
    target=prior/name
    if not target.exists(): target.write_bytes((base/name).read_bytes())
subprocess.run(['python3',str(root/'dsVert/inst/cross-grid-v2/integrator-validation/generate-release-manifest.py'),'--oracle-records',str(out/'manifest/oracle-records')],check=True)
real=[json.loads(x) for x in (base/'RELEASE_MANIFEST.jsonl').read_text().splitlines()]
selection=[json.loads(x) for x in (base/'SELECTION_MANIFEST.jsonl').read_text().splitlines()]
assert len(real)==24 and len(selection)==1080
for family in {r['family'] for r in real}:
    jobs=[r for r in real if r['family']==family]
    assert len(jobs)==4 and all(r['epsilon']==8 for r in jobs)
    assert sorted((r['K'],r['mode']) for r in jobs)==[(2,'baseline'),(2,'recovery'),(3,'baseline'),(5,'baseline')]
    assert sum(r['capacity_measurement'] for r in jobs)==1
assert all(r['source_commits']==heads for r in real+selection)
assert all(not r['real_authenticated_release_required'] for r in selection)
report=dict(source_commits=heads,real_jobs=len(real),oracle_jobs=len(selection),ready_real_jobs=sum(r['fleet_ready'] for r in real),per_family_real_jobs=dict(collections.Counter(r['family'] for r in real)),sha256={n:hashlib.sha256((base/n).read_bytes()).hexdigest() for n in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json')})
assert report['ready_real_jobs']==12
(out/'MANIFEST_VALIDATION.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
