"""Retain original computations and verify identical oracle dependencies at final pins."""
import hashlib,json,shutil,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
report=json.loads((out/'manifest/ORACLE_VALIDATION.json').read_text());origin=report['source_commits']
heads={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in origin}
paths={'dsVert':['R','inst/dsvert-mpc','inst/bin','tests/testthat','inst/cross-grid-v2/integrator-validation/structured_integer_oracle.R','inst/cross-grid-v2/integrator-validation/structured_oracle_commitment.R'], 'dsVertClient':['tests/testthat/helper-cox-grid-integer.R']}
checked={}
for repo in origin:
 subprocess.run(['git','-C',str(root/repo),'diff','--exit-code',origin[repo],heads[repo],'--',*paths[repo]],check=True)
 names=subprocess.check_output(['git','-C',str(root/repo),'ls-files','--',*paths[repo]],text=True).splitlines()
 checked[repo]={name:hashlib.sha256((root/repo/name).read_bytes()).hexdigest() for name in names if (root/repo/name).is_file()}
records=out/'manifest/current-pair-oracle-records';records.mkdir()
for p in (out/'manifest/oracle-records').glob('*.json'):
 r=json.loads(p.read_text());assert r['source_commits']==origin
 r['commitment_computation_source_commits']=origin
 r['source_commits']=heads
 r['commitment_validation']='same exact oracle inputs at final pair; see ORACLE_DEPENDENCY_EQUIVALENCE.json; no recomputation claimed'
 (records/p.name).write_text(json.dumps(r,indent=2)+'\n')
(out/'ORACLE_DEPENDENCY_EQUIVALENCE.json').write_text(json.dumps(dict(computed_at=origin,verified_at=heads,dependency_sha256=checked,scope='All server R, native code/runtimes, test helpers and oracle harness unchanged; client oracle only sources helper-cox-grid-integer.R. Newly added Cox client release helpers are not loaded by this oracle.'),indent=2)+'\n')
prior=out/'prior-manifests';prior.mkdir(exist_ok=True)
for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json'):
 shutil.copy2(root/'integrator-evidence'/name,prior/name)
subprocess.run(['python3',str(root/'dsVert/inst/cross-grid-v2/integrator-validation/generate-release-manifest.py'),'--oracle-records',str(records)],check=True)
real=[json.loads(l) for l in (root/'integrator-evidence/RELEASE_MANIFEST.jsonl').read_text().splitlines()]
assert len(real)==24 and sum(r['fleet_ready'] for r in real)==12
assert all(r['capacity_seconds']==28800 and r['capacity_bytes']==256000000000 and r['source_commits']==heads for r in real)
for family in {r['family'] for r in real}:
 assert sorted((r['K'],r['mode']) for r in real if r['family']==family)==[(2,'baseline'),(2,'recovery'),(3,'baseline'),(5,'baseline')]
status=root/'integrator-evidence/RELEASE_MANIFEST_STATUS.json';s=json.loads(status.read_text())
s['existing_wave_instruction']='Do not rerun LMM/GLMM heavy wave; harvest and rescore original-pair records under release-capacity.json. Current-pair ready entries describe available paths, not authorization for duplicate releases.'
s['oracle_commitment_provenance']='cycle43-20260920/ORACLE_DEPENDENCY_EQUIVALENCE.json'
s['capacity_policy']=json.loads((root/'dsVert/inst/cross-grid-v2/integrator-validation/release-capacity.json').read_text())
status.write_text(json.dumps(s,indent=2)+'\n')
(out/'MANIFEST_VALIDATION.json').write_text(json.dumps(dict(source_commits=heads,real_jobs=24,ready_jobs=12,oracle_jobs=1080,capacity_seconds=28800,oracle_computed_at=origin,oracle_equivalence='ORACLE_DEPENDENCY_EQUIVALENCE.json',sha256={name:hashlib.sha256((root/'integrator-evidence'/name).read_bytes()).hexdigest() for name in ('RELEASE_MANIFEST.jsonl','SELECTION_MANIFEST.jsonl','RELEASE_MANIFEST_STATUS.json')}),indent=2)+'\n')
print(json.dumps(heads))
