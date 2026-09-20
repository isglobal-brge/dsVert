import base64,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
remote=r'''import base64,hashlib,json
from pathlib import Path
root=Path('/workspace/dsvert-simple-paired-cycle21')
files={}
for name in ('paired-analysis.json','paired-results.json','paired-harvest-verification.json','paired-harvest-sha256.json','dsVertClient-paired.log','dsVertClient-paired.csv','dsVertClient-paired.resources.json','dsVertClient-paired.exit'):
 p=root/'logs'/name;b=p.read_bytes();files[name]={'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()}
print(json.dumps(files))'''
p=subprocess.run([str(root.parent/'dsvert-fleet/pod13'),'python3 -'],input=remote,text=True,capture_output=True,check=True,timeout=60)
files=json.loads(p.stdout);dest=out/'simple-paired';dest.mkdir(exist_ok=True)
for name,r in files.items():
 b=base64.b64decode(r['base64']);assert hashlib.sha256(b).hexdigest()==r['sha256'];(dest/name).write_bytes(b)
analysis=json.loads((dest/'paired-analysis.json').read_text());t=analysis['dsVertClient']['totals']
assert t['passed']==33908 and t['failed']==t['error']==t['warning']==0 and t['skipped']==5
assert (dest/'dsVertClient-paired.exit').read_text().strip()=='0'
verified=json.loads((dest/'paired-harvest-verification.json').read_text());assert verified['source_changed']==[] and verified['source_files_checked']==2504
report=dict(source_pair='f3795a2/e748f05',client=analysis['dsVertClient'],server=analysis['dsVert'],source_verification=verified,raw_sha256={n:r['sha256'] for n,r in files.items()},additional_module_skip='test-dslite-glm.R:19: DSLite mock missing dsVert PSI methods; not represented in test-level RDS rows',review='No family-specific client defect reported. Five skips retain explicitly untested source-only/installed-tree/reference/optional Gaussian LASSO scopes. Confirmatory evidence, not a zero-skip claim or replacement of generic v1.2.0 validation.')
(out/'SIMPLE_PAIRED_CONFIRMATION.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(client_tests=1150,passed=33908,skips=5,source_files=2504)))
