import concurrent.futures,hashlib,json,os,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent; root=base.parents[1]
out=base/'manifest'; out.mkdir()
records=out/'oracle-records'; records.mkdir(exist_ok=True)
heads={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}
for repo in heads: subprocess.run(['git','-C',str(root/repo),'diff','--quiet','HEAD','--'],check=True)
def run(family):
 for k in (2,3,5):
  target=records/f'{family}-k{k}.json'
  assert not target.exists()
  command=['Rscript','--vanilla',str(root/'dsVert/inst/cross-grid-v2/integrator-validation/structured_oracle_commitment.R'),str(root),family,str(k),str(target)]
  with (out/f'oracle-{family}-k{k}.log').open('x') as log:
   subprocess.run(command,cwd=root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,check=True)
  r=json.loads(target.read_text());assert r['source_commits']==heads
  digest=hashlib.sha256(('\n'.join([str(r['n'])]+r['exact'])+'\n').encode()).hexdigest()
  assert r['expected_oracle_sha256']==digest
  old=json.loads((root/'integrator-evidence/cycle19-20260920/oracle-records'/target.name).read_text())
  assert digest==old['expected_oracle_sha256']
 return family
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 for family in pool.map(run,('lmm','binomial_glmm','poisson_glmm')): print(family,'all three commitments equal previous exact integers',flush=True)
(out/'ORACLE_VALIDATION.json').write_text(json.dumps(dict(source_commits=heads,records=9,all_equal_previous_exact=True,scope='Independent signed synthetic exact integers; no real releases, noise or selection reliability campaign'),indent=2)+'\n')
