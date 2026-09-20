import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
files=[out/'test-dp-cox-cross-public-evidence.R.csv',out/'final/test-dp-cox-grid-cross.R.csv',out/'final/test-dp-cox-catalog-draft.R.csv']+list((out/'regression').glob('*.csv'))
rows=[]
for p in files:
 r=list(csv.DictReader(p.open()));assert r and all(x['failed']=='0' and x['error']=='FALSE' and x['warning']=='0' and x['skipped']=='FALSE' for x in r),str(p)
 rows+=r
heads={repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}
m=json.loads((out/'proof-r3/source-manifest.json').read_text())
for n,h in m['sha256'].items():
 if '/R/' in n or '/tests/' in n: assert hashlib.sha256((root/n).read_bytes()).hexdigest()==h,n
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits=heads,tests=len(rows),assertions=sum(int(x['passed']) for x in rows),failures=0,errors=0,warnings=0,skips=0,coverage=[str(p.relative_to(out)) for p in files],snapshots=json.loads((out/'SNAPSHOT_VERIFICATION.json').read_text()),scope='Cox K2/K3/K5 real signed draft parsing, preflight tamper/owner rejection, existing Cox contract/reader, catalog and GLM/LMM regressions; no complete Cox source sharing or DP release',retained_failures='proof-r1/r2 assertions compared uncanonicalized list order; final.log broader mock lookup needed explicit testthat package. Production code unchanged across all fixed snapshots. Baseline prior code rejects the valid signed Cox draft.',shared_dp='Optional Gaussian certified-support gap remains live; certified Laplace fallback regression passes. Shared sampler unchanged and owned here; GEE lane must not fork a fix.')
(out/'R_PROOF.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k] for k in ('source_commits','tests','assertions')},indent=2))
