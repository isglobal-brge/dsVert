"""Detached r6 proof continuation; stop on any unmet gate, never promote."""
import hashlib, json, os, subprocess, sys, time, traceback
from pathlib import Path
root=Path('/workspace/dsvert/gee-fixed-rho-r6')
assert Path.cwd()==root
logs=root/'logs'; logs.mkdir(exist_ok=True)
lane=root/'dsVert/inst/cross-grid-v2/gee-fixed-rho'
env=dict(os.environ, R_LIBS_USER='/workspace/dsvert/gobase/R-library', GOTOOLCHAIN='go1.25.7', GOMAXPROCS='2', GOMEMLIMIT='8GiB', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', NOT_CRAN='true', PROCESSX_NOTIFY_OLD_SIGCHLD='true', DSVERT_GEE_TEST_BINARY=str(root/'dsVert/inst/bin/linux-amd64/dsvert-mpc'))
for key in ('DSVERT_TEST_SYNOPSIS_E2E_FAMILY','DSVERT_TEST_SYNOPSIS_E2E_K'):env.pop(key,None)
state=dict(status='starting',promoted=False,started_unix=time.time(),steps=[],working_correlation=dict(correlation='independence',rho=0),maximum_concurrent_releases=1)
manifest=None; manifest_hash=None
background=[]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(status):
 state.update(status=status,updated_unix=time.time())
 (logs/'continuation-state.json').write_text(json.dumps(state,indent=2)+'\n')
 print(json.dumps(dict(status=status,unix=time.time())),flush=True)
def verify():
 if manifest is None:return
 assert digest(root/'frozen-source-manifest.json')==manifest_hash,'manifest changed'
 for name,expected in manifest['sha256'].items():assert digest(root/name)==expected,name
 assert digest(logs/'structured-oracle.test')==manifest['oracle_sha256']
def start(name,command):
 verify(); record=dict(name=name,command=command,started_unix=time.time())
 output=(logs/(name+'-controller.log')).open('x')
 child=subprocess.Popen(command,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT)
 record.update(pid=child.pid,stdin=os.readlink(f'/proc/{child.pid}/fd/0'))
 state['steps'].append(record);save('running_'+name)
 return child,output,record
def finish(job):
 child,output,record=job;code=child.wait();output.close()
 record.update(exit_code=code,finished_unix=time.time())
 (logs/(record['name']+'-controller.exit')).write_text(str(code)+'\n')
 verify();save('finished_'+record['name'])
 assert code==0,record['name']+' failed; remaining gates not launched'
def run(name,command):finish(start(name,command))
status=1
try:
 run('build-focused',['python3',str(lane/'build-and-focus.py')])
 manifest=json.loads((root/'frozen-source-manifest.json').read_text());manifest_hash=digest(root/'frozen-source-manifest.json')
 state['source_manifest_sha256']=manifest_hash;state['repositories']=manifest['repositories'];verify()
 test_code='pkgload::load_all("dsVertClient",quiet=TRUE); r<-testthat::test_local("dsVert",filter="^(dp-synopsis-exact-downstream|exact-gc-release-policy|exact-gc-transport)$",reporter="summary",stop_on_failure=FALSE); s<-as.data.frame(r); write.csv(s[setdiff(names(s),"result")],"logs/transport-regressions.csv",row.names=FALSE); stopifnot(nrow(s)>0,!anyNA(s[c("failed","error")]),!any(s$failed>0|s$error)); cat("GEE_TRANSPORT_REGRESSIONS_PASS",sum(s$passed),"assertions",sum(s$skipped),"skips",sum(s$warning),"warnings\\n")'
 run('transport-regressions',['Rscript','--vanilla','-e',test_code])
 oracle_dir=logs/'oracle-commitments';oracle_dir.mkdir()
 for family in ('binomial_gee','poisson_gee'):
  run(family+'-oracle-n4',['Rscript','--vanilla',str(lane/'oracle-commitment.R'),str(root),family,str(oracle_dir/(family+'-n4.json')),'4'])
 for family in ('binomial_gee','poisson_gee'):
  background.append(start(family+'-oracle-n2000',['Rscript','--vanilla',str(lane/'oracle-commitment.R'),str(root),family,str(oracle_dir/(family+'-n2000.json'))]))
 for family in ('binomial_gee','poisson_gee'):
  expected=json.loads((oracle_dir/(family+'-n4.json')).read_text())['expected_oracle_sha256']
  run(family+'-n4',['python3',str(lane/'run-release.py'),family,'2','--n','4','--expected-oracle-sha256',expected])
 for job in background:finish(job)
 background=[]
 for package in ('dsVert','dsVertClient'):
  run(package+'-paired',['Rscript','--vanilla',str(root/'dsVert/inst/cross-grid-v2/cycle16/run-paired.R'),str(root),package])
 run('gee-campaign',['python3',str(lane/'run-campaign.py'),'--oracle-records',str(oracle_dir)])
 save('completed_proofs_pending_review');status=0
except BaseException as error:
 state['error']=str(error);traceback.print_exc();save('failed_no_remaining_jobs_launched')
finally:
 for job in background:
  if job[0].poll() is None:job[0].wait()
  job[1].close()
  job[2].update(exit_code=job[0].returncode,finished_unix=time.time())
 (logs/'continuation.exit').write_text(str(status)+'\n')
 (logs/'continuation-state.json').write_text(json.dumps(state,indent=2)+'\n')
sys.exit(status)
