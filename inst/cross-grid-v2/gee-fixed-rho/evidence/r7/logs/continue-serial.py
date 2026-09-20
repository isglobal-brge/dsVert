"""Detached r7 proof continuation; stop on any unmet gate, never promote."""
import hashlib, json, os, shutil, subprocess, sys, time, traceback
from pathlib import Path
root=Path('/workspace/dsvert/gee-fixed-rho-r7')
prior=Path('/workspace/dsvert/gee-fixed-rho-r6')
assert Path.cwd()==root
logs=root/'logs'; logs.mkdir(exist_ok=True)
lane=root/'dsVert/inst/cross-grid-v2/gee-fixed-rho'
env=dict(os.environ, R_LIBS_USER='/workspace/dsvert/gobase/R-library', GOTOOLCHAIN='go1.25.7', GOMAXPROCS='2', GOMEMLIMIT='8GiB', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', NOT_CRAN='true', PROCESSX_NOTIFY_OLD_SIGCHLD='true', DSVERT_GEE_TEST_BINARY=str(root/'dsVert/inst/bin/linux-amd64/dsvert-mpc'))
for key in ('DSVERT_TEST_SYNOPSIS_E2E_FAMILY','DSVERT_TEST_SYNOPSIS_E2E_K'):env.pop(key,None)
state=dict(status='starting',promoted=False,started_unix=time.time(),steps=[],working_correlation=dict(correlation='independence',rho=0),maximum_concurrent_releases=1,sampler_execution_coordinates=16,fresh_synthetic_proof_identity=True,prior_identity_migrated=False)
manifest=None; manifest_hash=None

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
def run(name,command,cwd=root):
 verify(); record=dict(name=name,command=command,started_unix=time.time())
 with (logs/(name+'.log')).open('x') as output:
  child=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT)
  record.update(pid=child.pid,stdin=os.readlink(f'/proc/{child.pid}/fd/0'))
  state['steps'].append(record);save('running_'+name)
  code=child.wait()
 record.update(exit_code=code,finished_unix=time.time())
 (logs/(name+'.exit')).write_text(str(code)+'\n')
 verify();save('finished_'+name)
 assert code==0,name+' failed; remaining gates not launched'
status=1
try:
 native_dir=root/'dsVert/inst/dsvert-mpc'
 run('runtime-build',['make','all'],native_dir)
 run('oracle-build',['go','test','-c','-tags','grouped_reference_test,dsvert_family_reference','-o',str(logs/'structured-oracle.test'),'.'],native_dir)
 oracle_build=root/'dsVert/inst/cross-grid-v2/build';oracle_build.mkdir(exist_ok=True)
 shutil.copy2(logs/'structured-oracle.test',oracle_build/'cross-grid-oracle.test')
 files=sorted(p for package in ('dsVert','dsVertClient') for p in (root/package).rglob('*') if p.is_file())
 manifest=dict(repositories=json.loads((root/'base-commits.json').read_text()),sha256={str(p.relative_to(root)):digest(p) for p in files},oracle_sha256=digest(logs/'structured-oracle.test'),go_toolchain='go1.25.7')
 (root/'frozen-source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 manifest_hash=digest(root/'frozen-source-manifest.json')
 state.update(source_manifest_sha256=manifest_hash,repositories=manifest['repositories']);verify()
 assert digest(prior/'frozen-source-manifest.json')=='d41a66b168b424e78da3134eb14462e24cb4b5454981ec8c20f18b852500201c','prior trusted evidence changed'
 assert digest(prior/'logs/gee-native-focused.log')=='bed1e242d84b00803eebf94d25beae26a1e967a35e3fae744c6684575785a961','prior trusted evidence changed'
 assert digest(prior/'logs/gee-native-focused.exit')=='9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa','prior trusted evidence changed'
 previous=json.loads((prior/'frozen-source-manifest.json').read_text())
 def native_names(m):return {n for n in m['sha256'] if n.startswith('dsVert/inst/dsvert-mpc/') and n.endswith(('.go','/go.mod','/go.sum'))}
 names=native_names(manifest)
 assert names and names==native_names(previous),'native file set changed'
 for name in sorted(names):assert manifest['sha256'][name]==previous['sha256'][name]==digest(prior/name),name
 assert (prior/'logs/gee-native-focused.exit').read_text().strip()=='0'
 runtime='dsVert/inst/bin/linux-amd64/dsvert-mpc'
 assert manifest['sha256'][runtime]==previous['sha256'][runtime]==digest(prior/runtime)
 assert previous['oracle_sha256']==digest(prior/'logs/structured-oracle.test')
 state['native_reuse']=dict(snapshot=str(prior),manifest_sha256=digest(prior/'frozen-source-manifest.json'),matching_source_files=len(names),native_test_log_sha256=digest(prior/'logs/gee-native-focused.log'),native_test_exit_code=0,runtime_sha256=manifest['sha256'][runtime],oracle_sha256=manifest['oracle_sha256'],prior_oracle_sha256=previous['oracle_sha256'],oracle_rebuilt_from_identical_native_inputs=True)
 (logs/'native-reuse.json').write_text(json.dumps(state['native_reuse'],indent=2)+'\n')
 run('gee-r-focused',['Rscript','--vanilla',str(lane/'run-focused.R'),str(root)])
 test_code='pkgload::load_all("dsVertClient",quiet=TRUE); r<-testthat::test_local("dsVert",filter="^(dp-synopsis-exact-downstream|exact-gc-release-policy|exact-gc-transport)$",reporter="summary",stop_on_failure=FALSE); s<-as.data.frame(r); write.csv(s[setdiff(names(s),"result")],"logs/transport-regressions.csv",row.names=FALSE); stopifnot(nrow(s)>0,!anyNA(s[c("failed","error")]),!any(s$failed>0|s$error)); cat("GEE_TRANSPORT_REGRESSIONS_PASS",sum(s$passed),"assertions",sum(s$skipped),"skips",sum(s$warning),"warnings\\n")'
 run('transport-regressions',['Rscript','--vanilla','-e',test_code])
 oracle_dir=logs/'oracle-commitments';oracle_dir.mkdir()
 reused=[]
 oracle_record_hashes={'binomial_gee-n2000.json': '5e3f983d6166c492772e30766611598b462c94061731012f61f4b171eb55e6fc', 'binomial_gee-n4.json': 'e191e6211ffdb75b512bedb00202b813272f34891485c211df31e3886dbf835f', 'poisson_gee-n2000.json': 'b1de1e4862fc3f514afe262122eef4e6a255168e5d0e1ba0fcf44de2bd0bd939', 'poisson_gee-n4.json': '3dcadada291462800ffb4fb1e5727bc31d15e9cb3bd4f467e4aa1068355debae'}
 for family in ('binomial_gee','poisson_gee'):
  for n in (4,2000):
   path=prior/'logs/oracle-commitments'/(family+'-n'+str(n)+'.json');record=json.loads(path.read_text())
   assert digest(path)==oracle_record_hashes[path.name],'prior oracle commitment changed'
   assert record['family']==family and record['n']==n and record['working_correlation']['correlation']=='independence' and record['working_correlation']['rho']==0
   for name,expected in record['source_file_sha256'].items():assert digest(root/name)==expected,name
   assert record['oracle_program_sha256']==digest(lane/'oracle-commitment.R')
   shutil.copy2(path,oracle_dir/path.name)
   reused.append(dict(path=str(path),sha256=digest(path),dependency_hashes_match=True,expected_oracle_sha256=record['expected_oracle_sha256']))
 (logs/'oracle-reuse.json').write_text(json.dumps(reused,indent=2)+'\n')
 for family in ('binomial_gee','poisson_gee'):
  expected=json.loads((oracle_dir/(family+'-n4.json')).read_text())['expected_oracle_sha256']
  run(family+'-n4',['python3',str(lane/'run-release.py'),family,'2','--n','4','--expected-oracle-sha256',expected])
 for package in ('dsVert','dsVertClient'):
  run(package+'-paired',['Rscript','--vanilla',str(root/'dsVert/inst/cross-grid-v2/cycle16/run-paired.R'),str(root),package])
 run('gee-campaign',['python3',str(lane/'run-campaign.py'),'--oracle-records',str(oracle_dir),'--native-evidence-root',str(prior)])
 save('completed_proofs_pending_review');status=0
except BaseException as error:
 state['error']=str(error);traceback.print_exc();save('failed_no_remaining_jobs_launched')
finally:
 (logs/'continuation.exit').write_text(str(status)+'\n')
 (logs/'continuation-state.json').write_text(json.dumps(state,indent=2)+'\n')
sys.exit(status)
