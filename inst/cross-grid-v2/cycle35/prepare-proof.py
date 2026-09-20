import hashlib,json,subprocess,sys
from pathlib import Path
out=Path(__file__).resolve().parent; root=out.parents[1]; snap=out/sys.argv[1]
snap.mkdir()
files={}
for repo in ('dsVert','dsVertClient'):
 for name in subprocess.check_output(['git','-C',str(root/repo),'ls-files'],text=True).splitlines():
  src=root/repo/name
  if not src.is_file(): continue
  dst=snap/repo/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes());dst.chmod(src.stat().st_mode)
  files[repo+'/'+name]=hashlib.sha256(dst.read_bytes()).hexdigest()
(snap/'source-manifest.json').write_text(json.dumps({'sha256':files,'base_commits':{repo:subprocess.check_output(['git','-C',str(root/repo),'rev-parse','HEAD'],text=True).strip() for repo in ('dsVert','dsVertClient')}},indent=2)+'\n')
print(len(files))
