import datetime,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
remote=r'''import datetime,json,os
from pathlib import Path
root=Path('/workspace/dsvert/executor-cycle16-lmm-release-r2')
rows=[]
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  cwd=os.readlink(proc/'cwd')
  if not cwd.startswith(str(root)):continue
  rows.append(dict(pid=int(proc.name),cwd=cwd,stat=(proc/'stat').read_text(),command=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(),wchan=(proc/'wchan').read_text()))
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
logs={p.name:dict(size=p.stat().st_size,mtime_utc=datetime.datetime.fromtimestamp(p.stat().st_mtime,datetime.timezone.utc).isoformat()) for p in (root/'logs').iterdir() if p.is_file()}
print(json.dumps(dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),processes=rows,logs=logs)))
'''
p=subprocess.run([str(root/'pod4'),'python3 -'],input=remote,text=True,capture_output=True,timeout=55)
assert p.returncode==0,p.stderr
value=json.loads(p.stdout)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
(out/f'LMM_HEALTH_{stamp}.json').write_text(json.dumps(value,indent=2)+'\n')
print(json.dumps(value,indent=2))
