import datetime,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
remote=r'''import datetime,json,os
from pathlib import Path
root=Path('/workspace/dsvert-simple-paired-cycle21')
launch=json.loads((root/'logs/dsVertClient-paired.launch.json').read_text())
p=Path('/proc')/str(launch['pid'])
log=root/'logs/dsVertClient-paired.log'
r=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),launch=launch,log_size=log.stat().st_size,log_mtime_utc=datetime.datetime.fromtimestamp(log.stat().st_mtime,datetime.timezone.utc).isoformat(),completed=(root/'logs/dsVertClient-paired.exit').is_file())
if p.exists():
 r.update(command=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(),cwd=os.readlink(p/'cwd'),stat=(p/'stat').read_text(),wait_channel=(p/'wchan').read_text())
 r['children']=[]
 for proc in Path('/proc').iterdir():
  if not proc.name.isdigit():continue
  try:
   stat=(proc/'stat').read_text()
   if int(stat.split(') ',1)[1].split()[1])==launch['pid']:
    r['children'].append(dict(pid=int(proc.name),stat=stat,command=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode()))
  except (FileNotFoundError,PermissionError,ProcessLookupError):pass
print(json.dumps(r))
'''
p=subprocess.run([str(root.parent/'dsvert-fleet/pod13'),'python3 -'],input=remote,text=True,capture_output=True,timeout=60)
assert p.returncode==0,p.stderr
r=json.loads(p.stdout);(out/'SIMPLE_PAIRED_HEALTH.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
