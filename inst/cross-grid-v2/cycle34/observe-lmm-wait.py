import datetime,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1]
remote=r'''import datetime,json,os
from pathlib import Path
anchor=1182464
processes={}
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  stat=(proc/'stat').read_text();parts=stat.split(') ',1)[1].split()
  processes[int(proc.name)]=dict(pid=int(proc.name),parent=int(parts[1]),stat=stat)
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
selected={anchor}
while True:
 new={pid for pid,p in processes.items() if p['parent'] in selected}|selected
 if new==selected:break
 selected=new
rows=[]
for pid in sorted(selected):
 if pid not in processes:continue
 value=processes[pid];proc=Path('/proc')/str(pid)
 for key in ('wchan','stack','syscall','mountinfo'):
  try:
   text=(proc/key).read_text()
   if key=='mountinfo':text='\n'.join(line for line in text.splitlines() if 'fuse' in line or ' /workspace ' in line)
   value[key]=text
  except OSError as e:value[key]=str(e)
 try:
  value['command']=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode()
  value['cwd']=os.readlink(proc/'cwd')
  value['fds']={f.name:os.readlink(f) for f in (proc/'fd').iterdir()}
 except OSError as e:value['read_error']=str(e)
 rows.append(value)
print(json.dumps(dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),processes=rows)))
'''
p=subprocess.run([str(root/'pod4'),'python3 -'],input=remote,text=True,capture_output=True,timeout=55)
assert p.returncode==0,p.stderr
value=json.loads(p.stdout)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
(out/f'LMM_WAIT_{stamp}.json').write_text(json.dumps(value,indent=2)+'\n')
print(json.dumps(value,indent=2))
