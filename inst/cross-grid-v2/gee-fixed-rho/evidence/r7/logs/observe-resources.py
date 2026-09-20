import json,time
from pathlib import Path
root=Path("/workspace/dsvert/gee-fixed-rho-r7")
controller=2957748
initial=Path(f"/proc/{controller}/stat").read_text().split()[21]
out=(root/"logs/resource-observations.jsonl").open("x")
while True:
 try:
  if Path(f"/proc/{controller}/stat").read_text().split()[21]!=initial:break
 except FileNotFoundError:break
 rows={}
 for p in Path("/proc").iterdir():
  if not p.name.isdigit():continue
  try:
   fields={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in (p/"status").read_text().splitlines()}
   stat=(p/"stat").read_text().split()
   rows[int(p.name)]={"pid":int(p.name),"ppid":int(fields["PPid"]),"name":fields["Name"],"rss_kib":int(fields.get("VmRSS","0 kB").split()[0]),"hwm_kib":int(fields.get("VmHWM","0 kB").split()[0]),"user_ticks":int(stat[13]),"system_ticks":int(stat[14])}
  except (FileNotFoundError,ProcessLookupError,PermissionError):pass
 selected={controller};changed=True
 while changed:
  found={pid for pid,row in rows.items() if row["ppid"] in selected}
  changed=not found.issubset(selected);selected.update(found)
 cg=Path("/sys/fs/cgroup/memory")
 observation={"unix":time.time(),"controller_pid":controller,"processes":[rows[pid] for pid in sorted(selected) if pid in rows]}
 for name in ("memory.usage_in_bytes","memory.limit_in_bytes","memory.max_usage_in_bytes","memory.oom_control"):
  path=cg/name
  if path.exists():observation[name]=path.read_text().strip()
 out.write(json.dumps(observation)+"\n");out.flush();time.sleep(10)
out.close()
