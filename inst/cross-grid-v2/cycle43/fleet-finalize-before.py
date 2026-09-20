"""Render collected evidence without interpreting absent checks as successful."""
import json,pathlib,re,datetime
root=pathlib.Path(__file__).resolve().parent
rows=[json.loads(l) for l in (root/'RESULTS.jsonl').read_text().splitlines() if l]
for r in rows:
 p=pathlib.Path(r.get('local_log','/nonexistent'))
 t=p.read_text(errors='replace') if p.is_file() else ''
 r['oracle_check_reached']='DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED' in t
 if r['status']=='FAIL':
  if 'fixed-work Gaussian table is outside the certified support' in t:r['failure_reason']='Discrete-Gaussian plan unavailable: fixed-work Gaussian table is outside certified support.'
  elif r.get('returncode')==0 and r.get('capacity_pass') is False:
   exceeded=[]
   if r.get('seconds') is not None and r['seconds']>21600:exceeded.append(f"release duration {r['seconds']} seconds exceeds 21600 seconds")
   rpc=(r.get('bytes') or {}).get('serialized_rpc')
   if rpc is not None and rpc>256000000000:exceeded.append(f"serialized RPC {rpc} bytes exceeds 256000000000 bytes")
   r['failure_reason']='Capacity gate: '+('; '.join(exceeded) if exceeded else 'required measurements unavailable')+'.'
  else:
   errors=[l for l in t.splitlines() if l.startswith(('Error','! '))];r['failure_reason']=errors[-1] if errors else r.get('error','See preserved harness log.')
(root/'RESULTS.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
pins=json.loads((root/'artifacts/pins.json').read_text())
expected=len((root/'artifacts/dispatched-manifest.jsonl').read_text().splitlines())
lines=['# HEAVY release results','',f'Collected {len(rows)}/{expected} ready job results: {sum(r["status"]=="PASS" for r in rows)} PASS, {sum(r["status"]=="FAIL" for r in rows)} FAIL.', '',f'Server `{pins["dsVert"]}`; client `{pins["dsVertClient"]}`. Exact committed archives; packaged binary and harness hashes verified. One real release per pod; 86400s maximum / 900s idle leases; private state `/var/lib/dsvert-heavy-state/<job>`.', '', '| Family | ε | K | Mode | Pod | Oracle | Recovery | Cold | Tamper | Native bytes | RPC bytes | Release s | Wall s | Result |', '|---|---:|---:|---|---|---|---|---|---|---|---:|---:|---:|---|']
for r in sorted(rows,key=lambda x:(x['family'],x['K'],x['mode'])):
 m=r.get('metrics') or {};b=r.get('bytes') or {};check=lambda v:'PASS' if v else 'not verified'
 native=json.dumps(b['native']) if b.get('native') is not None else 'unavailable'
 vals=[r['family'],r['epsilon'],r['K'],r['mode'],r['pod'],check(r.get('oracle_equal')),check(r.get('recovery')) if r['mode']=='recovery' else 'not requested',check(r.get('cold')),check(r.get('tamper')),native,b.get('serialized_rpc') if b.get('serialized_rpc') is not None else 'unavailable',round(r['seconds'],2) if r.get('seconds') is not None else 'unavailable',round(r['wall_seconds'],2) if r.get('wall_seconds') is not None else 'unavailable',r['status']]
 lines.append('| '+' | '.join(map(str,vals))+' |')
lines+=['','Failures before the final oracle/lifecycle checks leave those checks unverified; they do not establish an oracle mismatch. Missing native/RPC measurements are unavailable, not zero. Wall seconds measure the whole harness invocation. The uniform capacity ceilings are 256,000,000,000 serialized-RPC bytes and 21,600 release seconds.','']
for r in rows:
 if r['status']=='FAIL':lines.append(f"- `{r['job_id']}`: {r['failure_reason']} [Log]({pathlib.Path(r['local_log']).relative_to(root)})")
lines+=['','Nine new CPU-only pods, each 32 vCPU / 64 GB at $0.96/hour ($8.64/hour total, storage additional), plus reused idle pod12/14/15. Pod11/13 were occupied by prior work at dispatch. Pods and private state remain allocated for review. See [fleet inventory](FLEET.md) and [audit](artifacts/fleet-audit.json).','', 'Pod4 was read-only. No project code, manifest, integrator status, thesis, GEE worktree, or frozen LMM changes. No pushes or tags. The state-path override is recorded alongside each exact manifest CLI in RESULTS.jsonl.']
latest=[json.loads(l) for l in (root.parent/'dsvert-crossowner/integrator-evidence/RELEASE_MANIFEST.jsonl').read_text().splitlines() if l]
dispatched={j['job_id']:j for j in map(json.loads,(root/'artifacts/dispatched-manifest.jsonl').read_text().splitlines())}
replacement=[j for j in latest if j.get('fleet_ready') and (j['job_id'] not in dispatched or j.get('source_commits')!=dispatched[j['job_id']].get('source_commits'))]
(root/'artifacts/manifest-provenance-check.json').write_text(json.dumps({'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ready_jobs_not_covered_by_dispatched_pair':replacement},indent=2))
if replacement:lines+=['',f'The manifest changed after dispatch. {len(replacement)} currently ready entries name a replacement commit pair; this batch provides evidence only for the original pair above. See [manifest provenance check](artifacts/manifest-provenance-check.json).']
(root/'SUMMARY.md').write_text('\n'.join(lines)+'\n')
