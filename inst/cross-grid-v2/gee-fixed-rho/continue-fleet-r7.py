"""Harvest r7 gates and transfer its serial campaign to two idle fleet pods."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time


lane = Path(__file__).resolve().parent
evidence = lane / "evidence/r7-fleet"
evidence.mkdir(parents=True, exist_ok=True)
fleet = Path.home() / "Documents/GitHub/dsvert-fleet-heavy"
pod4 = Path.home() / "Documents/GitHub/dsvert-crossowner/pod4"
root4 = "/workspace/dsvert/gee-fixed-rho-r7"
root = "/workspace/dsvert/gee-fixed-rho-r7-fleet"
expected = "a57e599d16f284612554484ad041f1a43f03a5149eaa040435131e8d13a9294d"
state_path = evidence / "dispatch-state.json"
assert not state_path.exists(), "Existing dispatcher state: inspect before resuming"
state = dict(status="waiting_gates", started_unix=time.time(), promoted=False,
             source_manifest_sha256=expected, assignments={"11": "binomial_gee", "16": "poisson_gee"},
             gates={}, launches={})


def save():
    state["updated_unix"] = time.time()
    state_path.write_text(json.dumps(state, indent=2) + "\n")


def remote(pod, command, data=None):
    if pod == 4:
        ssh = [str(pod4)]
    else:
        ip, port = (fleet / f"pod{pod}_endpoint").read_text().split()
        ssh = ["ssh", "-i", str(Path.home() / ".ssh/id_ed25519_runpod"),
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", port, "root@" + ip]
    return subprocess.run(ssh + [command], input=data, capture_output=True, text=True,
                          timeout=35, check=True).stdout


def read_gate(pod, path, name):
    raw = remote(pod, "if test -f " + shlex.quote(path) + "; then cat " + shlex.quote(path) + "; fi")
    if not raw:
        return False
    (evidence / (name + ".json")).write_text(raw)
    proof = json.loads(raw)
    assert proof["source_manifest_sha256"] == expected, name
    assert proof["proof_passed"] is True and proof["exit_code"] == 0, name + " failed"
    assert proof["source_unchanged"] is True, name
    state["gates"][name] = hashlib.sha256(raw.encode()).hexdigest()
    return True


def handoff():
    # Stop only the old scheduling parent after BOTH release children passed.
    # An already-started paired R child may finish; no release is interrupted.
    code = f'''
import json,os,signal,time
from pathlib import Path
r=Path({root4!r}); pid=2957748
assert b"gee-fixed-rho-r7/logs/continue-serial.py" in Path(f"/proc/{{pid}}/cmdline").read_bytes()
os.kill(pid,signal.SIGSTOP)
try:
 s=json.loads((r/"logs/continuation-state.json").read_text())
 assert not (r/"logs/gee-campaign").exists(), "Serial campaign already started"
 assert all(any(x["name"]==family+"-n4" and x.get("exit_code")==0 for x in s["steps"]) for family in ("binomial_gee","poisson_gee"))
 record=dict(pod4_serial_controller_stopped=True,pid=pid,stopped_unix=time.time(),prior_state=s["status"],active_paired_children=[x for x in s["steps"] if x["name"].endswith("-paired") and "exit_code" not in x],reason="Both preflights completed; fleet owns six n2000 cells; no duplicate serial campaign",source_manifest_sha256={expected!r})
 os.kill(pid,signal.SIGTERM)
 (r/"logs/fleet-handoff.json").write_text(json.dumps(record,indent=2)+"\\n")
 print(json.dumps(record))
finally:
 try:os.kill(pid,signal.SIGCONT)
 except ProcessLookupError:pass
'''
    raw = remote(4, "python3 -c " + shlex.quote(code))
    (evidence / "handoff.json").write_text(raw)
    state["handoff"] = json.loads(raw)
    save()


def launch(pod, family):
    remote(pod, "mkdir -p " + root + "/logs/fleet-readiness")
    for name in (*state["gates"], "handoff"):
        remote(pod, "cat > " + root + "/logs/fleet-readiness/" + name + ".json",
               (evidence / (name + ".json")).read_text())
    remote(pod, "cat > " + root + "/logs/run-fleet-shard.py", (lane / "run-fleet-shard.py").read_text())
    library = "/workspace/dsvert-fleet/R-library" if pod == 11 else "/workspace/dsvert-heavy/R-library"
    code = f'''
import json,subprocess,os
from pathlib import Path
r=Path({root!r}); assert not (r/"logs/gee-fleet/{family}").exists()
for name in ("R","Rscript","dsvert-mpc"):
 assert subprocess.run(["pgrep","-x",name],stdout=subprocess.DEVNULL).returncode==1, "Pod is busy: "+name
with (r/"logs/fleet-controller.log").open("x") as output:
 p=subprocess.Popen(["python3",str(r/"logs/run-fleet-shard.py"),{family!r},"--root",str(r),"--r-library",{library!r}],cwd=r,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
 record=dict(pid=p.pid,stdin=os.readlink(f"/proc/{{p.pid}}/fd/0"),family={family!r})
 (r/"logs/fleet-launch.json").write_text(json.dumps(record)+"\\n")
 print(json.dumps(record))
'''
    return json.loads(remote(pod, "python3 -c " + shlex.quote(code)))


try:
    save()
    while len(state["gates"]) < 4:
        try:
            for family in ("binomial_gee", "poisson_gee"):
                name = family + "-smoke"
                if name not in state["gates"]:
                    read_gate(4, root4 + "/logs/gee-fixed-rho/" + family +
                              "-n4-k2-independence-rho0-baseline-resources.json", name)
            if all(family + "-smoke" in state["gates"] for family in ("binomial_gee", "poisson_gee")) and "handoff" not in state:
                # Resources are written just before the scheduling parent records its exit.
                parent = json.loads(remote(4, "cat " + root4 + "/logs/continuation-state.json"))
                if any(x["name"] == "poisson_gee-n4" and x.get("exit_code") == 0 for x in parent["steps"]):
                    handoff()
            for pod, package in ((11, "dsVert"), (16, "dsVertClient")):
                if package + "-paired" not in state["gates"]:
                    read_gate(pod, root + "/logs/gee-paired/" + package + "/result.json", package + "-paired")
            state.pop("transient_ssh_error", None)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            state["transient_ssh_error"] = str(error)
        save()
        if len(state["gates"]) < 4 or "handoff" not in state:
            time.sleep(45)
        if len(state["gates"]) == 4 and "handoff" not in state:
            handoff()
    assert "handoff" in state
    state["status"] = "launching"
    save()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pod: pool.submit(launch, pod, family) for pod, family in ((11, "binomial_gee"), (16, "poisson_gee"))}
        for pod, future in futures.items():
            state["launches"][str(pod)] = future.result()
            save()
    state["status"] = "dispatched_six_jobs_two_serial_shards"
    save()
except Exception as error:
    state.update(status="stopped_requires_inspection", error=str(error))
    save()
    raise
