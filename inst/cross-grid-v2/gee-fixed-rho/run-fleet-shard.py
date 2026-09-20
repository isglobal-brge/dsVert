"""Run one family's three frozen releases after source-bound readiness gates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("family", choices=("binomial_gee", "poisson_gee"))
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--r-library", type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
logs = root / "logs/gee-fleet" / args.family
logs.mkdir(parents=True, exist_ok=False)
manifest_hash = hashlib.sha256((root / "frozen-source-manifest.json").read_bytes()).hexdigest()
state = dict(family=args.family, source_manifest_sha256=manifest_hash,
             promoted=False, status="checking_gates", jobs=[], started_unix=time.time())


def save():
    (logs / "state.json").write_text(json.dumps(state, indent=2) + "\n")


status = 1
try:
    readiness = root / "logs/fleet-readiness"
    for name in ("binomial_gee-smoke", "poisson_gee-smoke", "dsVert-paired", "dsVertClient-paired"):
        proof = json.loads((readiness / (name + ".json")).read_text())
        assert proof["proof_passed"] is True and proof["exit_code"] == 0, name
        assert proof["source_manifest_sha256"] == manifest_hash, name
        assert proof["source_unchanged"] is True, name
    assert json.loads((readiness / "handoff.json").read_text())["pod4_serial_controller_stopped"] is True
    lane = root / "dsVert/inst/cross-grid-v2/gee-fixed-rho"
    plan = logs / "plan.jsonl"
    subprocess.run(["python3", str(lane / "generate-manifest.py"), "--root", str(root),
                    "--oracle-records", str(root / "logs/oracle-commitments"),
                    "--source-manifest", str(root / "frozen-source-manifest.json"),
                    "--output", str(plan)], check=True, stdin=subprocess.DEVNULL)
    rows = [json.loads(line) for line in plan.read_text().splitlines()]
    env = dict(os.environ, R_LIBS_USER=str(args.r_library), GOMAXPROCS="2", GOMEMLIMIT="8GiB")
    # Measure the uninterrupted capacity cell before spending work on recovery.
    for owners in (3, 2, 5):
        row = next(row for row in rows if row["family"] == args.family and row["K"] == owners)
        command = ["python3", str(lane / "run-release.py"), args.family, str(owners),
                   "--expected-oracle-sha256", row["expected_oracle_sha256"]]
        if owners == 2:
            command.append("--recovery")
        record = dict(K=owners, mode=row["mode"], command=command, started_unix=time.time())
        state["jobs"].append(record)
        with (logs / ("k" + str(owners) + ".log")).open("x") as output:
            child = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=subprocess.STDOUT)
            record.update(pid=child.pid, stdin=os.readlink(f"/proc/{child.pid}/fd/0"))
            state["status"] = "running_k" + str(owners)
            save()
            record["exit_code"] = child.wait()
        label = f"{args.family}-n2000-k{owners}-independence-rho0-{row['mode']}"
        path = root / "logs/gee-fixed-rho" / (label + "-resources.json")
        proof = json.loads(path.read_text())
        record.update(finished_unix=time.time(), resources=str(path),
                      resources_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      proof_passed=proof["proof_passed"])
        save()
        assert record["exit_code"] == 0 and proof["proof_passed"] is True, label
        assert proof["source_manifest_sha256"] == manifest_hash, label
    status = 0
    state["status"] = "completed_pending_review"
except Exception as error:
    state.update(status="failed_no_remaining_jobs_launched", error=str(error))
finally:
    state.update(exit_code=status, finished_unix=time.time())
    save()
    (logs / "driver.exit").write_text(str(status) + "\n")
    print(json.dumps(state), flush=True)
raise SystemExit(status)
