"""Run one complete package suite against a frozen GEE pair; never promote."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("package", choices=("dsVert", "dsVertClient"))
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--r-library", type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
manifest_path = root / "frozen-source-manifest.json"
manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
manifest = json.loads(manifest_path.read_text())
logs = root / "logs/gee-paired" / args.package
logs.mkdir(parents=True, exist_ok=False)
record = dict(package=args.package, source_manifest_sha256=manifest_hash,
              source_repositories=manifest["repositories"], promoted=False,
              started_unix=time.time(), proof_passed=False)


def verify():
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == manifest_hash
    for name, expected in manifest["sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
    assert hashlib.sha256((root / "logs/structured-oracle.test").read_bytes()).hexdigest() == manifest["oracle_sha256"]


status = 1
try:
    verify()
    env = dict(os.environ, R_LIBS_USER=str(args.r_library),
               DSVERT_GEE_TEST_BINARY=str(root / "dsVert/inst/bin/linux-amd64/dsvert-mpc"),
               DSVERT_PAIRED_LOG_DIR=str(logs), GOMAXPROCS="2", GOMEMLIMIT="8GiB",
               OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", NOT_CRAN="true",
               PROCESSX_NOTIFY_OLD_SIGCHLD="true", DSVERT_RELEASE_TTL_SECONDS="900",
               DSVERT_RELEASE_MAX_RUNTIME_SECONDS="86400")
    for key in ("DSVERT_TEST_SYNOPSIS_E2E_FAMILY", "DSVERT_TEST_SYNOPSIS_E2E_K"):
        env.pop(key, None)
    command = ["Rscript", "--vanilla", str(root / "dsVert/inst/cross-grid-v2/cycle16/run-paired.R"),
               str(root), args.package]
    record["command"] = command
    with (logs / "suite.log").open("x") as output:
        child = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=subprocess.STDOUT)
        record.update(pid=child.pid, stdin=os.readlink(f"/proc/{child.pid}/fd/0"))
        (logs / "launch.json").write_text(json.dumps(record, indent=2) + "\n")
        record["process_exit_code"] = child.wait()
    verify()
    record["source_unchanged"] = True
    with (logs / (args.package + "-paired.csv")).open() as results:
        rows = list(csv.DictReader(results))
    def count(value):
        return {"TRUE": 1, "FALSE": 0}.get(value, 0) if value in ("TRUE", "FALSE") else int(value)

    totals = {key: sum(count(row[key]) for row in rows)
              for key in ("passed", "failed", "skipped", "warning")}
    totals["error"] = sum(row["error"] == "TRUE" for row in rows)
    record.update(totals=totals, cases=len(rows),
                  review_required=[row for row in rows if row["error"] != "FALSE" or
                                   any(count(row[key]) for key in ("failed", "skipped", "warning"))])
    record["proof_passed"] = (bool(rows) and record["process_exit_code"] == 0 and
                              not record["review_required"])
    status = 0 if record["proof_passed"] else 1
except Exception as error:
    record["error"] = str(error)
finally:
    record.update(finished_unix=time.time(), exit_code=status)
    (logs / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    (logs / "driver.exit").write_text(str(status) + "\n")
    print(json.dumps(record), flush=True)
raise SystemExit(status)
