"""One synthetic signed fixed-rho GEE release; writes evidence, never promotion."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("family", choices=("binomial_gee", "poisson_gee"))
parser.add_argument("owners", type=int, choices=(2, 3, 5))
parser.add_argument("--n", type=int, choices=(4, 2000), default=2000)
parser.add_argument("--recovery", action="store_true")
parser.add_argument("--correlation", choices=("independence", "exchangeable", "ar1"), default="exchangeable")
parser.add_argument("--rho", type=float, choices=(0, .25, .5), default=.25)
parser.add_argument("--expected-oracle-sha256", help="Precommitted exact count/vector digest; required at n2000")
args = parser.parse_args()
if args.correlation == "independence" and args.rho != 0:
    parser.error("independence requires --rho 0")
expected_oracle = args.expected_oracle_sha256
if args.n == 2000 and not expected_oracle:
    parser.error("n2000 requires --expected-oracle-sha256 from the independent fixture oracle")
if expected_oracle and (len(expected_oracle) != 64 or any(c not in "0123456789abcdef" for c in expected_oracle)):
    parser.error("--expected-oracle-sha256 must be a lowercase SHA256 digest")

root = Path.cwd().resolve()
manifest_path = root / "frozen-source-manifest.json"
manifest = json.loads(manifest_path.read_text())
label = (f"{args.family}-n{args.n}-k{args.owners}-{args.correlation}-rho{args.rho:g}-"
         + ("recovery" if args.recovery else "baseline"))
logs = root / "logs" / "gee-fixed-rho"
logs.mkdir(parents=True, exist_ok=True)
paths = {suffix: logs / (label + suffix) for suffix in
         (".log", "-metrics.json", "-resources.json", ".exit", "-launch.json")}
if any(path.exists() for path in paths.values()):
    raise RuntimeError("Existing attempt evidence: use a fresh snapshot for a retry")


def verify_source():
    bad = [name for name, digest in manifest["sha256"].items()
           if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest]
    if bad:
        raise RuntimeError("Frozen source changed: " + ", ".join(bad))


verify_source()
env = os.environ.copy()
env.update(
    R_LIBS_USER=env.get("R_LIBS_USER", "/workspace/dsvert/gobase/R-library"),
    GOMAXPROCS=env.get("GOMAXPROCS", "2"), GOMEMLIMIT=env.get("GOMEMLIMIT", "16GiB"),
    OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", NOT_CRAN="true",
    PROCESSX_NOTIFY_OLD_SIGCHLD="true", DSVERT_RELEASE_TTL_SECONDS="900",
    DSVERT_RELEASE_MAX_RUNTIME_SECONDS="86400", DSVERT_GRID_VALIDATION_N=str(args.n),
    DSVERT_GRID_VALIDATION_FAMILY=args.family,
    DSVERT_GRID_VALIDATION_P="3", DSVERT_GRID_VALIDATION_GRID="2",
    DSVERT_GRID_VALIDATION_OWNERS=str(args.owners), DSVERT_GRID_VALIDATION_EPSILON="8",
    DSVERT_GRID_VALIDATION_INSTANCE="1", DSVERT_GRID_VALIDATION_INSTANCE_COUNT="1",
    DSVERT_GRID_VALIDATION_REAL_COUNT="1", DSVERT_GRID_VALIDATION_COLD="1",
    DSVERT_GRID_VALIDATION_ORACLE_ONLY="0", DSVERT_GRID_VALIDATION_REPLAY_ONLY="0",
    DSVERT_GRID_VALIDATION_INTERRUPT=str(int(args.recovery)),
    DSVERT_GRID_VALIDATION_KEEP_STATE="1", DSVERT_GRID_VALIDATION_PROGRESS="1",
    DSVERT_GRID_VALIDATION_METRICS_PATH=str(paths["-metrics.json"]),
    DSVERT_GRID_VALIDATION_STATE_PARENT=f"/var/lib/{root.name}/{label}",
    DSVERT_GRID_VALIDATION_EXPECTED_ORACLE_SHA256=expected_oracle or "",
    DSVERT_GEE_CORRELATION=args.correlation, DSVERT_GEE_RHO=str(args.rho))
command = ["Rscript", "--vanilla", str(root / "dsVert/inst/cross-grid-v2/integrator-validation" /
           f"validate_{args.family}_dslite.R"), str(root)]
started = time.monotonic()
started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
with paths[".log"].open("x") as log:
    child = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                             stdout=log, stderr=subprocess.STDOUT)
    launch = dict(command=command, pid=child.pid, started_utc=started_utc,
                  stdin=os.readlink(f"/proc/{child.pid}/fd/0"),
                  source_repositories=manifest.get("repositories"),
                  source_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    paths["-launch.json"].write_text(json.dumps(launch, indent=2) + "\n")
    returncode = child.wait()
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
marker = "DSLITE_GEE-FIXED-RHO"
required = ["DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED " + args.family,
            "DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED",
            marker + "_COLD_EXPORTED_API_EQUAL_AUTHENTICATED"]
if args.recovery:
    required += [marker + "_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED"]
    required += [marker + "_RECOVERY_BOUNDARY " + mode + " OBSERVED" for mode in
                 ("prepared", "bilateral_prepare", "unilateral_commit", "committed", "unilateral")]
log_text = paths[".log"].read_text(errors="replace")
record = dict(measurement=label, started_utc=started_utc,
              finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              source_repositories=manifest.get("repositories"),
              source_manifest_sha256=launch["source_manifest_sha256"],
              process_wall_seconds=time.monotonic() - started,
              max_child_rss_kib_linux=usage.ru_maxrss,
              user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
              process_exit_code=returncode, stdin=launch["stdin"],
              transport_policy=dict(ttl_seconds=900, max_runtime_seconds=86400),
              markers={value: value in log_text for value in required},
              metric_shape_passed=False, recovery_metrics_passed=not args.recovery,
              promoted=False)
try:
    verify_source()
    record["source_unchanged"] = True
except RuntimeError as error:
    record["source_unchanged"] = False
    record["source_error"] = str(error)
if paths["-metrics.json"].exists():
    metrics = json.loads(paths["-metrics.json"].read_text())
    record["release_metrics"] = metrics
    expected = dict(family=args.family, n=args.n, p=3, grid=2, candidates=2,
                    owners=args.owners, slots=4, clusters=math.ceil(args.n / 4), oracle_only=False)
    correlation = dict(mode="fixed_analyst_specified", correlation=args.correlation,
                       rho=args.rho, score_clip=1, composition="staged_fixed_rho_v1")
    record["metric_shape_passed"] = (all(metrics.get(key) == value for key, value in expected.items())
                                     and metrics.get("working_correlation") == correlation
                                     and metrics.get("epsilon") == 8)
    measured = [metrics.get("end_to_end_serialized_rpc_bytes"), metrics.get("end_to_end_release_elapsed")]
    record["capacity_gate"] = dict(
        ceiling_bytes=256000000000, ceiling_seconds=21600,
        measured_serialized_rpc_bytes=measured[0], measured_release_seconds=measured[1],
        scope=metrics.get("end_to_end_scope"), wire_scope=metrics.get("serialized_rpc_scope"),
        passed=all(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= limit
                   for value, limit in zip(measured, (256000000000, 21600))), budget_stop=False)
    if args.recovery:
        record["recovery_metrics_passed"] = (
            metrics.get("recovery") == "exercised" and
            metrics.get("native_recovery") == "prepare_remask_and_unilateral_commit_exact_replay")
record["proof_passed"] = (returncode == 0 and all(record["markers"].values()) and
                           record.get("capacity_gate", {}).get("passed", False) and
                           record["recovery_metrics_passed"] and record["metric_shape_passed"] and
                           record["source_unchanged"])
record["exit_code"] = 0 if record["proof_passed"] else (returncode if returncode > 0 else 1)
paths["-resources.json"].write_text(json.dumps(record, indent=2) + "\n")
paths[".exit"].write_text(str(record["exit_code"]) + "\n")
print(json.dumps(record), flush=True)
sys.exit(record["exit_code"])
