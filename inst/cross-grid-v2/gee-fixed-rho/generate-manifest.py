"""Emit eight planned GEE release rows from precommitted synthetic oracles."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, required=True, help="Paired source/snapshot root")
parser.add_argument("--oracle-records", type=Path, required=True)
parser.add_argument("--source-manifest", type=Path, help="Final frozen committed pair; omit for pending rows")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
manifest = json.loads(args.source_manifest.read_text()) if args.source_manifest else None
heads = None if manifest is None else {
    name: value["head"] if isinstance(value, dict) else value
    for name, value in manifest["repositories"].items()}
records = {}
for path in sorted(args.oracle_records.glob("*.json")):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        continue
    if value.get("family") not in ("binomial_gee", "poisson_gee") or value.get("n") != 2000:
        continue
    assert value.get("oracle_only") is True and value.get("real_authenticated_release") is False, path
    assert (value["p"], value["grid"], value["clusters"], value["slots"], value["coordinate_count"]) == (3, 2, 500, 4, 42), path
    assert (value["instance"], value["fixture_seed"], value["numeric_grid_bits"]) == (1, 20260919, 16), path
    assert value["working_correlation"] == dict(correlation="exchangeable", rho=.25,
                                               score_clip=1, composition="staged_fixed_rho_v1"), path
    assert [item["K"] for item in value["topologies"]] == [2, 3, 5], path
    digest = value["expected_oracle_sha256"]
    exact_bytes = ("\n".join(["2000"] + value["exact"]) + "\n").encode()
    assert hashlib.sha256(exact_bytes).hexdigest() == digest, path
    oracle_program = "dsVert/inst/cross-grid-v2/gee-fixed-rho/oracle-commitment.R"
    assert hashlib.sha256((root / oracle_program).read_bytes()).hexdigest() == value["oracle_program_sha256"], path
    if manifest is not None:
        assert manifest["sha256"].get(oracle_program) == value["oracle_program_sha256"], oracle_program
    for name, expected in value["source_file_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
        if manifest is not None:
            assert manifest["sha256"].get(name) == expected, ("unfrozen oracle dependency", name)
    assert value["family"] not in records, ("duplicate oracle", path)
    records[value["family"]] = value
assert set(records) == {"binomial_gee", "poisson_gee"}, "Need both n2000 oracle commitments"
driver = "dsVert/inst/cross-grid-v2/gee-fixed-rho/run-release.py"
rows = []
for family, oracle in sorted(records.items()):
    for owners, mode in ((2, "baseline"), (3, "baseline"), (5, "baseline"), (2, "recovery")):
        command = ["python3", driver, family, str(owners), "--expected-oracle-sha256",
                   oracle["expected_oracle_sha256"]]
        if mode == "recovery":
            command.append("--recovery")
        rows.append(dict(
            family=family, n=2000, p=3, grid=2, candidates=2, clusters=500, slots=4,
            coordinate_count=42, source_commits=heads,
            source_manifest_sha256=None if manifest is None else hashlib.sha256(args.source_manifest.read_bytes()).hexdigest(),
            harness_sha256=hashlib.sha256((root / driver).read_bytes()).hexdigest(),
            workdir="fresh isolated prepared workspace containing the frozen committed pair",
            promoted=False, job_id=f"{family}-e8-k{owners}-i01-{mode}", epsilon=8,
            delta=2**-100, K=owners, instance=1, mode=mode,
            cli=shlex.join(command) + " </dev/null", expected_oracle_sha256=oracle["expected_oracle_sha256"],
            oracle_hash_scope=oracle["oracle_hash_scope"], oracle_source_file_sha256=oracle["source_file_sha256"],
            oracle_program_sha256=oracle["oracle_program_sha256"],
            working_correlation=oracle["working_correlation"], fleet_ready=manifest is not None,
            pending=None if manifest is not None else "freeze final committed server/client/runtime pair",
            execution_pool="pod4 dedicated gee snapshot", one_real_release_per_pod=False,
            real_authenticated_release_required=True, cold_replay_tamper_required=True,
            bilateral_and_unilateral_recovery_required=mode == "recovery",
            capacity_measurement=owners == 2 and mode == "baseline",
            capacity_bytes=256000000000, capacity_seconds=21600))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
print(json.dumps(dict(real_jobs=len(rows), ready_real_jobs=sum(row["fleet_ready"] for row in rows),
                     output=str(args.output))))
