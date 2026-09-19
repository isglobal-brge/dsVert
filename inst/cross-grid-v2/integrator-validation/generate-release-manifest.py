#!/usr/bin/env python3
"""Emit exact validation commands; never infer promotion from a job definition."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "integrator-evidence"
HARNESS_DIR = "dsVert/inst/cross-grid-v2/integrator-validation"
HARNESSES = {
    "nb": ("validate_nb_dslite.R", "nb"),
    "lasso": ("validate_lasso_dslite.R", "binomial"),
    "multinomial": ("validate_categorical_dslite.R", "multinomial"),
    "ordinal": ("validate_categorical_dslite.R", "ordinal"),
    **{family: (f"validate_{family}_dslite.R", family) for family in
       ("lmm", "binomial_glmm", "poisson_glmm", "binomial_gee", "poisson_gee", "cox")},
}
STRUCTURED = ["lmm", "binomial_glmm", "poisson_glmm", "binomial_gee", "poisson_gee", "cox"]
UNWIRED = STRUCTURED[1:]


def revision(repo):
    return subprocess.check_output(
        ["git", "-C", str(ROOT / repo), "rev-parse", "HEAD"], text=True
    ).strip()


def main():
    heads = {repo: revision(repo) for repo in ("dsVert", "dsVertClient")}
    rows = []
    for family, (harness, base_family) in HARNESSES.items():
        for epsilon in (1, 4, 8):
            for owners in (2, 3, 5):
                # Same 20 independent instances as the retained Step-2 campaign;
                # now every job requests one REAL release, never oracle-only.
                for instance in range(1, 21):
                    job = f"{family}-e{epsilon}-k{owners}-i{instance:02d}"
                    predictors = 3 if family.endswith("_gee") or family == "lmm" else 6
                    env = {
                        "GOMAXPROCS": "2", "GOMEMLIMIT": "8GiB",
                        "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1", "NOT_CRAN": "true",
                        "DSVERT_GRID_VALIDATION_N": "2000",
                        "DSVERT_GRID_VALIDATION_P": str(predictors),
                        "DSVERT_GRID_VALIDATION_GRID": "2",
                        "DSVERT_GRID_VALIDATION_FAMILY": base_family,
                        "DSVERT_GRID_VALIDATION_EPSILON": str(epsilon),
                        "DSVERT_GRID_VALIDATION_OWNERS": str(owners),
                        "DSVERT_GRID_VALIDATION_INSTANCE": str(instance),
                        "DSVERT_GRID_VALIDATION_INSTANCE_COUNT": "1",
                        "DSVERT_GRID_VALIDATION_REAL_COUNT": "1",
                        "DSVERT_GRID_VALIDATION_ORACLE_ONLY": "0",
                        "DSVERT_GRID_VALIDATION_COLD": "1",
                        "DSVERT_GRID_VALIDATION_INTERRUPT": "1",
                        "DSVERT_GRID_VALIDATION_STATE_PARENT": f"/var/lib/dsvert-release-jobs/{job}",
                    }
                    if family == "lasso":
                        env["DSVERT_GRID_VALIDATION_REQUIRE_DURABLE_REUSE"] = "1"
                    argv = ["env", *[f"{k}={v}" for k, v in env.items()], "Rscript", "--vanilla",
                            f"{HARNESS_DIR}/{harness}", "."]
                    rows.append({
                        "job_id": job, "family": family, "epsilon": epsilon,
                        "K": owners, "instance": instance, "n": 2000, "p": predictors, "grid": 2,
                        "source_commits": heads, "cli": shlex.join(argv),
                        "workdir": "isolated prepared dsvert-crossowner workspace root",
                        "execution_pool": "fleet_after_pod4_promotion_proofs",
                        "real_authenticated_release_required": True,
                        "cold_replay_recovery_tamper_required": True,
                        "pod4_n2000_proof": False, "fleet_ready": False,
                        "harness_present": True,
                        "harness_sha256": hashlib.sha256((ROOT / HARNESS_DIR / harness).read_bytes()).hexdigest(),
                        "expected_oracle_sha256": None,
                        "oracle_hash_status": "pending deterministic fixture/output commitment; randomized sticky noise is checked by replay",
                        "readiness": ("awaiting authenticated grouped/Cox producer wiring, shape admission and real pod proof"
                                      if family in UNWIRED else "awaiting current-pair pod4 n2000 topology proof"),
                        **({"clusters": 500, "slots": 4, "candidates": 4,
                            "objective": "ml"} if family == "lmm" else {}),
                    })
    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "RELEASE_MANIFEST.jsonl").write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    )
    (EVIDENCE / "RELEASE_MANIFEST_STATUS.json").write_text(json.dumps({
        "complete": False, "fleet_ready": False, "job_count": len(rows),
        "included_families": list(HARNESSES), "missing_harness_scripts": [],
        "unproven_authenticated_harnesses": UNWIRED,
        "unproven_n2000_structured_harnesses": STRUCTURED,
        "blocked_producer_families": UNWIRED,
        "source_commits": heads,
        "gate_bytes": 256_000_000_000, "gate_seconds": 21600,
        "per_family_job_counts": {family: sum(row["family"] == family for row in rows) for family in HARNESSES},
        "prepare_cli": shlex.join(["bash", f"{HARNESS_DIR}/prepare-release-workspace.sh", heads["dsVert"], heads["dsVertClient"]]),
        "expected_oracle_hashes_complete": False,
        "pod4_proof_execution": {
            "maximum_concurrent_real_releases": 2,
            "preferred_concurrent_real_releases": 1,
            "check_before_each_launch": "uptime and effective CPU quota; load must be below 1.5 * min(nproc, cgroup CPU quota)",
            "effective_cpu_observation": 7.65,
            "load_limit_observation": 11.475,
            "observation_scope": "cycle10 pod4 cpu.cfs_quota_us=765000 and cpu.cfs_period_us=100000; re-read quota before launch",
            "lmm_sequence": ["n2000_K2", "n2000_K3", "n2000_K5", "native_recovery", "paired_suite"],
            "family_order": STRUCTURED,
            "family_order_gate": "one real n2000 proof before the next family; all promotion gates before promotion",
            "bulk_matrix_on_pod4": False,
            "cycle9_overload_transport_failures": "retryable infrastructure; preserve failed evidence and retry under this policy",
        },
        "prerequisites": [
            "Use a separate writable source snapshot per job; harness debug/output paths are not shared-job safe.",
            "Launch detached jobs with stdin redirected from /dev/null.",
            "The K/epsilon/instance matrix targets the fleet after promotion gates; do not launch the matrix on pod4.",
            "On pod4 run promotion proofs sequentially; never exceed two concurrent real releases or overlap the paired suite with heavy releases.",
            "Install the paired R dependencies and configure R_LIBS_USER on each worker.",
            "Verify dsVert/inst/bin/SHA256SUMS and prepare the oracle test executable.",
            "Provide a private writable /var/lib/dsvert-release-jobs parent (not a temporary noise root).",
            "Expected oracle output commitments must be generated and verified before readiness.",
            "Collect pod4 n2000 proof and set readiness before reviewer fan-out. No job entry is promotion evidence.",
        ],
        "oracle_build_cli": "mkdir -p dsVert/inst/cross-grid-v2/build && cd dsVert/inst/dsvert-mpc && go test -c -o ../cross-grid-v2/build/cross-grid-oracle.test .",
        "scope": "Validation-size jobs only. Capacity measurements and final paired suites remain separate gates.",
    }, indent=2) + "\n")
    assert len(rows) == 1800 and len({row["job_id"] for row in rows}) == len(rows)
    for row in rows:
        assert shlex.split(row["cli"])[-1] == "."
        assert (ROOT / shlex.split(row["cli"])[-2]).is_file()
    print(f"Wrote {len(rows)} pending fleet jobs; six structured families await n2000 proof, five await producer integration.")


if __name__ == "__main__":
    main()
