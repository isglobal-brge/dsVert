# Fixed-rho GEE signed release proofs

Run from a dedicated frozen pod snapshot containing `dsVert/`, `dsVertClient/`,
`frozen-source-manifest.json`, and `integrator-validation/` (a copy or symlink of
`dsVert/inst/cross-grid-v2/integrator-validation`). Build the native runtime and
`dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test` before freezing the
manifest. Each attempt uses a distinct snapshot/state root. The driver refuses
to overwrite attempt evidence and verifies every pinned file before and after.

The signed synthetic fixture uses n2000, p3, two beta candidates, C500/B4, ε8,
δ=2^-100, score clip 1, the existing signed integer caps, and two compute/noise
authorities. K is the number of authenticated source owners. The default
working correlation is analyst-specified independence rho=0. The optional
release flags admit exchangeable or AR1/rho in {0,1/4,1/2}; no
estimation or new privacy budget is introduced.

Smoke first (`--n 4`); compute a synthetic oracle commitment before the n2000
release. These commands use no authority transport or DP draw:

```sh
Rscript --vanilla dsVert/inst/cross-grid-v2/gee-fixed-rho/oracle-commitment.R "$PWD" binomial_gee logs/binomial-gee-oracle.json
Rscript --vanilla dsVert/inst/cross-grid-v2/gee-fixed-rho/oracle-commitment.R "$PWD" poisson_gee logs/poisson-gee-oracle.json
python3 dsVert/inst/cross-grid-v2/gee-fixed-rho/generate-manifest.py --root "$PWD" --oracle-records logs --source-manifest frozen-source-manifest.json --output logs/RELEASE_MANIFEST_GEE.jsonl
```

The resulting manifest contains K2 recovery and K3/K5 baseline commands for each
family, six jobs total: one actual n2000 publication per family and topology.
K2 recovery exercises interruption before its first successful publication,
then verifies the same sticky release identity on replay. The release driver requires
`--expected-oracle-sha256` at n2000 and rejects a mismatching released fixture.
Omit `--source-manifest` only to emit explicitly pending source fields during
development. Oracle records bind their exact arithmetic/certificate source
files; the generator rejects stale oracle dependencies and requires fresh
independence/rho0 records. Retained exchangeable commitments cannot be reused
for this default cell. Run the independent
oracle with a final fourth argument `4` to cross-check a smoke commitment.

For detached execution, launch the command using `nohup`, redirect its output
to a new driver log and use `< /dev/null`. The driver's R child also uses
`subprocess.DEVNULL`; its observed `/proc/PID/fd/0` target is recorded. Do not
reuse or modify any existing LMM snapshot or release controller.

`run-campaign.py` runs one release at a time, retaining two authenticated
authorities per release. Direct release launches also take the shared
`.gee-fixed-rho-release.lock` in the snapshots' parent directory and fail closed
if another lane release holds it. The R child inherits the lock descriptor so
it remains held if its controller exits early. This lock covers only this GEE
lane, with one release per DataSHIELD transport; other lanes are unaffected.
Run the n4 smoke families serially as well. This limits
concurrent sampler memory use; it does not change ε/δ, signed numeric caps,
transport caps or acceptance gates. The r4 binomial sampler failure coincided
with container memory pressure, but its cause was not recovered. Serial
scheduling is a resource mitigation, not evidence that OOM caused that failure.

Authenticated staged fixed-rho GEE uses a deterministic sampler execution
width of at most 16 coordinates, additionally bounded by the certified physical
plan. The 43-coordinate proof cell therefore uses 16/16/11. The complete-vector
privacy plan, sensitivity and coordinate caps are unchanged. Geometry is bound
into PREPARE and the noise transcript: do not rechunk an existing release or
migrate its private state. A changed implementation is tested under a fresh
synthetic proof identity; recovery retains that identity and geometry.

All jobs require an actual exported-API DP release, exact integer-oracle
equality, identical sticky replay, rejected signed-contract tampering,
authenticated cold lifecycle rejection tests and cold exported-API equality.
Each K2 recovery job additionally proves prepared-receipt interruption,
bilateral native PREPARE remasking with a fresh nonce/mask domain, unilateral
native COMMIT exact replay, terminal COMMIT before R persistence and unilateral
R persistence recovery. These checks preserve the existing signed release
identity. The native probe is custodian-local and returns pass/fail evidence.

Each job measures the existing 256 decimal GB/21,600-second gate once using
bootstrap-through-first-publication R-serialized RPC bytes and elapsed time;
raw native payload counters are also retained. The K3 baseline provides each
family's capacity measurement without recovery retries. Every job retains the
same capacity gate. This RPC scope excludes IPC
framing and is not total network traffic. The 900-second inactivity/86,400-second total
execution policy is unchanged from the retained proof runner and does not
weaken the independent six-hour acceptance gate. Process wall time includes
oracle/cold checks and is recorded separately. No unmeasured larger n/p/J or
correlation cell is certified by a completed default-cell proof. Report the
measured capacity scope as p<=3/C<=500 at B4/J2 and independence/rho0.

The **paired suite** means the complete server and client `testthat` suites
against this same frozen pair, using `cycle16/run-paired.R`; focused GEE tests
alone are insufficient. The runner expects `logs/structured-oracle.test` to
point to the matching compiled native test binary. Run each package serially:

```sh
unset DSVERT_TEST_SYNOPSIS_E2E_FAMILY DSVERT_TEST_SYNOPSIS_E2E_K
export DSVERT_GEE_TEST_BINARY="$PWD/dsVert/inst/bin/linux-amd64/dsvert-mpc"
Rscript --vanilla dsVert/inst/cross-grid-v2/cycle16/run-paired.R "$PWD" dsVert
Rscript --vanilla dsVert/inst/cross-grid-v2/cycle16/run-paired.R "$PWD" dsVertClient
```

The explicit binary selects this snapshot's GEE runtime; clearing both
selectors prevents an inherited focal family/topology from narrowing the suite.
Review `.rds`/`.csv` results, failures, errors, skips and warnings. Promotion
requires both paired passes and the per-family topology/recovery evidence.
The driver emits `promoted:false`; only the reviewed promotion record may
declare the measured scope promoted.

The r7 fleet continuation uses `run-paired.py` to run the complete server suite
on idle pod11 and complete client suite on idle pod16 against byte-verified
copies of the same frozen pair. Its source and oracle verification runs before
and after each suite; any warning or skip remains a review gate. New controller
scripts live outside the frozen package trees. The dedicated remote root is
`/workspace/dsvert/gee-fixed-rho-r7-fleet` on each pod.

`continue-fleet-r7.py` is a single detached local dispatcher. Inspect
`evidence/r7-fleet/dispatch-state.json` before any manual launch. It waits for
both r7 n4 preflights and both fresh paired suites. Once both preflights finish,
it stops only pod4's old scheduling parent before that parent can launch a
duplicate n2000 campaign; an already-running paired child may finish. It then
uses `run-fleet-shard.py` for binomial on pod11 and Poisson on pod16. Each shard
runs K3 baseline first for uninterrupted capacity, K2 recovery, then K5 baseline,
stopping on failure. At most one real release runs per pod, with two pods in
parallel. No busy fleet pod is repurposed. All launches use `/dev/null` stdin.
See [POISSON_CONTRACT.md](POISSON_CONTRACT.md) for the finalized Poisson scope.
