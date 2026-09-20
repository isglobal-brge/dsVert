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
working correlation is analyst-specified exchangeable rho=1/4. The optional
flags admit independence/rho0 and exchangeable or AR1/rho in {0,1/4,1/2}; no
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
files; the generator rejects stale oracle dependencies. Run the independent
oracle with a final fourth argument `4` to cross-check a smoke commitment.

For detached execution, launch the command using `nohup`, redirect its output
to a new driver log and use `< /dev/null`. The driver's R child also uses
`subprocess.DEVNULL`; its observed `/proc/PID/fd/0` target is recorded. Do not
reuse or modify any existing LMM snapshot or release controller.

`run-campaign.py` runs one release at a time, retaining two authenticated
authorities per release. Run the n4 smoke families serially as well. This limits
concurrent sampler memory use; it does not change ε/δ, signed numeric caps,
transport caps or acceptance gates. The r4 binomial sampler failure coincided
with container memory pressure, but its cause was not recovered. Serial
scheduling is a resource mitigation, not evidence that OOM caused that failure.

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
framing and is not total network traffic. The 900-second lease/86,400-second
execution policy is unchanged from the retained proof runner and does not
weaken the independent six-hour acceptance gate. Process wall time includes
oracle/cold checks and is recorded separately. No unmeasured larger n/p/J or
correlation cell is certified by a completed default-cell proof.

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
