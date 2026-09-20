Latest continuation: `continuation/RESUME.md` and `continuation/progress.json`.
Code `fe4c953/4c6c562`; LMM n2000/K2 still active, no promotion.

# Cycle18 checkpoint — LMM public sampler cap repaired; promotion pending

Production code: server `12aec48`, client `4c6c562`. LMM cap change itself is
server `e4df243` / client `4c6c562`; native binaries remain `b59d34c`.
No new n2000 result, no promotion, no new math blocker, no escalation.

## LMM lifecycle audit and repair

Reused the existing signed Synopsis/joint exact-GC lifecycle. These requested
boundaries were already wired and remain in place:

- Signed workload/profile/artifact admission: `dpGLMGridCrossMaterializer.R`,
  client `dp_glm_grid_cross_release.R` and grouped contract validators.
- Structured public reader and certificate: client `dp_grouped_grid_cross.R`.
- Authenticated publication/cold evidence: server `dpLMMGridCrossPrepare.R`
  and `dpGLMGridCrossLifecycle.R`, client LMM public-evidence reader.
- Fixture provisioning: `integrator-validation/validate_structured_dslite.R`
  assigns the smaller transport identity's bootstrap home to the grouping
  owner BEFORE building pins or signing; raw owner data never move.
- Existing proof harness invokes exported APIs, sticky replay, source/stage
  tamper, direct and exported cold replay, and the recovery helper.

The actual remaining cap defect was in client preflight AND public sampler
policy. A 256-candidate LMM needs 257 total coordinates because admission
contributes one count. A single LMM artifact above51 coordinates now uses
`dsvert-lmm-grid-exact-gc-cost-policy-v1`, ceiling257. Both server/client policy
selection, certified chunk sizing and public vector verification agree.
258 is rejected. Existing <=51 LMM releases preserve v2 policy identity,
so old small-grid publication/cold verification is not invalidated. Simple
families and GLMM retain their previous policy. No sampler fallback is added.
The internal backend-selection field `promoted` is not heavy-family promotion.

Final focused results: server56 tests/649 assertions; client47 tests/713
assertions, all zero failures/errors/warnings/skips. Includes real signed
256-candidate preflight, tampered profile rejection, cap overflow and33
8-coordinate chunks with a one-coordinate tail. Tests of signed admission,
public provenance/cold evidence and old policy behavior also pass. This is
not a real 256-candidate release measurement or n2000 capacity proof.
Raw CSV/logs and `focused-summary.json` are in this directory. Earlier parse
and NULL-policy regression failures were corrected; their logs are retained.

## Frozen paired suite for LMM cap source

`/workspace/dsvert/executor-cycle18-lmm-paired-r1`, PID2031343, stdin/dev/null.
Source `e4df2434119204003c40f86b1b960d4a9df205ac` /
`4c6c5622fbdc2ae97de315f18c18901d452f3c09`.
Manifest `c50188ffc68de06f927b07dbb31bb801e63d6ccdf2b146b81a83f2533e779fc5`;
all2563 hashes reverified at06:19 UTC. Server then client full suites run
sequentially with the existing cycle16 R runner; no full pass yet.
Release harness environment is24h/15min. Policy unit tests retain their own
explicit test settings. This suite has its own isolated peers/state roots.
It does NOT replace the paired stage of the frozen n2000 LMM driver.
The later Cox-only identity patch12aec48 is not in this frozen paired source.

New local collector78671, stdin/dev/null, retains completion and runs the
existing paired analyzer. Launch/identity/hash record is under `paired/`.
No old collector was replaced. Commands:

```sh
python3 integrator-evidence/cycle18-20260920/paired/harvest.py --allow-partial
# After driver exit (watcher also runs this automatically):
python3 integrator-evidence/cycle18-20260920/paired/harvest.py
```

Inspect RDS/CSV and every nonpass, even when runner exit0. Do not relabel this
suite as applying to Cox12aec48 or to the older release sources.

## Active release sequences: preserve, harvest, do not duplicate

Cycle16 LMM r2: `bc59147/6ba11a0`, PID1182464,2553 hashes match. Still n2000/K2,
no completed metrics/exit/oracle proof. Existing order n4 -> n2000 K2/K3/K5 ->
recovery -> full paired remains untouched.24h total/15min inactivity, isolated
peers per release. Latest observations are pinned in this cycle's progress.json.
The reviewer n2000 milestone remains uncorroborated by these live artifacts;
its n4 oracle marker must not be relabelled n2000.

Cycle17 GLMM r1: `cd54dd5/6ba11a0`, PID1984876,2556 hashes match. Binomial waits
for the existing shared release lock, then its sequential proof; Poisson runs
only after binomial succeeds. Identical24h/15min settings. No duplicate release
was launched and no frozen code, log, runtime or release controller was changed.

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle17-20260920/harvest.py --verify-source
```

Promotion stays No until complete actual K2/K3/K5, bilateral/unilateral recovery,
cold/tamper/sticky, full paired review and measured <=256,000,000,000 serialized
aggregate-RPC bytes /21,600 seconds.24h lease is not a relaxed capacity ceiling.
No n4 or old-runtime measurement establishes capacity of current expanded grids.

## Secondary scope

Cox12aec48 reuses the LMM session/pinset identity checks in its authenticated
source loader. Previously matching peer names alone did not establish that
both transport identity keys matched the signed authorities. The real SQLite
loader fixture now uses its actual signed keys; replacing either with a third
owner's real key rejects while keeping peer names/alignment digest unchanged.
Focused14 tests/840 assertions PASS with zero nonpasses. No new public route
or signed Cox release is claimed. Remaining: owner-local time sidecar/producer,
private complete-case composition, live native handoff, DP/public lifecycle.

GEE estimated-alpha scope is still the unanswered contract in cycle17's
GEE_ALPHA_SCOPE.md: estimator, projection/degenerate cases, coefficient privacy
and global sensitivity. No fixed-rho proof is relabelled as estimated-alpha;
no invented estimator or BLOCKED file.

No tags, pushes, thesis edits or simple-family release jobs. Root STATUS and
PROMOTION_TABLE retain truthful pending gates; packaged cycle18 evidence is
committed as a separate documentation checkpoint after the production commits.
