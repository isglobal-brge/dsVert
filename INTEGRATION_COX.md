# Cox integration boundary

This branch supplies an internal chunk producer library and signed R contracts.
It does **not** promote a working production release. `runtime_enabled=FALSE`,
server `produce()` and the client release function fail with the fixed public
failure. The artifact reports contract-only/pending states; `required_result_states`
pins the requested materialized/joint-DP states for future result evidence. Same-owner/sealed routes
are untouched. Do not enable the route by flipping a Boolean.

Entry points (one registration function per language/package):

- Go `registerCoxGridCrossLoss()` -> Version, SharedPlan, SharedCompile, RunShares.
  Use these share-based entries for transcript v2. Legacy Plan/Compile are only
  retained for integer regression and must not be selected by the fused producer.
- Server `.dsvert_dp_cox_grid_cross_register()` -> spec, contract validator,
  artifact, source contract, sensitivity, disabled producer.
- Client `.dsvert_dp_cox_grid_cross_client_register()` -> validator, moment,
  disabled release. Its namespace-internal `entry` (`dp_cox_grid`) accepts additive owner-qualified
  `Surv(time,event)` formulas. Both actual Ed25519 signatures are mandatory.

## Exact remaining wiring

1. Register the client entry in the public method inventory and maturity registry,
   update their exact-surface/count tests, then add `export(dp_cox_grid)`. The
   family branch keeps this export pending: the existing inventory requires exact
   public-surface equality and currently classifies all 97 analysis entries as
   promoted. Do not silently classify the disabled Cox producer as promoted.
   Add Cox to the fused producer's family registration and purpose-specific
   manifest/lifecycle admission. Authenticate both schema and complete canonical
   Cox contract before input resolution. Preserve epsilon, delta, adjacency,
   whole-cohort U/Delta, source snapshot, profile hashes and common-lattice scale.
   No inherited GLM row sensitivity or partial-dot rounding is valid for Cox.
2. Implement the signed source layout: normalize bounded features using the
   frozen exact binary64-to-f50 routine, exact public-beta partial f100 dots;
   combine both owners' complete-case bits and private PSI equality evidence.
   Event validity must reject finite nonbinary events. Invalid time/covariate
   records are inactive; duplicate patient records reject the entire snapshot.
   Bind all ownership, column order and alignment/source receipts.
3. The outcome owner privately sorts descending finite clipped time; signed zero
   is canonical and invalid/padded lanes use terminal sentinel then PSI slot
   order. Supply Beneš controls with `primitiveVPermutationControls` and sorted
   tie-END bits; each tied censored patient is in the prefix. Outcome owner is
   the permutation garbler; reverse-role protocol coverage remains required.
4. Bind `coxLossPlanShares`'s canonical digest (spec, padded rows, J+2 packed
   columns, 32-row scalar batches, 4096-word OT batches, compact framing and
   streaming checked-OT mode). Authenticate generated profile/finalizer sources;
   `coxLossProgramsMatch` rejects substituted program metadata before access.
   The whole contract digest includes epsilon/delta, caps, source/PSI binding and
   admission. The materializer locally adds the two owners' f100 dot shares,
   then packs each PSI row as `[dot_0,...,dot_(J-1),live,event]` in Ring128.
   Padded slots have authenticated zero dots/live/event. Outcome-owner time
   keys remain local: their order is represented by private Beneš controls and
   sorted tie-end bits, never exposed time ranks or event-dependent shapes.
5. Compile with `SharedCompile`; call `RunShares` exactly once for the complete
   release. It performs ONE packed OT Beneš permutation over all J columns and
   metadata. Per candidate: exp batches consume joined f100 dots, round once to
   q16, check live/event, and emit Ring64 weight/event-eta/active shares. Prefix
   additions are local on shares. A private OT reverse doubling scan selects
   the last prefix in every Breslow tie, including ties across chunk boundaries.
   Fixed padded log batches consume selected prefixes and active shares. Sum
   log contributions minus event-eta locally in Ring64; finalize once on the
   whole-cohort lattice. No prefix or cohort addition runs inside GC. Logs run
   for all padded slots with private event masking, so event counts stay private.
   A complete coordinate and its validity are returned ONLY as local shares.
6. Supply the existing authenticated peer channel/session and nonzero contract
   digest. The internal runner uses encrypted records and step-2's compact
   topology-bound framing (family-local adaptation of 0006f1a; replace with the
   shared helpers at integration). Two distinct checked COT extensions persist
   only within this connection, in opposite roles, with advancing PRG streams.
   Every chunk chains ordinal/predecessor and both PRIVATE-key state commitments into
   the next GC context. Receipts contain no unkeyed private-state digest. Each commitment key is fresh
   and known only to its custodian, never the shared channel key.
   The outcome owner is the permutation/GC garbler. Source-bound controls and
   time ties are the owner's responsibility under the pinned semi-honest model;
   this does not claim a malicious-source proof. The fused lifecycle supplies
   durable authenticated source/result receipts. On interruption, discard OT
   streams and use a NEW session ID for a kernel restart before any DP commit;
   do not reset/reuse an extension or replay encrypted record nonces. Current
   runner state is in memory; persistence/resumption belongs to step 2.
7. `RunShares` returns coordinate AND validity shares modulo 2^64; the signed
   private layout pins `kernel_output_ring_bits=64`, `joint_dp_source_ring_bits=128`
   and the required conversion. In step-2's authenticated fused circuit, compute
   q=(a+b) mod 2^64 and v=(v_a+v_b) mod 2^64, require v=1 and 0<=q<=U_j, then
   cast the reconstructed q to uint128 and freshly remask for the joint-DP ABI.
   Never open q/v or zero-extend the two individual shares: their Ring128 sum
   can contain an unwanted 2^64 carry. This conversion belongs inside the
   authenticated fusion, not a plaintext adapter or new family RPC.
   Inject the J converted coordinates ONCE into the existing joint DP source
   prefix, keeping it zero until all results/validities and receipts are complete.
   Calibrate the existing joint sampler to the full workload including every
   coordinate. Recheck tail/approximation delta and noise no-wrap/resource bounds.
   Publish only its existing support-clamped, cross-signed sticky vector and
   canonical semantic release ID; recovery/retry must never draw fresh noise.
   Framing, receipt keys, OT stream/session IDs, chunk retries and deployment
   admission metadata are execution bindings, not new statistical queries.
   Changing them alone must not create a fresh semantic release/noise draw.
8. Replace the disabled client release body with the authenticated existing
   lifecycle reader. Validate both DP result signatures/evidence, payload,
   contract, snapshot and release ID before returning coordinates to the internal
   moment helper. The helper assumes authenticated, public support-clamped integer
   coordinates. Canonical first-minimum, slope rescaling and no inference remain.
9. Close deployment gates: Ring64-to-Ring128 carry/no-carry cases and invalid
   terminal validity (without opening either), both roles on pinned processes/hosts, PSI mismatch,
   swapped source columns, corrupted records/OT, stale profile, duplicate injection,
   crashes around commit, lost ACK, concurrent sticky replay. Test-only DSLite
   methods and reference noise are not substitutes for these gates.
10. Enforce the signed admitted-capacity envelope before protected access, in
    addition to unchanged 32M-gate / 2 MiB-source / 512 Ki-bit runner limits.
    Scalar batches fail compilation above 5000 non-XOR gates per row, INCLUDING
    the source ABI bridge and output masks. The final measured envelope will be
    recorded below. Registered SharedPlan/SharedCompile/RunShares already enforce
    the measured rectangle, mirrored in spec.resource_admission on both R sides.
    Do not call the unregistered measurement helpers to bypass this guard.
    All production release paths remain disabled pending authenticated fusion.

## Revised envelope measurement

The old 722 GB + 373 GB component model measures the superseded architecture
and is not a current failed gate. The new benchmark executes the ENTIRE family
kernel (packed permutation, all padded exp/log batches, exact share additions,
private tie selection, finalizers and receipts) on two encrypted peers on the
pod. It measures both directions, includes cold compilation in elapsed time and
checks every reconstructed SYNTHETIC coordinate against the independent oracle.
It does not yet include source/PSI resolution, authenticated DP fusion, sampler
or sticky publication; those arrive from step 2 and must fit the remaining
headroom at integration. It is not a two-host network/RTT measurement.

The pod exposes 96 CPUs but its cgroup quota is 7.65 cores. Benchmark launcher
records host details and uses at most two GOMAXPROCS=2 processes concurrently.
The completed matrix and chosen public admission are pending measurement.

## Synthetic test boundary

`k2_exact_gc_cox_loss_plaintext_command_test.go` requires BOTH `_test.go` and
`//go:build dsvert_cox_plaintext_test`; the command also requires
`DSVERT_COX_PLAINTEXT_TEST=1`. A normal production `go build`, even with the tag,
cannot contain it. R production functions have no reference command or fallback.
Run the DSLite test with `DSVERT_COX_TEST_BINARY` set to a `go test -c -tags
 dsvert_cox_plaintext_test` binary. It uses public synthetic local tables, two
real DSLite connections, real contract signatures, independent per-peer
negative-binomial reference noise contributions, and pooled `survival::coxph`
with Breslow ties. It exercises the R contract/postprocessing path and compares
Go with an independent pure-R integer risk-set evaluator. It is deliberately
labelled `production_protocol=FALSE`: it does not certify joint sampler security,
PSI/source authentication, or a sticky production lifecycle.
