# Cox integration boundary

This branch supplies an internal chunk producer library and signed R contracts.
It does **not** promote a working production release. `runtime_enabled=FALSE`,
server `produce()` and the client release function fail with the fixed public
failure. The artifact reports contract-only/pending states; `required_result_states`
pins the requested materialized/joint-DP states for future result evidence. Same-owner/sealed routes
are untouched. Do not enable the route by flipping a Boolean.

Entry points (one registration function per language/package):

- Go `registerCoxGridCrossLoss()` -> version, Plan, Compile.
- Server `.dsvert_dp_cox_grid_cross_register()` -> spec, contract validator,
  artifact, source contract, sensitivity, disabled producer.
- Client `.dsvert_dp_cox_grid_cross_client_register()` -> validator, moment,
  disabled release. Public `dp_cox_grid` accepts additive owner-qualified
  `Surv(time,event)` formulas. Both actual Ed25519 signatures are mandatory.

## Exact remaining wiring

1. Add Cox to the fused producer's family registration and purpose-specific
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
4. Bind `coxLossPlan`'s deterministic schedule hash and each ordinal through
   `coxLossChunkBinding(contract, predecessor)`. Hash serialization is a stream
   of header + canonical chunk JSON records; switch endpoints are reconstructed
   from the primitive and checked but omitted from the signed serialization.
   Version/source hash authentication must reject reordered, missing, substituted
   or replayed chunks. Kernel shapes are fixed before private input access.
5. Run prepare -> permutation -> forward -> backward -> finalize per candidate.
   Prepare has triples (f100 dot,live,event), then validity, Ring128. Reduce
   resulting shares modulo 2^64. Padded triples are authenticated (0,0,0).
   Permutation tiles take touched rows in ascending public slot order, triples
   plus shared validity, then garbler-only control words. Every output is masked.
   Forward inputs: (eta_q16,live,event,tie_end)*rows, prefix_W, validity;
   outputs: (eta_q16,event,tie_end,log_prefix_q20)*rows, prefix_W, validity.
   Backward inputs: forward row tuples, reverse_H, cumulative_L, validity;
   outputs: reverse_H,cumulative_L,validity. Start W/H/L at zero and never reset
   across tiles. AND all dependency validities; fail closed at final injection.
   Finalize accepts cumulative_L and validity and returns capped lattice q and
   validity shares. Payload changes on invalid input are never publishable.
6. Use `primitiveVRunGarbler/Evaluator` for authenticated sessions, checked OT,
   encrypted records and fresh output masks. The garbler input arrays supplied
   to these wrappers EXCLUDE final masks (wrappers generate them). Direct
   circuit tests include masks only for synthetic reconstruction. No scheduler,
   durable state store or network RPC is supplied by this family registration.
7. Inject the J coordinates ONCE into the authenticated existing joint DP source
   prefix, keeping it zero until all results/validities and receipts are complete.
   Calibrate the existing joint sampler to the full workload including every
   coordinate. Recheck tail/approximation delta and noise no-wrap/resource bounds.
   Publish only its existing support-clamped, cross-signed sticky vector and
   canonical semantic release ID; recovery/retry must never draw fresh noise.
8. Replace the disabled client release body with the authenticated existing
   lifecycle reader. Validate both DP result signatures/evidence, payload,
   contract, snapshot and release ID before returning coordinates to the internal
   moment helper. The helper assumes authenticated, public support-clamped integer
   coordinates. Canonical first-minimum, slope rescaling and no inference remain.
9. Close deployment gates: both roles on pinned processes/hosts, PSI mismatch,
   swapped source columns, corrupted records/OT, stale profile, duplicate injection,
   crashes around commit, lost ACK, concurrent sticky replay. Test-only DSLite
   methods and reference noise are not substitutes for these gates.
10. Meet or obtain reviewer resolution of the measured scalar/envelope cost target
    before declaring N=10000,J=50 supported. No runner cap has been raised.

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
