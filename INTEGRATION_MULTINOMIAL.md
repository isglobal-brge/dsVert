# Multinomial integration contract

The family is implemented behind new files. No shared producer, source RPC,
worker allowlist, same-owner method or generation-one route is enabled here.

Entry points:

| Layer | Single family registration / entry |
| --- | --- |
| Go | `exactGCRegisterMultinomialLossV1()` |
| Server | `.dsvert_dp_multinomial_grid_cross_register()` |
| Client | `.dsvert_dp_multinomial_grid_cross_register()`; public `dp_multinomial_grid()` |

Version is `multinomial_grid_cross_v1`, operation
`dp.multinomial-grid-cross.v1`, profile
`cross-grid-multinomial-piecewise-q16-v1`. Both validators reconstruct all
signed metadata, including the pinned profile hash, error allowances, caps,
source layout and canonical class/candidate order. Required states remain
`cross_owner_exact_gc_materialized` and `exact_gc_to_joint_dp_vector_v1`;
the strings alone cannot authorize release.

Exactly this wiring remains for the fused producer:

1. Register the descriptor in the new cross-grid dispatch only. Validate both
   custodians' signed contract/schema and the approved resource plan before
   resolving protected input. Match the Go profile/hash to the numeric contract.
   Add strict Go signed-contract parsing/adaptation for `class_order`,
   `non_reference_order`, `reference`, class-major `beta_encoded` and the new
   numeric fields; the frozen binomial/Poisson Go envelope does not accept this
   family payload. Preserve unknown-field rejection and canonical hash parity.
2. Reuse frozen Ring128 source records, categorical outcome encoding and
   recipient-specific private PSI/alignment evidence. Resolve one signed
   category per patient; ambiguous/missing categories must be invalid, not
   averaged. Form exact f100 partial predictors in sufficiently wide shares,
   with the intercept once per nonreference class. Never round per owner.
   Widen Ring128 source shares securely with the required carry correction;
   simply zero-extending each additive residue to Ring192 is incorrect when
   the original ring sum wraps. This conversion belongs inside the producer.
3. Invoke `registration.Source(exactGCFamilyLossSpec{Classes, GridBits, Cap})`
   per candidate. Candidate/class order is signed; reference score is zero.
   The generator validates its public arguments before circuit compilation.
4. Circuit ABI uses Ring192 residues: garbler inputs have `(K-1)+4` coordinates,
   evaluator inputs `(K-1)+2`. First come the K-1 additive f100 predictor shares,
   then additive outcome and private complete-case/alignment bit shares.
   Garbler appends an independent uniform loss mask and a guard-bit mask.
   Output is `[quantized_loss-loss_mask, guard XOR guard_mask]`. Preserve both
   shares: never return an unmasked row loss, predictor, label, guard or mask.
5. Reduce row contributions into per-candidate additive sums and combine guards
   privately. Any failed guard aborts through the transcript-safe error boundary.
   Bind actual circuit/profile identity, signed spec, source commitments,
   row/candidate traversal, capacity and output-share digests into bilateral
   result evidence. The integer loss clamp is compulsory.
6. Inject authenticated sum shares once into the zero release prefix, then run
   the existing two-authority joint-DP vector protocol with the signed epsilon,
   delta, adjacency, caps and sensitivities. Authenticate the released vector,
   apply the established public release clamp and sticky semantic publication.
   Only this authenticated DP vector may reach client postprocessing.
7. Replace the client's fixed failing release seam with that authenticated
   lifecycle, preserving local validation before any DataSHIELD call. The
   postprocessor uses canonical first-minimum selection and reports no SEs.
8. Run actual two-peer protected-input tests, tampered-evidence/guard tests,
   replay tests and the full benchmark envelope. The supplied DSLite tool uses
   public synthetic rows, test-only noise and a test-tagged Go reference; it
   cannot serve as evidence for production PSI, MPC or joint-DP execution.

The Go plaintext bridge is `_test.go` plus build tag
`dsvert_family_reference_test`. Compile it only with `go test -c -tags=...`;
never add it to the executable command dispatch. R integer oracles remain
under `tests/testthat/` only.

The supplied source is a standalone Boolean adapter for correctness and cost
measurement. It currently performs its ABI share additions and exponential sum
inside that circuit. The scalable producer must move permitted linear sums
and public-coefficient products to shares and replace the nonlinear evaluator
with a cheaper secure implementation. Component profiles alone already exceed
the cost target, so removing adapter overhead will not suffice. Do not promote
this adapter as the reviewer's compliant arithmetic-share producer.

See `STATUS_MULTINOMIAL.md` for measured tests/cost and unresolved promotion
gates, and `NUMERIC_CERTIFICATE_MULTINOMIAL.md` for approximation-aware utility.
