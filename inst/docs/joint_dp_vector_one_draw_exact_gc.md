# One-draw joint-DP vector exact-GC integration

The scalar Laplace biomedical-vector route uses
`joint-dp-vector-laplace-v3`. Two pinned, non-colluding compute peers jointly
produce one global discrete-Laplace draw inside exact GC. The current public
cost-policy ceiling is one total coordinate; wider Laplace vectors use the
independent-complete-draw convolution backend. The DSI client is only an
authenticated ciphertext relay.

## Immutable selection

`backend_selection` is computed from total public coordinate count while the
signed manifest is built, before a source share or sticky seed is read. It is
included in the release contract. Timeouts, retries, reconnects and worker
failures may retry the same selected operation, but cannot change its backend.
The exact-GC plan assessment, one-coordinate promotion ceiling and resulting
cost-policy decision are all bound into the manifest. A transient runtime
failure is never a reason to switch to convolution.

The operation ID and state keys are deterministic functions of the manifest,
release contract, backend selection, transcript, chunk index and circuit
digest. A retry therefore cannot request fresh noise or a different circuit.

## Existing DSI surface

No new AggregateMethod is required. The client uses only:

- `exactGCTransportInitDS`
- `exactGCBindPeersDS`
- `exactGCExchangeDS`
- `exactGCAbortDS`

The existing `dsvertJointDPVectorStartDS` is the purpose-specific producer. It
stages the source internally and starts the worker; the generic endpoints
cannot stage arbitrary input or consume an output.

## Capsule coupling contract

The vector capsule must perform these steps atomically with its signed and
durable state transitions:

1. Store the exact-GC backend selection in the release contract and verify that
   the scalar release is inside both the one-coordinate promotion ceiling and
   the worker's certified `maximum_chunk_coordinates` (at most 128).
2. Establish the exact-GC transport session for the two designated peers
   before `dsvertJointDPVectorStartDS`.
3. Add that `session_id` to `StartDS`. Map prepare commitments to garbler and
   evaluator by pinned identity with
   `.dsvert_joint_dp_vector_exact_gc_role_bindings()`, compile the public worker
   contract, build its deterministic binding, and call
   `.dsvert_joint_dp_vector_exact_gc_start()`.
4. Return and cross-sign only the adapter's public initialization metadata.
   The client extracts both states and calls
   `.dsvert_joint_dp_vector_exact_gc_run()` for the same binding.
5. In `ResultDS`, call `.dsvert_joint_dp_vector_exact_gc_consume()` with a
   transactional callback that durably stores the output share, validity share
   and binding hash. The adapter peeks, commits, and only then consumes.
6. Include the validity share inside the existing encrypted final-share blob.
   At release, require both binding hashes, XOR the validity shares to one and
   call `.dsvert_joint_dp_vector_exact_gc_finalize()`. It reconstructs only the
   already-clamped DP output and rejects a value beyond its fixed public bound.

The analyst never receives a source share, private seed, random stream, output
share, validity share or pre-clamp value. Each peer sees only its own protected
inputs and shares; neither peer receives the other peer's seed or source share.
