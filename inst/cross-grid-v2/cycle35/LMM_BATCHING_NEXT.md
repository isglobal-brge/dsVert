# LMM batching boundary — read-only cycle35 review

Current source 8214373 / 5b6458f; no transport/native patch in this cycle.

Compile reuse is present, not pending:
- `cross_grid_grouped_route.go:groupedRouteNormalize` caches the compiled
  program by the complete emitted public source. Private words, validity,
  masks and execution randomness remain fresh.
- `cross_grid_stage_conversion.go:crossGridStageBuildConversion` caches public
  programs per chunk count, draws fresh masks, and runs correlation/opening/
  private-carry-sign for each chunk. Preserve the corrected signed identity.
- `k2_exact_gc_lmm_staged.go:lmm.lift` reuses the full-chunk public program and
  recompiles the tail. These caches are already covered by cycle20 proof.

Transport batching is a separate protocol change:
- `dsVertClient/R/exact_gc_transport.R` has one pending envelope per direction.
  `read_offset[source]` advances only after the recipient acknowledges exactly
  `offset + chunk_bytes`. The source is not redundantly polled while its sole
  envelope is pending. Retries keep unchanged envelopes/offsets; altered
  unacknowledged bytes, byte gaps and rollback acknowledgments are rejected.
- `dsVert/R/exactGCTransportDS.R` coalesces available spool fragments with a
  fixed public 50 ms window; the default raw envelope is 480 KiB. Although the
  transport validates configurations up to 8 MiB, **do not simply raise the
  DSLite envelope size**: the existing portable-limit regression documents
  that DSLite 1.8 accepts 786432-character scalars but rejects 1048576. Base64
  payload plus metadata must fit the actual transport's scalar bound.
- Thus an authenticated multi-envelope batch needs bounded individual payload
  scalars, ordered offset/hash/signature validation for every member, bounded
  total request/response memory, idempotent exact retry and explicit cumulative
  acknowledgment semantics. It cannot merely concatenate larger base64 text
  into the current scalar argument or advance offsets on successful polling.

Before changing defaults, use new snapshots to compare the frozen baseline
against the candidate implementation: identical opened integer output and
sticky DP bytes, both bilateral fresh-attempt and unilateral committed replay,
cold/source/stage tamper, unchanged arithmetic/caps/privacy, and actual complete
serialized-RPC bytes/time plus native cost. Keep the 24h/15min lease setup.
Tests to extend are `test-exact-gc-transport.R` in both packages and staged
conversion/normalization recovery tests. Test fragment boundaries, duplicate
batches, partial delivery/retry, changed envelope, gaps, ACK rollback and both
peers' terminal states. Do not resume the obsolete frozen queue or infer speedup
from compile savings, chunk counts, native-only timings or censored releases.
