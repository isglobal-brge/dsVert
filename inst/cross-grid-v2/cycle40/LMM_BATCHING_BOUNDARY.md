# Concrete durable batching boundary (read-only, cycle40)

Execution source 391742c/0a86516. No transport or native change in this cycle.
Compile reuse already exists; see cycle35/LMM_BATCHING_NEXT.md. New old-source
K5 evidence exceeds the release time ceiling by 1174.592s; no speedup is claimed.

The current server/client protocol cannot safely become a simple loop over
several existing single-envelope exchanges in one RPC:

1. `dsVert/R/exactGCTransportDS.R:.exact_gc_inbound_append` only recognizes a
   retry of **the last** committed (offset,end,hash). If a proposed batch appended
   A then B and lost its response, retrying A first would fail as a conflicting
   retry, even if A is authentic. Worker consumption/compaction means comparing
   the current spool bytes is not a sufficient general replacement.
2. `.exact_gc_outbound_offer_write` persists only one offered range/hash.
   `.exact_gc_exchange_impl` accepts an advancing ACK only at that offer's end
   and only when its start equals the previous durable ACK. Repeatedly writing
   several individual offers would overwrite the first and break cumulative ACK.
3. The same exchange stores just one `out_cache` envelope at a given read offset.
   `dsVertClient/R/exact_gc_transport.R` stores one pending envelope per direction
   and requires an exact single-envelope endpoint acknowledgment before advancing.
4. Larger scalar payloads remain constrained by the measured DSLite parser limit;
   batching must preserve individually bounded scalar payloads and a bounded total.

A future implementation therefore needs a bounded, durably identified batch
with complete authenticated member ranges/hashes and explicit retry/ACK rules,
including a response lost after partial or complete delivery. Validate all
members before publishing any bytes; validate exact retries even after native
worker consumption and spool compaction. This is implementation work, not a
new arithmetic impossibility or a request for an ultra spec.

Required regression cases beyond current single-envelope tests: response loss
after first/middle/final member; crash between segment publication and durable
state update; retry after compaction; changed early member; gaps/duplicates/
reordering; ACK rollback/partial/overrun; memory/scalar bounds; terminal state
with pending members. Compare actual opened integers and sticky DP bytes under
baseline/bilateral/unilateral/cold execution in separate source-pinned snapshots.
Do not touch the frozen LMM run or relax rounding/caps/epsilon/delta.
