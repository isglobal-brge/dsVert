# Formal binomial/Poisson GLM frontdoor: promotion gate

Date: 2026-08-02

## Decision

The formal binomial/logit and Poisson/log GLM implementation is **not a
registered DataSHIELD method yet**.  The public `formal_analysis_id` route in
`dsVertClient` is sealed before datasource discovery and reports
`formal_glm_phase19_durable_r_dsi_release_bridge_not_promoted`.

This is an evidence gate, not a cosmetic readiness flag.  No legacy GLM
endpoint is re-enabled and the internal server candidate deliberately defines
no function ending in `DS`.

## What is already implemented and tested

The Go implementation contains the complete in-process computational chain:

1. authenticated Phase-1.8 materialization;
2. the full durable Phase-1.9 fan-in schedule;
3. Phase-1.5 streaming inference and validity propagation;
4. the common joint-DP bridge and one-draw exact-GC release;
5. durable release/replay state.

The productive Go tests exercise binomial and Poisson models for K=2, 3, 4
and 5 over `net.Pipe`, including sticky retry, tamper rejection and restart
state.  The common one-draw ledger input commitment also binds the ordered
validity-share transcripts from both roles, so a re-signed validity change
after a crash cannot reuse an already committed payload.

The new R contracts additionally verify:

- a canonical, server-owned analysis registry binding;
- a recomputed canonical digest of every normalized pinned Ed25519 peer key;
- exactly two server-selected compute/noise peers from the complete pinset;
- purpose binding to schema, artifact, Phase-1.5 plan, capsule, logical
  snapshot, registry generation and execution-path hashes;
- indistinguishable responses for an unknown analysis id and a selector
  mismatch;
- a client request containing only `analysis_id`, `data_name`, `family` and
  `formula_sha256` selectors;
- rejection of analyst epsilon, delta, bounds, seeds, rings, numeric backends,
  precision and role selection;
- zero DSI calls, zero relay starts and zero openings while the gate is shut;
- no operation count, request count or history-based denial policy.

## Exact missing production evidence

Promotion requires all five items below in the real R/DSI lifecycle:

1. `server_owned_all_k_analysis_registry_to_phase18_authorization_v1`;
2. `r_dsi_wrapper_for_phase19_full_durable_schedule_v1`;
3. `phase19_dp_shares_to_durable_common_one_draw_release_v1`;
4. `signed_public_release_adapter_bound_to_phase19_validity_v1`;
5. `local_multiprocess_dsi_e2e_restart_tamper_k2_k3_k4_k5_v1`.

In particular, the current Phase-1.9 command-line worker processes one block;
there is no promoted R coordinator that drives the complete durable schedule,
resumes it after process loss, consumes its final DP shares exactly once and
returns the signed common release through DSI.  Passing an in-memory Go test
cannot substitute for that lifecycle evidence.

## Promotion criteria

The remote method may be registered only when all of the following hold:

- the R server receives public selectors only and resolves every other value
  from immutable custodian configuration;
- every peer independently verifies the same registry, pinset, designated
  pair, snapshot, artifact, plan, capsule and execution-path commitments;
- the relay can reorder, duplicate, drop or alter traffic without changing an
  accepted result; alteration must be detected and dropping may only affect
  availability;
- restart at every durable boundary yields the same release or a clean,
  explicit failure, never a second noise draw for the same release identity;
- invalid Phase-1.9 arithmetic or admission shares cannot reach an opening;
- exactly one jointly sampled DP release is opened, with no intermediate
  gradient, Hessian, row, share, validity bit or model iterate exposed;
- real local multiprocess DSI tests pass for both families at K=2, 3, 4 and 5,
  including restart, replay, byte tampering, wrong peer, wrong registry,
  wrong snapshot and concurrent retry cases;
- the complete server, client, Go, package-check and remote-surface suites are
  green without adding a legacy endpoint or a readiness bypass.

## Defensible threat model after promotion

The intended confidentiality claim assumes at least one of the two designated
compute/noise peers is honest and does not collude with the other.  The analyst
may control the relay and all client-side routing: authenticated,
purpose-bound transcripts prevent that relay from silently substituting a
different accepted computation, although it can always deny service.  The
complete custodian pinset is fixed by server policy rather than by the client.

If both designated peers collude, or a custodian process and its persistent
secrets are fully compromised, additive shares can be reconstructed; the
package must not claim otherwise.  Differential privacy protects the released
statistic under its stated adjacency, clipping and contribution contract, not
arbitrary endpoint compromise or unrestricted non-DP auxiliary releases.

There is intentionally no request quota that refuses a scientifically valid
operation because a counter was exhausted.  Sticky retries of the same release
return the same draw. A future public formal-GLM capsule would still be subject
to the outer finite lifetime policy: one non-refundable unit per new capsule,
with exact `N * epsilon <= 8` and `N * delta < 1` composition.
