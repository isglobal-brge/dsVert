# DP admission audit: bounded lifetime, no request quota

Original audit: 2026-08-01. Lifetime-contract update: 2026-08-09.

## Required contract

- Formal differential privacy is bounded across at most `N` distinct immutable
  workload capsules per stable privacy accountant namespace, where the
  server-owned option
  `dsvert.dp.lifetime_max_distinct_capsules` defaults to `1`.
- One stable, unique accountant namespace must span domain, cohort, policy,
  pinset and ledger reconfiguration for each protected privacy universe. This
  is currently a custodial deployment assumption: dsVert neither enforces
  cross-namespace uniqueness nor automatically migrates reservations.
- Every capsule has the same fixed policy-owned epsilon and delta. Exact decimal
  arithmetic must prove `N * epsilon <= 8` and `N * delta < 1` before the policy
  can become active.
- The allocator commit is the charge point. It writes one durable reservation
  before protected-source access or sampling. A committed reservation remains
  charged if the protocol is later abandoned and is never refunded.
- Replaying or post-processing the exact same capsule and public release
  instance is unlimited, byte-sticky and free. It does not advance the allocator
  or change accuracy.
- Each capsule may publish at most one public `release_instance`. PREPARE may
  persist sibling candidates, but the first valid START at a designated peer
  irrevocably claims one instance before local staged-source access or sampling.
  A release-domain rotation may select another candidate only before that claim;
  afterwards the exact instance must continue, restore or fail closed. A
  post-publication loss must restore and replay it or fail closed, never
  resample it.
- The fixed, detail-free `[dsvert_dp_lifetime_budget_exhausted:v1]` condition is
  an opaque terminal union: global `N` is exhausted, or the requested capsule
  cannot safely advance because its irrevocable instance claim/publication
  binding already exists and the exact instance cannot continue or replay. It
  does not imply `remaining_distinct_capsules == 0`; separating the causes
  would reveal state. It is not a request counter or rate limit.
- Byte, memory, dimensional, inactivity, lock and backpressure bounds remain
  separate availability and integrity controls.

## Promoted capsule path

The lifetime boundary spans these production components:

- `R/jointDPControlPlane.R` validates the exact lifetime contract and burns one
  unit at allocator commit;
- `R/capsuleAllocatorRegistryIntegration.R` creates a dense authenticated
  reservation journal entry for every burn;
- `R/capsuleRegistry.R` mirrors those reservations and reports the remaining
  distinct-capsule units;
- `R/jointDPVectorCapsuleDS.R` persists the per-peer, per-capsule claim at the
  first valid START and rejects sibling progression before another sampler can
  run;
- `R/jointDPVectorReleaseLedger.R` records publication separately and enforces
  one public instance per capsule; and
- `R/jointDPCapsuleStatusDS.R` reports and cross-validates reservation and
  publication telemetry.

The pre-release path accepts only `dsvert-joint-dp-control-v3` and
`dsvert-joint-dp-capsule-identity-v3`, which bind the lifetime fields and
biomedical workload v7. V2 artifacts are legacy and fail closed; they are not
automatically migrated or re-signed. Rollout requires empty DP capsule state or
a future audited offline migration.

The authenticated allocator/registry state binds
`operation_accounting = "one_per_distinct_capsule_allocator_commit"`,
`operation_limit = TRUE`, and `history_can_deny_operation = TRUE`. Public status
also binds `request_limit = FALSE`,
`accuracy_depends_on_request_history = FALSE`,
`reuse = "unlimited_sticky_postprocessing"`, and
`new_capsules = "allowed_until_authenticated_lifetime_bound"`.

Manifest draft/sign/build, data-free plan, source transport and client-only
post-processing remain phase-local non-admission operations. Their local
`operation_limit = FALSE` or `history_can_deny_operation = FALSE` flags are
therefore intentional and must not be read as a bypass of the earlier allocator
commit. No protected source or sampler path is eligible without the committed
reservation.

`capsules_created` counts all durable reservation burns. `releases_published`
counts only public instances and must never exceed `capsules_created`.
`remaining_distinct_capsules` is derived from reservations, not publications,
so an abandoned commit cannot recreate budget.

## Retired request-history code

The geometric implementation remains solely behind the non-exported
`.test_only_allow_local_anchor` constructor flag for compatibility tests and
ledger-upgrade evidence. The production policy builder does not read
`dsvert.dp.enabled`, `dsvert.dp.decay` or
`dsvert.dp.composition_partitions`. Its v9 schema has no decay, per-request
allocation or partition fields; the finite lifetime capsule count is a distinct
server-owned policy field.

The public calibrator likewise has no decay, release-index, partition or
analyst-controlled lifetime-total aliases. Existing retired ledgers remain
audit evidence and cannot authorize a production release.

## Other fail-closed conditions

The following remain distinct from lifetime exhaustion:

- invalid adjacency, bounds, fixed domains, dimensions or non-finite input;
- a changed immutable snapshot/policy or invalid contribution contract;
- authentication, signature, pin, ledger-integrity or rollback-continuity
  failure;
- missing MPC capability, unavailable peer, lock contention, timeout, disk
  exhaustion, payload-size violation or transport backpressure; and
- a statistically non-identifiable or numerically unsupported specification.

These conditions use their own typed/public failure boundary and do not refund a
reservation that was already committed.

## Rollback boundary

At least one designated non-colluding peer must retain and use its complete
authenticated monotonic history. Simultaneous rollback or loss of every peer store to mutually
consistent old images cannot be detected from those images alone and is outside
the package model unless an independent linearizable anchor covers the relevant
head. A restored or replacement service must never interpret missing history as
fresh lifetime allowance inside the stated model. Nor may reconfiguration mint
a fresh accountant namespace for the same protected privacy universe; custodians
must preserve the stable namespace and its reservation history.

The wire/SQLite index is additionally restricted to the largest exactly
representable R double integer, `2^53 - 1`. That numeric/storage ceiling is not
the privacy limit; active policy normally stops at the much smaller configured
`N`.
