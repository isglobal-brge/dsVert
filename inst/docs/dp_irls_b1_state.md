# B1 public path state

This is an internal, public-only synthetic stage driver. It exposes no remote
method, reads no source data, draws no noise and does not admit an MPC producer.

`R/dpIRLSContract.R` normalizes the seven signed field groups and validates the
unanimous custodian signatures against external pins. The root commits the full
contract, including the complete frozen authorization closure. Stage and child
identities have fresh v3 domains. Exact epsilon accounting includes pilot,
optimizer lanes, terminal audit and auxiliary allocations; retained observations
charge each lane once and never reduce the full reservation.

`R/dpIRLSState.R` implements:

* `.dsvert_dp_irls_store_create(path, signed_contract, trusted_pins, authority)`:
  explicit provisioning into a new private directory. It prechecks every signed
  arithmetic configuration using public zero-decoded payloads.
* `.dsvert_dp_irls_successor_prepare(...)`: verifies contract and committed
  predecessors, resolves the most recent signed H for score-only stages, builds
  the update input from authenticated state, runs `dp-irls-update`, reserves
  `(root,t)`, signs and persists the exact public bytes before acknowledgment.
* `.dsvert_dp_irls_successor_commit(...)`: accepts two matching authority records
  only, verifies both designated signatures and the local reservation, and
  durably retains the canonical composite. The next stage requires this record.
* `.dsvert_dp_irls_successor_accounting(...)`: conservatively charges prepared
  payload lanes even if the parent never completes. Retries add no charge.

The two authorities use separate stores. SQLite transactions, FULL synchronization,
an exclusive process lock and the unique root/stage key serialize competing
requests. The retained row-set digest detects missing or corrupt rows; stage
signatures authenticate their contents. Missing database files are never opened
with create flags. A provisioned directory prevents automatic database recreation.
Tests simulate process failure after PREPARE and COMMIT and require retained bytes
on retry, including after only one authority has committed.

These guarantees assume private local storage. Restoring an old complete database
and its entire directory by a privileged operator is not detectable without an
external monotonic witness. B4 must define that operational recovery boundary;
the B1 implementation has no automatic reset or new-root recovery path.

The client checks the complete returned chain with existing client trust helpers
and its independent R/gmp update implementation. Its `chain_complete` field means
all optimizer/audit stages are present; `complete` also requires no auxiliary
releases awaiting a later evidence adapter. Pilot history is an explicit,
unanimously signed digest, beta and composition-cost declaration. B1 does not
reopen historical pilot artifacts or run auxiliary producers.

Run only the B1 tests with the isolated runtime:

```sh
source /workspace/dsflower/.tmp/v3/env.sh
nice -n 10 timeout 14m Rscript tools/test-dp-irls-b1.R
```

The arithmetic ABI is in `dp_irls_arithmetic_v1.md`; the signed schema is in
`dp_irls_contract_v1.md`. The maintainer's Claude-session milestone review is
required before treating B1 as reviewed. No live or inference qualification is
implied by these synthetic tests.
