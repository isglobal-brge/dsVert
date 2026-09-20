# Retained Cox oracle source attribution

K2, K3 and K5 completed the source-only N400/P5/grid2/epsilon8 harness with
exit code zero. All three independently produced the exact-coordinate
commitment `ba5d77ddffabca8ce5b9be5f516aee3662b90b6e44a2ef0bfb886da6c8bb950d`.
Original logs, metrics and snapshot manifests remain unchanged. Their paths,
hashes and original checkout HEADs are retained in `ORACLE_SUMMARY.json`.

The byte audit rehashes the immutable snapshots and compares every tracked
package R, src and inst file, DESCRIPTION, NAMESPACE and test helper against
the target workspace. This includes production native binaries, all Go
oracle/sampler source, numeric profiles, signed-source code and the complete
oracle harness. The manifest-generator regression `test_release_manifest.py`
is excluded because the oracle harness does not import or execute it.

K5 matches the target dependency bytes exactly. K2/K3 differ only in
`dsVertClient/R/exact_gc_transport.R`: the target adds the Cox staged operation
name, its output type, and ring/scale/purpose validation. The script pins the
exact reviewed old and new SHA256 values; any other dependency delta fails.
These additions are unused with `ORACLE_ONLY=1` and `REAL_COUNT=0`: the exported
Cox release and staged executor are bypassed. PSI uses existing operations,
and `grid_oracle_noise(..., synthetic_staged=TRUE)` compiles the signed noise
plan without invoking the Cox runner. The independent direct-risk-set integer
oracle and real sampler oracle are byte-identical for all topologies.

`ORACLE_SOURCE_EQUIVALENCE_DRAFT.json` records the current-byte audit, including
dirty source status. It is not committed-pair evidence. The script's default
mode was checked to reject the currently uncommitted harness and produce no
bound metrics.

The final clean-source audit completed successfully after the source commits using:

```sh
python3 integrator-evidence/cox-ultra/bind-oracle-records.py < /dev/null
```

Default mode requires clean tracked source and no untracked source files
(generated `__pycache__` entries are ignored), checks HEAD again after auditing,
and refuses to overwrite an existing bound-record directory. It creates
`ORACLE_SOURCE_EQUIVALENCE.json` and `oracles-bound/cox-k{2,3,5}.json`. Copies
retain the original source commits and link the original metrics and audit by
hash; only the copies receive the audited target source pair. This is explicit
source-equivalence attribution of existing oracle results, not a claim that
the oracle was rerun on those commits. No release manifest is changed.

Final binding: server `c97cd193c06dbae695792b4a03644c05fa733f8f`, client `28be3cd6fea312d8f1c2442c810b453ad81080ce`. The three bound records were consumed by the family-only release-manifest generator after both small signed native proofs passed. See `MANIFEST_VALIDATION.json` and `FINAL_MANIFEST_REVIEW.md`.
