# Public synthetic release records

Future completed cells from the structured, NB, categorical and LASSO harnesses
include `recomputation`, version `dsvert-public-synthetic-release-replay-v1`.
`DSVERT_GRID_VALIDATION_METRICS_PATH` writes the complete cell as JSON; the same
JSON is emitted to stdout. Existing v1.3.0 records are unchanged and do not gain
missing seeds retroactively. A failed release exits nonzero and cannot produce
a successful release record; diagnostic/error logs are not release evidence.

The embedded record contains:

- The full workload containing the signed grid contract, signed schema and
  public admission policy. LASSO also retains its signed postprocessing contract.
- Every exact raw integer coordinate, count first, as canonical decimal
  strings, together with its SHA-256 (UTF-8, one coordinate per LF-terminated
  line). `criterion_indices` is one-based into this complete vector and
  `exact_candidate_criterion_integers` preserves the corresponding candidate
  order, including structured workloads with several coordinates per candidate.
- Every released scaled integer coordinate, before conversion to R doubles.
- For native convolution/Gaussian paths, the complete production share and
  finalizer command, JSON input and output. These include the test peer seeds,
  commitments, transcript/release hashes, chunk geometry, scale shifts, bounds,
  synthetic source shares, sampler identifiers and full plan metadata.
- For the retained exact-GC reference route, both test peer seeds and the full
  purpose-bound worker policies in `peer_draws`.
- The public provenance certificate when the public API actually released it.

JSON uses 17 significant digits for finite R doubles so signed numeric specs
and native plan outputs round-trip exactly; exact integers stay decimal strings.
The usual `jsonlite` `digits=NA` emits only 15 significant digits and is not
sufficient for these replay records. JSON arrays remain arrays for singleton
chunks as well.

The native oracle calls the production sampler and finalizer and checks that
the captured source shares reconstruct the independent exact raw integers.
For oracle-only evaluation it first constructs synthetic additive source
shares from those integers and stores the resulting concrete native inputs;
such a record remains `oracle_only` and supplies no authenticated-release claim.
Missing peers, overlapping/incomplete chunks, mismatched source integers and
different native outputs fail the replay.

Capture is installed only by these isolated fixture harnesses, after requiring
the `cross-grid-synthetic` dataset and generated `synthetic-...` patient IDs.
The record is explicitly classified `public-synthetic-test-fixture`; seed
scope is `test-harness-only-never-production-secrets`. No production RPC,
server profile, identity signing key, noise root or transport secret is added
to the record. Do not install `synthetic_replay_record.R` in a server profile.

To recompute a completed native record without the original state directory:

```sh
python3 dsVert/inst/cross-grid-v2/integrator-validation/run-structured-noise-replay.py \
  /path/to/cell.json --binary /path/to/dsvert-mpc
```

Use the matching source/worker version identified in the record. For a
reference exact-GC record, substitute `--oracle-binary` and the executable built
by `prepare-release-workspace.sh`. An independent implementation can instead
consume the same exact integers, complete stream contexts and test seeds.
The script checks record consistency and bitwise numerical recomputation;
certificate authentication still uses the package's certificate validator.
