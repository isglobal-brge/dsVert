# One-hot encode a categorical variable (server-side aggregate)

Return a server-side one-hot-encoded matrix for a single categorical
column, along with metadata (levels, row margins). This is the
prerequisite for cross-server chi-square: both servers share the level
set and the indicator counts via the already-deployed Beaver
cross-product infrastructure, allowing the client to assemble the K x L
contingency table without ever materialising an n-vector on the analyst
client.

## Usage

``` r
dsvertOneHotDS(
  data_name,
  var,
  levels = NULL,
  session_id = NULL,
  suppress_small_cells = TRUE
)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- var:

  Character. Name of the categorical column to encode.

- levels:

  Optional character vector. If supplied, use these as the canonical
  level set (useful when the client wants a fixed common level ordering
  across the two servers); otherwise `sort(unique(data[[var]]))` is
  used.

- session_id:

  MPC session id (required; the one-hot matrix is stored under this
  session for subsequent Beaver cross-product reduction).

- suppress_small_cells:

  Logical. If TRUE (default) suppress per-level row-margin counts below
  the DataSHIELD privacy threshold.

## Value

A list with elements:

- `levels`: character vector of category names (canonical)

- `row_margins`: integer vector (count per level)

- `n`: total complete-case count

- `n_na`: count of dropped NA rows

- `session_key`: key under which the n x K one-hot matrix is stored in
  the MPC session for the downstream Beaver stage.

## Details

The raw one-hot matrix itself is NOT returned to the client: only the
level set (character) and the row margin sums (per-level counts) come
back. The n*K indicator matrix is materialised transiently inside the
session for use by the downstream Beaver dot-product Aggregate, and is
stored in the MPC session under `k2_onehot_<var>_fp` (row-major n*K FP
vector) for the client orchestrator to reference via a session_id.

Privacy: the per-level row-margin counts are themselves an aggregate
(one integer per category) and are subject to the same
`datashield.privacyLevel` suppression rule as the existing
`dsvertContingencyDS` helper.
