# Remove dsVert-internal columns from the aligned data frame

Aggregate helper. Strips any column whose name starts with `__dsvert_`
(e.g. `__dsvert_lmm_w`, `__dsvert_r2`) that previous methods added to
the aligned data frame. Combined with the existing `mpcCleanupDS` (wipes
MPC session) this provides a complete per-method teardown so running
multiple dsVert methods sequentially cannot corrupt each other's state.

Convention: every dsVert server helper that materialises a new column on
the data frame prefixes the name with `__dsvert_`. Client wrappers
should call this at the end of their on.exit cleanup chain to restore
the data frame to its post-PSI state.

## Usage

``` r
dsvertResetDataFrameDS(data_name, keep = character(0))
```

## Arguments

- data_name:

  Aligned data-frame name.

- keep:

  Optional character vector of column names to preserve (e.g. synthetic
  columns that the caller added on purpose and wants to keep –
  "cluster", "time", "event", "age_q").

## Value

list(columns_removed = character, n_removed = integer).
