# Generic strata-aware cumulative sum on an FP share vector

Applies k2-fp-cumsum to the share at `input_key` (optionally with strata
from ss\$k2_cox_strata), storing the result at `output_key`. Local on
shares: cumsum(share_A) + cumsum(share_B) = cumsum(share_A + share_B) by
linearity of cumulative sum.

## Usage

``` r
dsvertCoxPathBCumsumDS(
  input_key,
  output_key,
  reverse = TRUE,
  session_id = NULL,
  ring = NULL
)
```

## Arguments

- input_key:

  Session slot holding the input FP share vector.

- output_key:

  Session slot to receive the cumsum FP share.

- reverse:

  Logical. TRUE = right-to-left cumulative sum (used for risk-set
  weighted averages in Cox); FALSE = left-to-right.

- session_id:

  MPC session id.

- ring:

  Integer 63 (default) or 127. Falls back to the session- stored
  `ss$k2_ring` if not supplied.

## Value

list(stored = TRUE, output_key).
