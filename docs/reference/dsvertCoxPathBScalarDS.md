# Compute scalar share of Sum_i w_i \* share(i) where w is plaintext at both parties

Multiplies share at `input_key` element-wise by plaintext vector at
`weight_key` (plaintext means both parties hold identical bytes – e.g.
k2_cox_delta_fp or cox_n_W1_fp). Uses k2-fp-vec-mul (local on share x
plaintext) then k2-fp-sum to produce a scalar share. Used for the "x
delta" step in Fisher term 2 aggregation.

## Usage

``` r
dsvertCoxPathBScalarDS(
  input_key,
  weight_key = NULL,
  session_id = NULL,
  ring = NULL
)
```

## Arguments

- input_key:

  Session slot with FP share vector (e.g. the result of a Beaver product
  left over at cox_pb\_\<...\>\_fp).

- weight_key:

  Session slot with plaintext FP weight vector (e.g. "k2_cox_delta_fp").
  Pass NULL to skip the weight step.

- session_id:

  MPC session id.

- ring:

  Integer 63 (default) or 127. Falls back to the session- stored
  `ss$k2_ring` if not supplied.

## Value

list(scalar_share_fp = 8/16-byte base64).
