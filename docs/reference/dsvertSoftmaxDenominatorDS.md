# Sum K-1 exp(eta_k) shares + party-0 constant 1 -\> denominator share

Computes the softmax denominator share `D = 1 + Sum_k exp(eta_k)` via
K-1 sequential `k2-ring127-affine-combine` calls. Party 0 also adds the
constant 1 at the first step; party 1 does not (additive share
convention).

## Usage

``` r
dsvertSoftmaxDenominatorDS(
  exp_eta_keys,
  output_key,
  is_party0 = FALSE,
  n,
  session_id = NULL
)
```

## Arguments

- exp_eta_keys:

  Character vector of session slots holding the per-class `exp(eta_k)`
  shares.

- output_key:

  Session slot to store the summed D share.

- is_party0:

  Whether this server is party 0 (adds the +1 constant).

- n:

  Length of each share.

- session_id:

  MPC session id.
