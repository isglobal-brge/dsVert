# Prepare softmax-gradient inputs by copying shares into the canonical `secure_mu_share` / `k2_y_share_fp` slots

Used by `ds.vertMultinomJointNewton` to reuse the existing
`glmRing63GenGradTriplesDS` + `k2GradientR1DS`

- `k2GradientR2DS` matvec pipeline on a per-class residual share already
  computed via `dsvertComputeResidualShareDS`.

The gradient pipeline computes \\X^\top (\mu - y)\\ internally, so this
helper:

- Sets `secure_mu_share = 0` (zero share).

- Sets `k2_y_share_fp = -residual_share` so the pipeline's \\\mu - y =
  0 - (-r) = r\\ gives the right direction without further sign
  flipping.

## Usage

``` r
dsvertPrepareMultinomGradDS(
  residual_key,
  is_outcome_server,
  n,
  session_id = NULL
)
```

## Arguments

- residual_key:

  Session slot holding a Ring127 residual share.

- is_outcome_server:

  Whether this server holds the outcome.

- n:

  Length of residual vector.

- session_id:

  MPC session id.

## Value

`list(stored = TRUE)`.
