# Receive transport-encrypted W (beta-Hessian weight) share

Counterpart to the W-sharing emitted by `dsvertOrdinalPatientDiffsDS`
(when called with `weight_output_key` + `weight_target_pk`). NL
transport- decrypts the sealed peer share and stores it as a Ring127
share in `output_key`. The two slots – own at OS, peer at NL – form an
additive Ring127 share of the per-patient W vector for downstream
`.ring127_vecmul` in the client's X^T diag(W) X assembly (#A empirical
beta-Hessian path, McCullagh 1980 Sec.2.5).

## Usage

``` r
dsvertOrdinalReceiveBetaWeightsDS(W_blob_key, output_key, n, session_id)
```

## Arguments

- W_blob_key:

  character. Session blob slot holding the sealed blob produced by
  `dsvertOrdinalPatientDiffsDS$W_sealed_blob`.

- output_key:

  character. Session slot to write the NL-side Ring127 share of W into.

- n:

  integer. Length of W vector (= n_obs).

- session_id:

  MPC session id.

## Value

list(stored = TRUE, n = , output_key = ).
