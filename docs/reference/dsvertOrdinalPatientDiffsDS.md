# Ordinal joint Newton: per-patient F differences for the threshold update

Server-side aggregate that consumes the per-class cumulative-probability
shares (or plaintext F values relayed from the outcome server, mode b)
and emits the per-patient class indicator-minus-F differences used by
the joint Newton Hessian and gradient. Non-disclosive: only aggregate
summaries (sum_residual_fp, weight aggregates) are revealed at the audit
boundary; per-patient values stay share-secret.

## Usage

``` r
dsvertOrdinalPatientDiffsDS(
  data_name = NULL,
  indicator_cols = NULL,
  level_names = NULL,
  F_plaintext_b64 = NULL,
  peer_F_blob_key = NULL,
  F_keys = NULL,
  x_vars_label = NULL,
  beta_values_label = NULL,
  beta_intercept = 0,
  peer_eta_blob_key = NULL,
  theta_values = NULL,
  output_key = NULL,
  weight_output_key = NULL,
  weight_target_pk = NULL,
  cross_output_keys = NULL,
  cross_target_pk = NULL,
  n = NULL,
  is_outcome_server = FALSE,
  session_id = NULL
)
```

## Arguments

- data_name:

  Name of the aligned data frame on each server.

- indicator_cols:

  Character vector of integer-coded class indicator columns (one-hot) on
  the outcome server.

- level_names:

  Character vector of class names matching `indicator_cols`.

- F_plaintext_b64:

  Optional: base64url-encoded plaintext F vector relayed from OS for
  mode b (eta-reveal disabled).

- peer_F_blob_key:

  Optional: session-slot key for the encrypted peer F-share blob.

- F_keys:

  Character vector of session keys holding per-class F shares.

- output_key:

  Session slot to store the resulting T_i vector.

- weight_output_key:

  Session slot to store the W_i weights.

- weight_target_pk:

  Recipient PK for the encrypted weights blob.

- cross_output_keys:

  Per-class cross-block session slots.

- cross_target_pk:

  Recipient PK for the encrypted cross-block blob.

- n:

  Integer patient count.

- is_outcome_server:

  Logical. TRUE on the server holding the outcome.

- session_id:

  MPC session id.

## Value

list with stored = TRUE and metadata about the Beaver round to be
consumed by the client orchestrator.
