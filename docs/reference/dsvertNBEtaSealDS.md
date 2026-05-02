# Per-patient mu seal on non-label server for NB full-reg theta MLE

Computes \\\eta_i^s = X_i^s \beta\\ on this (non- label) server from the
locally-held feature partition and a client- supplied beta-slice, then
transport-seals the vector for the label server. Used by
`ds.vertNBFullRegTheta(variant="full_reg")` to get per-patient mu_i to
the outcome server without revealing them to the client.

Inter-server leakage (documented in P3 budget): the label server learns
`eta_nl_i` per patient after decryption. Equivalent to sharing the
non-label's BLUE fitted value with the outcome holder – a weaker
disclosure than raw features. The client still sees only scalar
aggregates (Sumpsi, Sumlog terms).

## Usage

``` r
dsvertNBEtaSealDS(data_name, x_vars, beta_values, target_pk, session_id = NULL)
```

## Arguments

- data_name:

  Character. Data frame with the feature columns.

- x_vars:

  Character vector. Non-label feature names on this server.

- beta_values:

  Numeric vector same length as `x_vars`: the non-label beta-slice from
  a prior Poisson fit (client-provided, since beta is revealed at
  convergence).

- target_pk:

  Character. Transport PK (base64url) of the label server that should
  receive the sealed `eta_nl` vector.

- session_id:

  Character.

## Value

List with `sealed` (base64url blob).
