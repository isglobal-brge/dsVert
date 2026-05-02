# Seal non-label eta^nl vector for outcome-server reveal

Computes eta^nl = X^nl \* beta^nl locally and transport- seals to
outcome server's PK. Bypasses the F-reveal Ring127 ULP cancellation
path; OS assembles full eta and computes F_k, P_k, T_i via
Machler-stable log1mexp plaintext formulas.

## Usage

``` r
dsvertOrdinalSealEtaDS(
  data_name,
  x_vars,
  beta_values,
  target_pk,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- x_vars:

  Character vector. Non-label feature names on this server.

- beta_values:

  Numeric vector. Coefficient slice corresponding to `x_vars`.

- target_pk:

  Character (base64url). Transport public key of the recipient server.

- session_id:

  Character. Active MPC session identifier.
