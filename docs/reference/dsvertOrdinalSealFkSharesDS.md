# Seal F_k shares for inter-server reveal to outcome server

Non-outcome server transport-encrypts its Ring127 F_k shares to the
outcome server's PK so the outcome server can assemble plaintext F per
patient. Cox-class inter-server reveal.

## Usage

``` r
dsvertOrdinalSealFkSharesDS(F_keys, target_pk, session_id = NULL)
```

## Arguments

- F_keys:

  character vector of session slot keys holding F_k shares.

- target_pk:

  outcome server transport PK (base64url).

- session_id:

  MPC session id.

## Value

list(sealed = base64url blob).
