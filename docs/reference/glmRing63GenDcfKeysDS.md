# Generate DCF keys on server and distribute to DCF parties

Called on a NON-DCF server to generate DCF keys securely. The client
never sees the key values – only opaque transport-encrypted blobs. This
prevents a malicious client from crafting DCF keys to leak information.

## Usage

``` r
glmRing63GenDcfKeysDS(
  dcf0_pk,
  dcf1_pk,
  family,
  n,
  frac_bits,
  num_intervals,
  ring = 63L,
  session_id = NULL
)
```

## Arguments

- dcf0_pk, dcf1_pk:

  Character. Transport PKs of DCF parties (base64url).

- family:

  Character. "sigmoid" or "poisson".

- n:

  Integer. Number of observations.

- frac_bits:

  Integer. Fractional bits for Ring63 FP.

- num_intervals:

  Integer. Number of spline intervals.

- ring:

  Integer 63 (default) or 127. Selects secret-share ring (task \#116
  Cox/LMM STRICT migration). Ring127 emits 16-byte DCF key records for
  the Uint128 pipeline; Ring63 keeps the 8-byte records.

- session_id:

  Character or NULL.

## Value

List with encrypted blobs for each DCF party.
