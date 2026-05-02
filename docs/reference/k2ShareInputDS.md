# Share local data with peer (FixedPoint shares)

Share local data with peer (FixedPoint shares)

## Usage

``` r
k2ShareInputDS(
  data_name,
  x_vars,
  y_var = NULL,
  peer_pk,
  ring = 63L,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- x_vars:

  Character vector. Non-label feature names on this server.

- y_var:

  Character. Name of the outcome column on the label server.

- peer_pk:

  Character (base64url). Peer party's transport public key for sealed
  shares.

- ring:

  Integer 63 (default) or 127. Selects secret-share ring (task \#116
  Cox/LMM STRICT migration). Ring127 routes through 16-byte Uint128
  records via k2-float-to-fp + k2-split-fp-share with ring="ring127";
  Ring63 keeps the 8-byte pipeline.

- session_id:

  Character. Active MPC session identifier.
