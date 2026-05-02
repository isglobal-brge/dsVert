# Register an offset column for an open GLM session (server-side)

Register a plaintext per-patient offset vector to be added to this
server's eta share during every subsequent `k2ComputeEtaShareDS` call in
the named session. Used to support rate-scale Poisson /
negative-binomial regressions of the form

    log E[y] = X beta + offset

where the offset is typically `log(person_years)` or `log(exposure)` and
is held on the server that also holds the outcome variable.

## Usage

``` r
k2SetOffsetDS(data_name, offset_column, session_id = NULL)
```

## Arguments

- data_name:

  Character. Aligned data-frame name on this server.

- offset_column:

  Character. Name of a numeric column in `data_name` holding the offset
  on the linear-predictor scale (i.e., already log-transformed where
  appropriate).

- session_id:

  Character. GLM session identifier.

## Value

Named list with `stored = TRUE` and the length of the stored FP vector.

## Details

The offset is added to this server's eta share in-place; the other DCF
party's share is unchanged. Because Ring63 additive sharing is linear,
the reconstructed eta is
`eta_own + eta_peer + offset = X beta + offset`.

Offsets never leave their home server; the client only orchestrates the
registration call to the server that owns the offset column.
