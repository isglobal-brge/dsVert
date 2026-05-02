# Compute eta share in FixedPoint from full data shares and public beta

If an offset has been registered for this session via k2SetOffsetDS(),
the stored log-offset FP vector is added to THIS server's eta share
after the X \* beta computation. Mathematically this gives eta = X
beta + offset because the offset is plaintext on exactly one server, so
adding it to that server's share is equivalent to adding it to the
reconstructed eta. The other server's share is unchanged. No
cross-server round trip is required; the offset values never leave their
home server.

## Usage

``` r
k2ComputeEtaShareDS(
  beta_coord,
  beta_nl,
  intercept = 0,
  is_coordinator = TRUE,
  session_id = NULL,
  output_key = NULL
)
```

## Arguments

- beta_coord:

  Numeric vector. Coordinator-side coefficient slice used to compute eta
  share.

- beta_nl:

  Numeric vector. Non-label-side coefficient slice used to compute eta
  share.

- intercept:

  Numeric scalar. Intercept term added to the linear predictor.

- is_coordinator:

  Logical. TRUE if this server is acting as the coordinator (label)
  party.

- session_id:

  Character. Active MPC session identifier.

- output_key:

  Optional character. When set, the computed eta share is additionally
  stored under this session key (in addition to the standard slots
  `k2_eta_share_fp`, `k2_eta_share`, `secure_eta_share`). Used by
  `ds.vertMultinomJointNewton` to maintain K-1 parallel eta shares (one
  per non-reference class) across the same session without overwrite.
