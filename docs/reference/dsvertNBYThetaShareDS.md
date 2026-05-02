# Label-side: re-share (y + theta) into Ring127 additive shares

Per Newton-theta iter, the score formula's last term is \\\sum_i (y_i +
\theta) / (\theta + \mu_i)\\. With mu_i in shares and (y_i + theta)
plaintext at label only (y is label's data, theta a scalar from coord),
the Beaver vecmul of `share((y+theta)) x share(1/(theta+mu))` requires
(y + theta) to be in shares too. Label generates a fresh uniform Ring127
mask r per call, keeps `share_label = (y + theta)_FP - r` as its share,
and transports the mask r as the peer's share to NL. After this call:

- Label's session: `k2_nb_yt_share_fp = share_label`

- NL receives mask via `dsvertNBYThetaShareReceiveDS` and stores it in
  `k2_nb_yt_share_fp`.

Both parties hold valid Ring127 additive shares of `(y + theta)` with no
per-patient leakage (mask is uniform random; share_label is
masked-by-uniform, also uniform).

## Usage

``` r
dsvertNBYThetaShareDS(theta, target_pk, session_id = NULL)
```

## Arguments

- theta:

  Numeric scalar. The current Newton iterate value.

- target_pk:

  Character. Transport PK of the NL server.

- session_id:

  Character.

## Value

List with `sealed` (transport-encrypted mask blob, base64url), `n`.
