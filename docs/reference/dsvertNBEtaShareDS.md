# NL-side: split eta^nl into Ring127 additive shares

Replaces `dsvertNBEtaSealDS` (which transported eta^nl plaintext to
label, violating D-INV-4). Computes eta^nl = X^nl beta plaintext locally
on the non-label server, FP-encodes in Ring127 (fracBits=50), and splits
into uniform additive shares:

- `own_share`: this server retains; stored as `ss$k2_nb_eta_share_fp`
  (this server's Ring127 share of eta_total – for the NL server,
  eta_total share == eta^nl share because NL contributes nothing to
  eta_label or beta_0).

- `peer_share`: returned in the transport-encrypted blob to be relayed
  to the label server.

The peer share is uniform random in Ring127, leaking no information
about eta^nl.

Disclosure footing: identical to `k2ShareInputDS`'s feature sharing –
uniform Ring127 additive split, transport-encrypted via the label's
Ed25519 transport public key.

## Usage

``` r
dsvertNBEtaShareDS(
  data_name,
  x_vars,
  beta_values,
  target_pk,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Data frame on this server.

- x_vars:

  Character vector. Non-label feature column names.

- beta_values:

  Numeric vector of length `length(x_vars)`.

- target_pk:

  Character. Transport public key (base64url) of the label server.

- session_id:

  Character.

## Value

List with `sealed` (transport-encrypted peer share blob, base64url) and
`n` (number of patients).
