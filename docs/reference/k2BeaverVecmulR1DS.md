# Beaver vecmul round 1

Per-party aggregate. Reads the own x- and y-share FP vectors from the
session (under `x_key` and `y_key`) and the own triple share, computes
the masked \\d^{own} = x^{own} - a^{own}\\, \\e^{own} = y^{own} -
b^{own}\\, and transport-encrypts `(d^{own}, e^{own})` to the peer's
public key. The client relays the returned `peer_blob` to the other
party via `mpcStoreBlobDS` under `"k2_beaver_vecmul_peer_masked"`, ready
for round 2.

## Usage

``` r
k2BeaverVecmulR1DS(
  peer_pk,
  x_key,
  y_key,
  n,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
```

## Arguments

- peer_pk:

  Base64url transport pk of the peer.

- x_key, y_key:

  Session keys containing this party's FP shares.

- n:

  Vector length.

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20). At ring=127 the handler defaults
  to fracBits=50 regardless of this argument.

- ring:

  Integer 63 (default) or 127.

## Value

list(peer_blob) – base64url sealed payload for peer relay.
