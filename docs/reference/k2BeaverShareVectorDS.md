# Share a session FP vector with the peer (additive 2-party split)

Reads an FP vector stored under `source_key` in the MPC session, splits
it into two additive Ring63 shares, overwrites `source_key` with this
party's share (so downstream helpers see a share rather than the
plaintext), and returns a transport-encrypted blob carrying the peer's
share for relay via `mpcStoreBlobDS` under `relay_key`.

Used by `ds.vertChisqCross` to share each one-hot indicator matrix
between the DCF parties before the per-cell Beaver product.

## Usage

``` r
k2BeaverShareVectorDS(source_key, peer_pk, session_id = NULL, frac_bits = 20L)
```

## Arguments

- source_key:

  Character. Session slot holding the plaintext FP vector (e.g.
  `"k2_onehot_<var>_fp"`).

- peer_pk:

  Transport pk of the peer (base64url).

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20).

## Value

list(peer_blob) – sealed payload for relay.
