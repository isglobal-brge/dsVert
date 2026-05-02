# Generate n-length Beaver triples for element-wise Ring63 product

Dealer-only aggregate. Samples n element-wise Beaver triples \\(a_i,
b_i, c_i = a_i b_i)\\ in Ring63, splits each into two additive shares,
and emits two self-contained payloads sealed (transport-encrypted) to
the two DCF parties' transport public keys. The client relays each blob
to the corresponding party via `mpcStoreBlobDS` under the key
`"k2_beaver_vecmul_triple"`; each party then consumes it via
[`k2BeaverVecmulConsumeTripleDS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulConsumeTripleDS.md).

Inter-party leakage: none. The triple is a standard MPC randomness
commitment; both parties learn only their own shares.

## Usage

``` r
k2BeaverVecmulGenTriplesDS(
  dcf0_pk,
  dcf1_pk,
  n,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
```

## Arguments

- dcf0_pk, dcf1_pk:

  Base64url transport public keys of the two DCF parties.

- n:

  Vector length.

- session_id:

  MPC session id (used only to drive the RNG seed).

- frac_bits:

  Ring63 fractional bits (default 20). At ring=127 the handler defaults
  to fracBits=50 regardless of this argument.

- ring:

  Integer 63 (default) or 127. Routes through the Uint128 Ring127
  handler when 127 (task \#116 Cox/LMM STRICT migration).

## Value

list(triple_blob_0, triple_blob_1) – both base64url sealed payloads for
relay to party 0 and party 1.
