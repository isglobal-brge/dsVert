# Beaver K x L contingency counts across DCF parties

Computes the joint contingency counts \\n\_{kl} = \sum_i X\_{ik}
Y\_{il}\\ where \\X\\ is the one-hot encoding of `var1` on this server
(held by the caller) and \\Y\\ is the one-hot encoding of `var2` on the
peer server (retrieved from the peer's session via a transport-encrypted
blob relay). Both matrices are FP-encoded in the session store under
`k2_onehot_<var>_fp` (see `dsvertOneHotDS`). Returns the K\*L cells as a
single aggregate vector; the analyst client never sees any \\n\\-length
indicator vector.

Delegates the bilinear form to the Go binary via
`k2-beaver-matrix-bilinear` which generates a single \\K \times L\\
Beaver triple batch and returns the reconstructed counts as non-negative
integers rounded from the Ring63 result.

## Usage

``` r
k2CrossOneHotCountsDS(
  var1,
  var2,
  peer_name = NULL,
  peer_pk = NULL,
  session_id = NULL
)
```

## Arguments

- var1:

  character – the variable held on this server.

- var2:

  character – the variable on the peer.

- peer_name:

  character – server name of the peer (used for session blob key
  disambiguation).

- peer_pk:

  base64 X25519 pk of the peer.

- session_id:

  MPC session.

## Value

list(counts = integer K\*L vector row-major, K, L, row_levels,
col_levels).
