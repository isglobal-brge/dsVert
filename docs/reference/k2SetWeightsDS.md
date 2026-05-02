# Register observation weights for an open GLM session (outcome-side)

Read a numeric weights column held on this server, convert to Ring63 FP,
store a copy locally for subsequent `k2ApplyWeightsDS` calls, and return
an encrypted blob destined for the peer DCF party. This is the first of
two registration steps needed for weighted GLM (inverse-probability
weighting, survey-weighted regression, etc.).

The weights are disclosed to the DCF peer server through the returned
ciphertext – an acceptable server-to-server leakage for IPW, where
weights are themselves derived from a propensity model whose
coefficients are already public. Nothing is ever disclosed to the
analyst client. Within-cohort, patient-level weight values never leave
the pair of DCF parties.

## Usage

``` r
k2SetWeightsDS(
  data_name,
  weights_column,
  peer_pk,
  ring = NULL,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Aligned data-frame name on this server.

- weights_column:

  Character. Name of the numeric weights column.

- peer_pk:

  Character. Transport (X25519) public key of the DCF peer.

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.

- session_id:

  Character. GLM session identifier.

## Value

A list with `peer_blob` (base64url transport-encrypted serialised FP
weights vector) and `n` (vector length). The client relays `peer_blob`
to the peer via `mpcStoreBlobDS`

- `k2ReceiveWeightsDS`.
