# Enforce K-arity at server side (defense-in-depth)

Refuses calls into a K-specific MPC primitive when the calling
deployment's K does not match `expected_K`. The K value is derived from
`ss$peer_transport_pks`, populated by `mpcStoreTransportKeysDS` AFTER
Ed25519 signature verification + trusted-peers list check performed by
`.verify_all_peer_identities` (mpcUtils.R:530-556).
`length(peer_transport_pks) + 1L` therefore equals the cryptographically
verified party count (this server + verified peers); a malicious or
misconfigured client cannot forge it.

## Usage

``` r
.k2_enforce_K(ss, expected_K, fn_name = NULL)
```

## Arguments

- ss:

  MPC session state (output of `.S(session_id)`).

- expected_K:

  Integer expected K (e.g. 2L for K=2-only paths).

- fn_name:

  Optional function name embedded in the error message to aid log-trace
  attribution.

## Value

`TRUE` invisibly on success; `stop(...)` on K mismatch.

## Details

Pattern: each K-specific \*DS function calls
`.k2_enforce_K(ss, expected_K = 2L, "fnName")` immediately after
resolving its session state. The check is silent when
`peer_transport_pks` is unset (e.g., the function is invoked before the
transport-key handshake – that path is already guarded by
`mpcStoreTransportKeysDS` and the `dsvert.require_trusted_peers`
default; this helper is defense-in-depth, not the first line).
