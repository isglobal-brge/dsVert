# LMM closed-form GLS: receive peer's column shares

Per-party aggregate. Consumes the peer's sealed share blob (relayed via
`mpcStoreBlobDS` under `"k2_lmm_gram_peer_shares"`), decrypts it, and
stores each column's FP share under `ss$lmm_gram_col_<name>` so the
subsequent Beaver vecmul rounds can dereference it by name.

## Usage

``` r
dsvertLMMReceiveGramSharesDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. Active MPC session identifier.
