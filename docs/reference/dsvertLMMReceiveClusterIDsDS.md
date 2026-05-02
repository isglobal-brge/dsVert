# Receive + store peer's cluster IDs (LMM exact)

Per-party aggregate. Consume the relayed blob, decrypt, and store the
integer cluster ID vector under `ss$k2_lmm_cluster_ids`.

## Usage

``` r
dsvertLMMReceiveClusterIDsDS(session_id = NULL)
```

## Arguments

- session_id:

  Character. Active MPC session identifier.
