# Cox K=2 discrete-time receive shared mask + y at NL

Counterpart to `dsvertCoxDiscreteShareMaskDS` – non-label server
transport-decrypts the sealed mask + y blobs and stores them as Ring127
shares (length J\*n, row-major). Forms the additive share pair (own at
OS, peer at NL) needed for the downstream Beaver-gated person-period Cox
Newton.

## Usage

``` r
dsvertCoxDiscreteReceiveSharesDS(
  mask_blob_key,
  y_blob_key,
  mask_output_key,
  y_output_key,
  n_pp,
  session_id
)
```

## Arguments

- mask_blob_key, y_blob_key:

  Character. Session blob slots holding sealed shares.

- mask_output_key, y_output_key:

  Character. Session slots to write decrypted Ring127 shares.

- n_pp:

  Integer. Total person-period rows = J \* n_obs.

- session_id:

  Character.
