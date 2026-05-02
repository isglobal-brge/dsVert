# Store DCF keys persistently (reused across iterations)

Decrypts transport-encrypted DCF keys and stores them in session. Keys
are generated server-side by glmRing63GenDcfKeysDS.

## Usage

``` r
k2StoreDcfKeysPersistentDS(session_id = NULL)
```

## Arguments

- session_id:

  Character or NULL.

## Value

List with status.
