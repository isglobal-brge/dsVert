# Receive and assemble extra feature shares from non-DCF servers

Called on DCF parties to receive feature shares from non-DCF servers.
Appends the shares to the peer X matrix for gradient computation.

## Usage

``` r
glmRing63ReceiveExtraShareDS(extra_key, extra_p, session_id = NULL)
```

## Arguments

- extra_key:

  Character. Blob key for the encrypted extra feature share.

- extra_p:

  Integer. Number of features in this share.

- session_id:

  Character or NULL.

## Value

List with status.
