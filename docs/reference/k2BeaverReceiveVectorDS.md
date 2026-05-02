# Receive a shared FP vector and store under a session key

Consume the peer-relayed blob previously delivered via `mpcStoreBlobDS`
under `blob_key`, decrypt with this party's transport secret key, and
store under `output_key`.

## Usage

``` r
k2BeaverReceiveVectorDS(blob_key, output_key, session_id = NULL)
```

## Arguments

- blob_key:

  Character. Session blob slot to consume the sealed share from.

- output_key:

  Character. Session-state key under which the output share is written.

- session_id:

  Character. Active MPC session identifier.
