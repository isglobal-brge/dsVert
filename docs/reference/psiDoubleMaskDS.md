# Double-mask target points using stored scalar (aggregate function)

Decrypts the encrypted target points blob, multiplies by the scalar
generated in Phase 1, and re-encrypts the result under the target's
transport PK. The client never sees raw EC points.

## Usage

``` r
psiDoubleMaskDS(target_name, from_storage = FALSE, session_id = NULL)
```

## Arguments

- target_name:

  Character. Name of the target server whose points are being
  double-masked.

- from_storage:

  Logical. If `TRUE`, read encrypted blob from server-side blob storage.
  Default `FALSE`.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

List with encrypted_blob (base64url).

## Details

PSI Firewall: one-shot per target – each target can only be
double-masked once, preventing the OPRF oracle attack.
