# Export encrypted masked points for a target server (aggregate function)

Encrypts stored masked points under the specified target server's
transport PK. The client receives an opaque blob it cannot decrypt.

## Usage

``` r
psiExportMaskedDS(target_name, session_id = NULL)
```

## Arguments

- target_name:

  Character. Name of the target server.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

List with encrypted_blob (base64url).
