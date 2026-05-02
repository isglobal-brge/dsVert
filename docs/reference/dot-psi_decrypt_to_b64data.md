# Decrypt a sealed blob and return as base64-encoded data (internal)

Decrypts a sealed blob and returns the raw base64-encoded payload (for
binary packed data).

## Usage

``` r
.psi_decrypt_to_b64data(sealed_b64url, session_id = NULL)
```

## Arguments

- sealed_b64url:

  Character. Sealed data in base64url.

- session_id:

  Character or NULL.

## Value

Character. Base64-encoded decrypted data.
