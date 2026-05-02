# Encrypt already-base64-encoded binary data under a recipient's transport PK (internal)

Takes data that is already base64-encoded (e.g. from psi-pack-points
output) and passes it directly to transport-encrypt.

## Usage

``` r
.psi_encrypt_b64data(data_b64, recipient_pk_b64)
```

## Arguments

- data_b64:

  Character. Already base64-encoded data.

- recipient_pk_b64:

  Character. Recipient's X25519 PK (standard base64).

## Value

Character. Sealed data in standard base64.
