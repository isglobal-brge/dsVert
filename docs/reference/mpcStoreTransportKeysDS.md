# Store peer transport public keys (with identity verification)

Store peer transport public keys (with identity verification)

## Usage

``` r
mpcStoreTransportKeysDS(
  transport_keys = NULL,
  transport_keys_b64 = NULL,
  identity_info = NULL,
  identity_info_b64 = NULL,
  session_id = NULL
)
```

## Arguments

- transport_keys:

  Named list of base64url transport PKs.

- transport_keys_b64:

  Character (base64url). JSON-encoded peer transport public keys.

- identity_info:

  Named list: server -\> list(identity_pk, signature). NULL to skip.

- identity_info_b64:

  Character (base64url). JSON-encoded identity info / Ed25519
  signatures.

- session_id:

  Character or NULL.

## Value

TRUE on success.
