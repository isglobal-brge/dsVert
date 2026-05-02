# Store peer transport public keys (aggregate function)

Stores other servers' transport PKs for encrypting PSI messages. Called
by the client after collecting PKs from all servers.

## Usage

``` r
psiStoreTransportKeysDS(
  transport_keys = NULL,
  transport_keys_b64 = NULL,
  identity_info = NULL,
  identity_info_b64 = NULL,
  session_id = NULL
)
```

## Arguments

- transport_keys:

  Named list. Server name -\> transport PK (base64url).

- transport_keys_b64:

  Character (base64url). JSON-encoded peer transport public keys.

- identity_info:

  Named list. Per-server identity public keys and signatures (NULL to
  skip).

- identity_info_b64:

  Character (base64url). JSON-encoded identity info / Ed25519
  signatures.

- session_id:

  Character or NULL. UUID for session-scoped storage.

## Value

TRUE (invisible).
