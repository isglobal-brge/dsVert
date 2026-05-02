# Initialize PSI transport keys (aggregate function)

Generates an X25519 transport keypair for blind-relay PSI. The secret
key is stored locally and NEVER returned to the client. The public key
is returned so the client can distribute it to other servers.

## Usage

``` r
psiInitDS(session_id = NULL)
```

## Arguments

- session_id:

  Character or NULL. UUID for session-scoped storage isolation.

## Value

List with transport_pk (base64url).

## Details

This must be called before any other PSI function. Initializes the PSI
firewall state machine.
