# Verify all peer identities (signatures + trusted list)

D-INV-5 enforcement. The Ed25519-signature + `trusted_peers`
pinned-config check protects against three distinct adversaries that
mTLS alone does NOT cover:

## Usage

``` r
.verify_all_peer_identities(identity_info, transport_keys, own_identity_pk)
```

## Arguments

- identity_info:

  Named list: server -\> list(identity_pk, signature) (base64url).

- transport_keys:

  Named list: server -\> transport_pk (base64url).

- own_identity_pk:

  Character. This server's identity PK (standard base64).

## Details

\(a\) Active man-in-the-middle. An on-path adversary that intercepts and
replaces secret shares mid-flight cannot forge an Ed25519 signature
without the sender's private key. Each share is signed by the sender;
the recipient verifies against the sender's public key, which is pinned
in `dsvert.trusted_peers`. No reliance on TLS PKI for integrity of the
share content.

\(b\) Rogue server injection. A compromised study admin or attacker with
a valid TLS certificate can attempt to add a server to the connection
pool. Without `trusted_peers`, the MPC protocol has no way to
distinguish "the legitimate study server" from "any server with a valid
TLS cert" – the rogue server would either receive legitimate shares or
inject replay/malformed-computation traces designed to leak structure,
and its TLS certificate alone would NOT trip the standard mutual-TLS
check. The pinned-public-key allow-list in `trusted_peers` prevents
this: only servers whose identity PK appears in the pre-distributed
config can sit in the pool.

\(c\) Non-repudiation. The Ed25519 signature on each share is a
tamper-evident cryptographic record of which server originated which
payload. Disputes about provenance reduce to signature verification
against the pinned public-key list – no need to trust audit logs.
