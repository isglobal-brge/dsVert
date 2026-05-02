# ECDH-PSI Record Alignment - Server-Side Functions (Blind Relay)

These functions implement Elliptic Curve Diffie-Hellman Private Set
Intersection (ECDH-PSI) for privacy-preserving record alignment across
vertically partitioned data. All EC point exchanges are
transport-encrypted (X25519 + AES-256-GCM ECIES) so the client acts as a
blind relay, never seeing raw elliptic curve points.

## Details

The protocol exploits the commutativity of scalar multiplication on
P-256: \\\alpha \cdot (\beta \cdot H(id)) = \beta \cdot (\alpha \cdot
H(id))\\.

Security (DDH assumption on P-256, malicious-client model):

- The client sees only opaque encrypted blobs (not reversible)

- Each server's scalar never leaves the server

- The PSI firewall enforces phase ordering and one-shot semantics

- No party can perform dictionary attacks or OPRF oracle attacks

## References

De Cristofaro, E. & Tsudik, G. (2010). "Practical Private Set
Intersection Protocols with Linear Complexity". *FC 2010*.
