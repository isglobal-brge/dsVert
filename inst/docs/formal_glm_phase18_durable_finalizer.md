# Formal GLM Phase 1.8 durable local finalizer

Status: internal research implementation. It has no R export, DataSHIELD
aggregate method, Go command handler, advertised capability or packaged-binary
claim.

## Durable source outbox

For a fixed pre-execution authorization, source, block and pair of signed
recipient transport tickets, the source commits the first complete encrypted
bundle before returning it. A per-slot inter-process lock is acquired and the
slot is checked again before protected rows are resolved or randomness is
drawn. Exact retries, including retries after process restart, return the same
bundle bytes without rereading data, resplitting shares or re-encrypting.

Records are authenticated with a server-local 256-bit key, sharded by a
semantic slot hash and key epoch, bounded to 4 MiB, written owner-only through a
temporary file, fsynced and atomically renamed. A different authenticated
bundle for an occupied slot is rejected. Temporary namespaces are slot-local,
so cleanup for one concurrent block cannot remove another block's write. A
contending identical retry waits for the active slot owner instead of failing
after an arbitrary timeout; this is serialization, not a request quota.

The key is generated automatically on first use, stored outside the package as
`finalizer.key` with mode 0600, and reused across restarts. If it is deliberately
removed, a fresh key and epoch are created without modifying the old epoch.
This availability choice permits a one-off reroll after state loss; persistence
and backups remain operational requirements.

## Recipient inbox and Go finalization

The recipient authenticates the complete pinned-source bundle and signature,
selects exactly its own ciphertext, and writes only a binary local-ingress
frame. The frame contains public route/shape commitments plus that ciphertext;
it contains no decrypted coordinate, validity bit, alignment gate, consensus
digest or patient identifier. Its server-local HMAC is verified by Go before
any length or field is trusted.

Go then enforces the pinned source and recipient slots, capsule, plan,
pre-execution token, global materialization root, fixed block schedule, ring and
exact power-of-two container width. It performs recipient-local AEAD decryption
only in memory, rejects legacy/full-alignment headers and unknown or
non-canonical JSON, rejects non-zero padding above `ring_bits`, wipes plaintext,
and creates the sealed Phase 1.9 verified-source-block. Each recipient sees only
its coordinate, validity, gate and consensus shares.

The durable Go store commits only the authenticated ciphertext frame using
fsync plus an atomic hard-link CAS. Exact retry is idempotent; conflicting retry
fails. Restart recovery requires exactly one valid slot from every one of `K`
custodians and never returns a partial fan-in. Fixed 2 MiB per-frame limits are
parser/resource bounds, not query/request quotas: any number of valid block
slots may be processed over time. Crash temporaries are reaped only after a
24-hour grace period, so a concurrently active writer with the same internal
prefix is never mistaken for stale state.

## Threat boundary and remaining work

The analyst/relay may omit, reorder, duplicate, replay or modify traffic. It
cannot forge the source signature, local frame MAC, AEAD ciphertext or Phase
1.9 sealed block. Supplying different global roots to the two recipients causes
context/pair rejection; future runtime wiring must derive that root from the
authenticated all-source transcript, never trust an analyst-provided value.

The model assumes pinned identities, two non-colluding semi-honest compute
peers and server-local key confidentiality. Either custodian may still lie
about its own data, and colluding compute peers can reconstruct their shared
inputs; malicious-secure source attestation and collusion resistance are not
claimed.

Tests cover K=2, K=3 and K=5, both compute roles, real X25519/AES-GCM,
byte-identical retry and restart, missing source slots, conflict, truncation,
oversize, MAC/AEAD tamper, route/role/context replay, legacy header, unsafe high
padding, cross-process exact-CAS contention, crash between hard-link commit and
temporary-name removal, stale-crash cleanup and absence of private plaintext in
persisted records. Shared R/Go golden vectors fix both the private-header JSON
and the outer frame field order, integer encoding, HMAC domain and canonical
bytes.

The remaining integration step is an internal runtime consumer which moves the
authenticated recipient-inbox frame to the Go finalizer and then to Phase 1.9.
It must not introduce a generic ciphertext reader, decryptor or opening method.
