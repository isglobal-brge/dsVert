# Exact-GC segmented spool contract

The exact-GC worker/DSI transport uses local spool protocol v3. The analyst is
still only a relay for signed envelopes containing AEAD-protected records; this
change concerns bounded local storage and does not create a new release.

## Layout and offsets

`inbound.segments/` and `outbound.segments/` contain immutable files named by
their absolute half-open range and SHA-256 digest:

`segment-<16-digit-start>-<16-digit-end>-<64-hex-sha256>.bin`

Offsets remain exact non-negative integers through `2^53`. A segment is written
to a mode-0600 same-directory temporary file and becomes visible through one
rename only after the complete ciphertext has been written. Go additionally
syncs the file and directory. R closes and size-checks the temporary file before
rename; if a platform loses a rename across a machine crash, missing coverage or
the segment digest fails closed before a record is used.

The zero-length `inbound.bin` and `outbound.bin` files are v3 compatibility
sentinels, not transcript stores. The persistent cursors are:

- `inbound.state`: accepted absolute head and the last accepted range/hash,
  sufficient for an exact lost-response retry after its segment was consumed;
- `inbound.ack`: worker-consumed absolute base;
- `outbound.head`: worker-published absolute end;
- `outbound.ack`: relay-confirmed absolute base; and
- `outbound.offer`: the one range/hash that may advance `outbound.ack`.

All cursor replacements use a private same-directory temporary file and atomic
rename. Values are canonical decimal encodings; rollback, gaps, skips,
overlapping segment names, short files, unsafe permissions and hash mismatches
are errors. Concurrent cursor readers bind validation and parsing to one open
inode snapshot, so replacing a shorter/longer decimal file cannot synthesize a
rollback. Segment consumers likewise hash and subsequently read through the
same descriptor; reclamation after hand-off cannot change or invalidate the
verified byte stream.

## Commit and recovery ordering

Inbound publication orders `segment rename -> inbound.state`. If execution is
interrupted between them, an exact retry verifies the already-published segment
and completes the state commit. If the worker consumed and deleted that segment
first, its durable `inbound.ack` prevents the re-published retry from being read
twice.

Outbound publication orders `segment rename -> outbound.head`. A byte is never
offered above the committed head. ACK processing validates exactly the persisted
offer and orders `outbound.ack -> segment deletion`. An interruption after the
ACK commit may retain extra ciphertext only; the next identical exchange
finishes reclamation. Repeated current ACKs are idempotent. Older ACKs and ACKs
that skip the offered range are rejected.

DSI request loss and reconnection are supported while the two worker processes
and their operation state remain live: the client repeats the same absolute
offset and envelope. A worker/process crash does **not** resume a partially
executed garbled circuit, because the circuit engine itself has non-persistent
private state. It terminates the operation fail-closed; a higher-level retry
uses the existing typed retry contract and a new cryptographic attempt. The
durable cursors ensure a storage interruption cannot be mistaken for a correct
continued transcript.

## Bounds and backpressure

The server-authoritative per-direction retained-ciphertext bound defaults to
1 GiB, is at least `max(8 * DSI chunk bytes, 1 MiB)`, and is at most 64 GiB.
These are byte/resource bounds, not request, operation or privacy-budget quotas.
The Go writer publishes pending bytes and waits for an outbound ACK when the
bound is full. The R receiver waits for `inbound.ack` and physical reclamation.
Both waits remain bounded by the existing progress/heartbeat lease and abort if
the peer worker disappears. Consequently total transcript length may exceed the
spool bound indefinitely while retained bytes stay bounded.

The hot Go write path maintains a conservative retained-byte counter and scans
the segment directory only on publication or backpressure. Inbound validation
and hashing occur once when each immutable segment is opened. A local Apple M2
development benchmark (five synced 480 KiB publish/reclaim iterations) measured
about 79 MB/s; this is diagnostic, hardware/filesystem dependent, and is not a
portable performance guarantee. DSI/HTTP/Base64 latency normally remains the
dominant end-to-end cost.

## Security boundary

The filename digest detects storage damage and conflicting retries; it is not a
substitute for protocol authentication. Confidentiality and peer authenticity
remain supplied by the exact-GC AEAD records, purpose/context binding, signed
DSI envelopes and pinned Ed25519 peer identities. A privileged host that can
alter both package code and process memory remains outside this package-level
threat model.
