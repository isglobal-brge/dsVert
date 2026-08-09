# Two-compute-peer additive-share linear prototype

This subpackage is an isolated research prototype. It is excluded from the R
tarball with the rest of `experiments/`; it is not registered, linked into a
binary, or exposed through a dsVert endpoint.

Unlike the central-fixture spike in the parent directory, each `Peer` here is
constructed with only its own additive CRT shares of `X`, `beta`, and residual
`r`. `NewPeer` deep-copies those shares and provides no input accessor. The
normal package has no function that combines the two inputs or outputs. Full
reconstruction exists only in `oracle_test.go`.

## Algebra and protocol

For two compute peers with additive shares modulo each CRT prime,

```text
X = X0 + X1
beta = beta0 + beta1
r = r0 + r1
```

the linear layers expand to local and cross terms:

```text
X*beta = X0*beta0 + X0*beta1 + X1*beta0 + X1*beta1
X^T*r  = X0^T*r0  + X0^T*r1  + X1^T*r0  + X1^T*r1
```

Local terms never leave their owner. For the cross term `X0*beta1`:

1. Peer 1 encrypts each scalar share in `beta1` under its own BGV key, packed
   across the output rows.
2. Peer 0 multiplies those ciphertexts by its plaintext-share columns `X0` and
   sums them.
3. Peer 0 samples a fresh uniform vector `m01` modulo the BGV plaintext prime,
   retains `m01` as its additive output contribution, homomorphically subtracts
   it, and returns `Enc_1(X0*beta1-m01)`.
4. Peer 1 decrypts the already-masked term and adds it locally to its output
   share. It never sends the decoded value back.

The reverse cross term swaps roles. `X^T*r` sends the complete residual vector
in one packed ciphertext. The evaluator multiplies it by each local
plaintext-share column, subtracts an independent uniform row mask from every
column ciphertext, and returns the `p` masked ciphertexts in one authenticated
bundle. The decrypting peer sums each masked column locally; the evaluator
retains the corresponding sum of masks. Thus the decrypted row contributions
remain information-theoretically hidden and the `X^T*r` message shape no longer
grows with `n` while `n` fits one slot pack. Consequently the two final output
shares sum to the complete linear layer, while each cross term remains hidden
by a mask unknown to the decrypting peer.

| Participant | Values available in the protocol |
|---|---|
| Peer 0 | Its own CRT shares `(X0,beta0,r0)`, ciphertexts of peer 1's scalar shares, masks sampled by peer 0, cross terms masked by peer 1, and peer 0's final additive outputs |
| Peer 1 | Its own CRT shares `(X1,beta1,r1)`, ciphertexts of peer 0's scalar shares, masks sampled by peer 1, cross terms masked by peer 0, and peer 1's final additive outputs |
| Relay/session | Public workload and bounds, pinned identities, ciphertext sizes/counts, signed headers, encrypted scalar inputs, and encrypted masked cross outputs; never a decryption key, raw input share, mask, decoded cross term, or output share |

An input ciphertext reveals its sender, receiver, layer, lane, public packed
position, size, and timing. Its payload is BGV-encrypted. A returned ciphertext
or fixed-count ciphertext bundle reveals the output layer/lane and public
column count, while every decrypted plaintext is a cross term minus a fresh
uniform mask. These metadata channels are public by design and must be included
in a production workload-disclosure review.

Every ciphertext is evaluated independently in the application-level CRT lanes
defined by the parent experiment. The signed boundary still requires `P>2M`.
The 63/127/257-bit CRT-to-signed reconstruction remains a future exact-GC task;
neither peer performs it locally.

## K custodians and two compute peers

`CustodianCount` records arbitrary `K>=2`, but the online protocol always has
exactly two compute peers. Its input contract is that each custodian has already
split its contribution between those two peers and that each peer has locally
aggregated all K contributions modulo every CRT prime. K therefore affects the
upstream sharing stage and public transcript, not the online cross-term message
count. This prototype does not implement or benchmark that upstream routing.

## Authenticated transcript

The session is created with exactly two pinned Ed25519 identities. Every
encrypted input and masked output binds:

- random session ID;
- canonical workload digest, signed/CRT boundary, dimensions, bounds, K, and
  both pinned identities;
- stage, sender, receiver, CRT lane, scalar index, and sequence;
- the complete serialized BGV ciphertext payload.

Unknown identities, tampering, substitutions, and replays fail closed. A relay
can still drop or delay messages. Production retries should resend the original
authenticated envelope idempotently rather than generate a new HE mask.

## Defensible claims

Under BGV/RLWE semantic security, secure random generation, authenticated pins,
separate peer processes, semi-honest execution, valid server-authoritative
bounds, and no peer collusion:

- each compute peer starts with only one additive sharing of every input;
- the relay observes ciphertexts and public metadata, not input shares or
  unmasked cross terms;
- the decrypting peer receives a uniformly masked cross term;
- fresh runs produce fresh additive output sharings;
- the signed-63/127/257 test fixtures, K=2/3/5 cases, and randomized signed
  matrices reproduce the independent `big.Int` oracle exactly;
- `P>2M` rules out CRT wrap if the underlying values obey their certified
  contribution bounds.

These are prototype claims, not a security certification.

## Explicit non-claims and blockers

- Both peers are simulated as Go objects in one address space. The code shape
  prevents normal API access to the other peer's input, but it does not prove
  process, host, memory, cache, or side-channel isolation.
- This is semi-honest 2PC. Ed25519 authenticates origin and transcript; it does
  not prove correct ciphertext formation, bounds, HE evaluation, masking, or
  decryption. A malicious compute peer can bias or abort the output. Range
  proofs/ZK or another actively secure protocol would be required for that
  threat model.
- The public bound cannot be checked from a uniformly random additive input
  share. Bounds must be enforced at contribution time or proven upstream.
- The session supplies the same public workload to both in-process peers. A
  production deployment needs a cross-signed workload/parameter manifest.
- There is no CRT-to-`Z_(2^k)` conversion. A reviewed GC must add both peers'
  residues modulo each prime, perform signed CRT reconstruction, check `|x|<=M`,
  and emit new secret shares without opening the value.
- The fixed experimental BGV parameters have no production security/noise
  certificate. Correctness tests do not certify arbitrary-depth or arbitrary-N
  workloads.
- A ciphertext has 4096 slots. The prototype rejects larger row/column
  dimensions; a real kernel needs authenticated row-chunk plans, persistent
  contexts and cross-chunk accumulation. The chunk count is public workload
  geometry, not a query-history quota.
- There is no DSI, TLS, Base64, retry, spool, or backpressure implementation.
  Wire measurements below count signed binary envelopes but omit those outer
  transports and the upstream K-custodian sharing.
- Session outputs and replay/mask registries are retained in memory for test
  inspection. Production requires an explicit bounded lifecycle.

## Complexity and measurements

For `n <= slots` rows, `p` columns, and `L` CRT lanes, the packed route sends:

```text
encrypted input ciphertexts = 2L(p+1)
masked output ciphertexts   = 2L(p+1)
authenticated messages      = 2L(p+3)
```

The `p` masked `X^T*r` outputs travel in one signed bundle per direction/lane,
which is why authenticated-message count differs from ciphertext count. The HE
wire is independent of K after upstream aggregation and, within one slot pack,
independent of `n`; local modular work remains `O(np)`. For larger cohorts the
same geometry becomes `O(ceil(n/slots) * Lp)` and needs the authenticated
streaming integration still listed above.

Reference Apple M2 measurements (`darwin/arm64`, Go 1.25.7), signed-63 CRT and
two peers:

| Shape | Time | Go allocations | Authenticated wire | Messages |
|---|---:|---:|---:|---:|
| 2x2, K=2 (`3x`) | 58.9 ms/op | 49.8 MB/op | 4,739,070 bytes | 30 |
| 64x3, K=5 (`1x`) | 71.7 ms/op | 69.4 MB/op | 6,317,592 bytes | 36 |
| 4096x8, K=5 (`1x`) | 229 ms/op | 180.9 MB/op | 14,210,202 bytes | 66 |

For 4096x8, the former scalar-residual geometry would require 24,636 signed
messages and roughly 3.2 GB of ciphertext payload at the same ciphertext size;
the packed route uses 66 messages and 14.2 MB. This is a geometry comparison,
not a measurement of the removed route. The results remain directional and do
not include DSI, exact CRT conversion, nonlinear GLM work or multi-chunk
cohorts.

## Reproduce

```sh
cd dsVert/experiments/lattigo-linear-accel
go test ./twopc -count=1
go test -race ./twopc -count=1
go vet ./twopc
go test ./twopc -run '^$' \
  -bench 'BenchmarkAdditiveShare2PC63(Online|Setup|PackedXtR.*)$' \
  -benchtime=3x -benchmem -count=1
/usr/bin/time -l go test ./twopc -run '^$' \
  -bench '^BenchmarkAdditiveShare2PC63Online$' -benchtime=1x -count=1
```
