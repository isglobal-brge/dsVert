# Isolated Lattigo linear-layer experiment

This directory is a non-production spike. It is a separate Go module, is
excluded from the R source tarball by `^experiments$`, and does not modify or
link `inst/dsvert-mpc`, dsVert endpoints, package dependencies, or packaged
binaries.

The dependency is pinned exactly to
[`github.com/tuneinsight/lattigo/v6@v6.2.0`](https://github.com/tuneinsight/lattigo/releases/tag/v6.2.0)
(Apache-2.0). The design uses Lattigo's documented
[`mpbgv.EncToShareProtocol`](https://pkg.go.dev/github.com/tuneinsight/lattigo/v6@v6.2.0/multiparty/mpbgv#EncToShareProtocol),
not a locally invented decryption protocol.

## What the spike demonstrates

- Two or more logically separate N-out-of-N compute roles generate independent
  RLWE secret-key shares and a collective BGV public key. No combined secret
  key is constructed.
- Exact integer `X*beta` and `X^T*r` layers run homomorphically. The baseline
  encrypts each `beta`/residual scalar, packs it across the relevant output
  slots, and uses the corresponding `X` column/row as a plaintext multiplier;
  ciphertext addition produces a packed output.
- Signed 63-, 127-, and 257-bit targets are represented by application-level
  CRT over independent native BGV plaintext rings `Z_t`. The lanes use
  deterministic, distinct, 29-bit NTT-friendly primes; arithmetic within every
  lane remains exact modular BGV arithmetic.
- A server-authoritative contribution certificate derives a conservative
  output magnitude `M`. Every run fails before encryption unless `P > 2M`,
  where `P` is the CRT product, and unless the requested signed-width capacity
  contains `M`.
- Before decoding any output, every role invokes Lattigo's encryption-to-shares
  protocol. Role 1 obtains `m - sum(mask_i, i>1)` and every other role keeps its
  uniform local mask. A role therefore sees only its additive output share.
- Public encryption-to-share messages are serialized, Ed25519-authenticated,
  and bound to the session, complete signed/CRT boundary digest, ciphertext
  hash, stage, lane, output, sender, and sequence. Replays and substitutions
  are rejected.
- Each role rejects a second mask generation for the same operation and keeps a
  private digest set to detect accidental mask reuse.
- `GCPartyInput` is an explicit CRT-to-signed handoff boundary. It carries one
  role's residues plus the rule a future exact GC must enforce: add shares
  modulo every `t_i`, reconstruct in `[0,P)`, subtract `P` when `x>P/2`, and
  assert `|x|<=M`. The non-test build contains no function that performs that
  reconstruction and no generic decrypt endpoint.

The tests reconstruct all role shares only in `oracle_test.go`. That file is
compiled solely for tests and checks the result against independent `big.Int`
matrix arithmetic, including negative values and carries across CRT lanes.

## Claims that are justified by this experiment

Under Lattigo's semi-honest multiparty assumptions, independent role processes,
authenticated peer keys, secure randomness, and at least one role that does not
collude or disclose its local mask:

1. The relay does not receive an unmasked linear-layer result.
2. One role does not receive the other roles' additive output shares.
3. A relay cannot alter, substitute, or replay an accepted public output-share
   message without detection; it can still delay or drop messages.
4. For the signed 63/127/257 fixtures under test, the integer result is
   identical to the `big.Int` oracle. The `P > 2M` check excludes arithmetic
   CRT wrap for every admitted public bound; this does not by itself certify HE
   noise for arbitrary matrix dimensions.

These are prototype claims, not a production security certification.

## Claims this spike does **not** make

- The roles are Go objects in one test process. This demonstrates protocol
  separation and serialized messages, not OS, container, host, or side-channel
  isolation.
- Lattigo states that malicious-security proofs for multiparty shares are not
  implemented. Ed25519 proves message origin and transcript binding; it does
  not prove that a compromised role computed a correct key-generation,
  ciphertext, or decryption share. A malicious role can bias or abort the
  result.
- Colluding roles can reconstruct outputs. A host that can inspect every role's
  memory can also reconstruct them.
- The deterministic CRS is public domain-separated setup material, not a
  secret. A production protocol must distribute it through the authenticated
  setup transcript.
- The experiment does not implement DSI transport, pinned-peer persistence,
  differential privacy, range proofs, GC, comparisons, truncation, nonlinear
  GLM steps, or a conversion between additive shares over `Z_(2^k)` and CRT.
- The central in-process harness reads the complete `X` fixture and supplies
  `X` as plaintext multipliers. This is not a vertically partitioned
  input-ingestion or owner-isolation proof. A distributed version must prove
  feature ownership and authenticated routing while ensuring that a role never
  receives another owner's plaintext `X` columns.
- The experimental parameters (`logN=12`, `logQ=[50,40]`, 29-bit plaintext
  primes) have not received a dsVert production security/noise audit. Passing
  correctness tests is not a parameter-security proof.
- This packing is a baseline, not the final scalable matrix kernel. It encrypts
  `columns + rows` packed scalars per CRT lane. A production accelerator should
  benchmark diagonal/BSGS transforms, persistent contexts, streaming, and DSI
  framing against representative dimensions.

The separate `twopc` subpackage now removes the row-count term from the
authenticated HE geometry while one row chunk fits the 4096 slots: residuals
are packed once, per-column cross products are independently row-masked, and
the decrypting peer sums only masked vectors. Its exact additive-share oracle,
threat boundary and 64/4096-row benchmarks are documented in
`twopc/README.md`; it remains isolated for the same production blockers.

## Verification

```sh
cd dsVert/experiments/lattigo-linear-accel
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go test -run '^$' -bench 'Benchmark(Linear63TwoRolesOnline|Setup63TwoRoles)$' \
  -benchtime=3x -benchmem -count=1
```

On macOS, an end-to-end process RSS observation can be added with:

```sh
/usr/bin/time -l go test -run '^$' \
  -bench '^BenchmarkLinear63TwoRolesOnline$' -benchtime=1x -count=1
```

Reference measurement on Apple M2 (`darwin/arm64`, Go 1.25.7), using the 2x2
signed-63 fixture and two roles:

| Phase | Time | Go allocations | Protocol bytes |
|---|---:|---:|---:|
| Online linear layers + share output | 32.4 ms/op | 20.1 MB/op | 1,576,872 input ciphertext + 788,436 output ciphertext + 790,104 signed share bytes |
| Collective setup | 28.1 ms/op | 12.0 MB/op | 786,840 public setup bytes |

The setup byte count covers CKG shares and collective public keys, not identity
provisioning or CRS framing. The online wire counts omit transport and
serialization of plaintext `X`, because the harness already has the complete
matrix in memory. The one-iteration `/usr/bin/time -l` run reported 169,033,728 bytes maximum
resident set size for the compiled Go test process and 35.3 ms benchmark time.
These small-fixture numbers are directional only: they include this baseline's
HE/share serialization, but they do not include DSI and do not predict large-N
or large-dataset performance.

## Exact blocker before product integration

The BGV-to-additive-share output is available and works. The remaining
cryptographic blocker is the downstream exact secret conversion: dsVert would
need an audited GC/MPC circuit that consumes each role's CRT residues, performs
the boundary rule above without opening the combined residues, and emits the
required signed/fixed-point shares. This spike intentionally stops at that
interface. Implementing CRT reconstruction locally at either role would destroy
the confidentiality property it is meant to preserve.
