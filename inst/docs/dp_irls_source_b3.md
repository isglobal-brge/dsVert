# Signed person-source conversion, B3

The B3 source ABI is `signed-person-q16-two-owner-valid-v1`. Its authoritative
plan is bound to the signed B1 root, predecessor and public evaluation point.
A row has two owner-validity words, three signed q16 predictor words, one
integer response, and one signed q16 offset. Four trailing Ring128 words hold
two owner alignment digests using XOR reconstruction. Only the encrypted
protected program compares those private alignment digests and validity words.

Each custodian seals an immutable copy of its authorized aligned frame after
validating the persistent padded-PSI attestation, its authenticated person order,
the full signed authorization-epoch vector, purpose and designated pair. The
source seal signs the root, local snapshot hashes, complete source dependencies,
conversion certificate and private person-order binding. Every materialization
checks those bytes and the retained snapshots. Missing padded rows have zero
owner-validity; both owner bits must be one to contribute. A malformed,
nonfinite, missing or out-of-domain value makes that person's local validity
zero. The circuit ANDs owner validity and enforces its own raw-domain checks.
No invalid person replaces the aggregate, and no validity or clamp count leaves
the protected program.

The conversion certificate admits finite IEEE754 binary64 inputs, interpreted
as their exact binary rational values. `gmp::as.bigq(double)` creates that exact
rational; signed real bounds are compared before quantization. Multiplication
by 65536 is rational and nearest-even rounding is integer division with exact
remainder comparison, including negative ties. Therefore each admitted q16
source differs from its input by at most 1/131072. Closed bounds are q16 lattice
points in the admitted profile, so monotone rounding preserves them. This is
a deterministic conversion with failure probability zero; no privacy delta is
needed. The outcome conversion requires an exact integer inside signed bounds.
The public intercept is installed by the circuit from the signed declaration.

Custodian provisioning retains private source copies, keys, signed contract,
transport keys, noise root and stage metadata in a signed mode-0600 record.
`.dsvert_dp_irls_restore(directory, trusted_pins)` authenticates it using external
pins and restores completed worker output through any publication boundary.
Publication replay uses the existing durable lane and B1 successor stores.
An interrupted protected worker initiates an encrypted two-authority recovery
offer/acknowledgment before both restart in fresh transport spools. The same
source, noise root and private stage store are retained. The Go executor uses
fresh per-peer channel nonces, replays committed shares/noise, and mutually
aborts an incomplete protected attempt. Lost or corrupt committed journal
state still fails closed. No restore or provisioning helper is a DSI endpoint.
