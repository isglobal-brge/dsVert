// k2_comparison.go: Secure comparison gate using DCF.
//
// Simple and correct approach: mask x, DCF evaluates [masked_x < masked_threshold].
// Uses a domain 2x larger than the value range to prevent wraparound.

package main

// SecureComparePublicThreshold computes [x < threshold] where x = x0+x1 mod valueDomain.
// numBits is the number of bits for values (e.g. 8 for values in [0,256)).
// Internally uses numBits+2 domain to prevent wraparound.
func SecureComparePublicThreshold(x0, x1 uint64, threshold uint64, numBits int) (bit0, bit1 byte) {
	// Extended domain: 2 extra bits to prevent wraparound
	extBits := numBits + 2
	N := uint64(1) << extBits

	// x in the extended domain (values < 2^numBits, so no wraparound issues)
	x0ext := x0 % N
	x1ext := x1 % N

	// Random mask
	r := cryptoRandUint64K2() % N
	r0 := cryptoRandUint64K2() % N
	r1 := (N + r - r0) % N

	// Mask x: m = x + r mod N
	m0 := (x0ext + r0) % N
	m1 := (x1ext + r1) % N
	m := (m0 + m1) % N

	// DCF alpha = (threshold + r) % N
	// Since threshold < 2^numBits and r < N = 2^(numBits+2),
	// threshold + r < 2^(numBits+2) + 2^numBits < 2^(numBits+3).
	// But N = 2^(numBits+2), so we could wraparound.
	// To handle: if threshold + r >= N, the comparison wraps.
	// But since x < 2^numBits < N/4 and threshold < 2^numBits < N/4,
	// and r < N, we have m = x+r which could be anywhere in [0, N).
	// threshold + r could also be anywhere in [0, 2N-1).
	//
	// The comparison [m < alpha'] where alpha' = (threshold+r)%N is equivalent to
	// [x < threshold] IF there's no wraparound, i.e., if x+r and threshold+r
	// are in the same "half" of the ring.
	//
	// Correct approach: ensure that r doesn't cause wrapping by restricting r to
	// [0, N - 2^numBits) so that x + r < N always (since x < 2^numBits).
	// Similarly, threshold + r < N + 2^numBits, but mod N this wraps.

	// Actually: let's just use the simple observation that for r < N - 2^numBits:
	// x + r < 2^numBits + (N - 2^numBits) = N, so no wrap.
	// threshold + r < 2^numBits + (N - 2^numBits) = N, so no wrap.
	// Then [x+r < threshold+r] = [x < threshold]. Done.

	// Regenerate r in safe range
	safeMax := N - (uint64(1) << numBits)
	r = cryptoRandUint64K2() % safeMax
	r0 = cryptoRandUint64K2() % N
	r1 = (N + r - r0) % N

	m0 = (x0ext + r0) % N
	m1 = (x1ext + r1) % N
	m = (m0 + m1) % N

	alpha := (threshold + r) % N // no wraparound guaranteed

	// Generate DCF: [m < alpha]
	key0, key1 := DCFGen(alpha, 1, extBits)

	// Evaluate
	v0 := DCFEval(0, key0, m)
	v1 := DCFEval(1, key1, m)

	// Result: v0 + v1 = [m < alpha] = [x < threshold]
	resultBit := byte(((v0 + v1) % 2 + 2) % 2)

	// Split into XOR shares
	rBit := byte(cryptoRandUint64K2() & 1)
	bit0 = rBit
	bit1 = resultBit ^ rBit

	return
}

// SecureEqualPublicValue computes [x == value] where x = x0+x1 mod N.
func SecureEqualPublicValue(x0, x1 uint64, value uint64, numBits int) (bit0, bit1 byte) {
	extBits := numBits + 2
	N := uint64(1) << extBits
	safeMax := N - (uint64(1) << numBits)

	r := cryptoRandUint64K2() % safeMax
	r0 := cryptoRandUint64K2() % N
	r1 := (N + r - r0) % N

	m0 := (x0%N + r0) % N
	m1 := (x1%N + r1) % N
	m := (m0 + m1) % N

	alpha := (value + r) % N
	key0, key1 := DPFGen(alpha, 1, extBits)

	v0 := DPFEval(0, key0, m)
	v1 := DPFEval(1, key1, m)

	resultBit := byte(((v0 + v1) % 2 + 2) % 2)

	rBit := byte(cryptoRandUint64K2() & 1)
	bit0 = rBit
	bit1 = resultBit ^ rBit

	return
}
