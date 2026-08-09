// k2_truncation.go: local truncation for K=2 MPC fixed-point arithmetic.
//
// Reference:
//   - Mohassel & Zhang, "SecureML", IEEE S&P 2017 (local truncation)
//   - Harth-Kitzerow et al., "Truncation Untangled", PoPETS 2025 (SoK)

package main

import (
	"fmt"
	"math"
	"math/bits"
)

const K2RecommendedTruncationFailureBits = 40

// LocalTruncationHeadroom is the proof obligation for promoting a collection
// of local truncations. MaxAbsTruncatedValue bounds the absolute real value of
// every product or accumulated dot product before it is rescaled from 2f to f
// fractional bits. MaxTruncations is an upper bound for the complete analysis,
// not merely one vector or protocol round. Both bounds must be derived and
// bound to the server-side analysis manifest; an analyst assertion is not a
// proof.
//
// The SecureML probability calculation also assumes a fresh, uniform additive
// split. A share produced by local truncation is not uniform and must not be
// fed into another local truncation without an audited refresh step.
type LocalTruncationHeadroom struct {
	RingBits              int
	FracBits              int
	MaxAbsTruncatedValue  float64
	MaxTruncations        uint64
	MinFailureBits        int
	BoundIsServerProven   bool
	SharesAreFreshUniform bool
}

// Validate fails closed unless the standard SecureML wrap-failure bound
//
//	Pr[failure] <= maxAbsValue * 2^(2*fracBits) / 2^ringBits
//
// is at most 2^-MinFailureBits over the complete analysis. The union bound
// adds ceil(log2(MaxTruncations)) bits to the per-event requirement. This
// controls, but cannot mathematically eliminate, the rare wrap event;
// zero-event correctness requires an interactive audited truncation protocol.
func (c LocalTruncationHeadroom) Validate() error {
	if !c.BoundIsServerProven {
		return fmt.Errorf("local truncation requires a server-proven bound")
	}
	if !c.SharesAreFreshUniform {
		return fmt.Errorf("local truncation requires a fresh uniform additive split")
	}
	if c.RingBits != k2Ring63Bits && c.RingBits != k2Ring127Bits {
		return fmt.Errorf("local truncation ring must be Ring63 or Ring127")
	}
	if c.FracBits < 1 || c.FracBits > c.RingBits-1 {
		return fmt.Errorf("local truncation frac_bits is outside the ring")
	}
	if err := validateFinite("max_abs_truncated_value", c.MaxAbsTruncatedValue); err != nil {
		return err
	}
	if c.MaxAbsTruncatedValue < 0 {
		return fmt.Errorf("max_abs_truncated_value must not be negative")
	}
	if c.MinFailureBits < 1 {
		return fmt.Errorf("min_failure_bits must be positive")
	}
	if c.MaxTruncations < 1 {
		return fmt.Errorf("max_truncations must be positive")
	}
	if c.MaxAbsTruncatedValue == 0 {
		return nil
	}
	// Frexp gives an exact binary decomposition of the already-validated
	// float64 bound. This avoids an optimistic one-bit result from Log2
	// rounding at an exact power-of-two boundary.
	fraction, exponent := math.Frexp(c.MaxAbsTruncatedValue)
	magnitudeBits := exponent
	if fraction == 0.5 {
		magnitudeBits--
	}
	// bits.Len64(n-1) is exactly ceil(log2(n)) for n >= 1.
	unionBits := bits.Len64(c.MaxTruncations - 1)
	availableFailureBits := c.RingBits - 2*c.FracBits - magnitudeBits - unionBits
	if availableFailureBits < c.MinFailureBits {
		return fmt.Errorf(
			"local truncation headroom proves only %d aggregate failure bits want %d",
			availableFailureBits, c.MinFailureBits,
		)
	}
	return nil
}

// SelectLocalTruncationRing is the implemented bounds preflight for the local
// truncation backend. It preserves the requested fractional precision and
// tries Ring63 before Ring127. It never rescales, chunks, or wraps silently.
// Those transformations require their own server-proven bounds, and no exact
// BigInt, CRT, or garbled-circuit truncation backend is implemented here. If
// Ring127 is insufficient, the caller receives an explicit error and must use
// a separately audited interactive protocol.
func SelectLocalTruncationRing(fracBits int, maxAbsValue float64,
	maxTruncations uint64, minFailureBits int, boundIsServerProven,
	sharesAreFreshUniform bool) (string, error) {
	for _, ringBits := range []int{k2Ring63Bits, k2Ring127Bits} {
		contract := LocalTruncationHeadroom{
			RingBits:              ringBits,
			FracBits:              fracBits,
			MaxAbsTruncatedValue:  maxAbsValue,
			MaxTruncations:        maxTruncations,
			MinFailureBits:        minFailureBits,
			BoundIsServerProven:   boundIsServerProven,
			SharesAreFreshUniform: sharesAreFreshUniform,
		}
		if err := contract.Validate(); err == nil {
			if ringBits == k2Ring63Bits {
				return "ring63", nil
			}
			return "ring127", nil
		}
	}
	return "", fmt.Errorf(
		"no implemented safe backend: Ring63 and Ring127 local truncation fail proven headroom; exact interactive fallback is unavailable",
	)
}

// AsymmetricLocalTruncatePair applies the legacy deterministic SecureML local
// truncation convention to a pair of additive shares. It needs no extra round,
// does not reconstruct the secret, and its reconstructed result differs from
// signed integer truncation by at most one ring unit under the protocol's
// normal wrap case. Like SecureML's local truncation, it has a wrap-failure
// probability proportional to the magnitude of the signed secret divided by
// the ring modulus. It is not stochastic and does not promise zero-mean error.
// This unguarded entry point is not suitable for a promoted production path;
// use a manifest-bound LocalTruncationHeadroom contract or interactive
// truncation.
func AsymmetricLocalTruncatePair(share0, share1, divisor, modulus uint64) (trunc0, trunc1 uint64) {
	trunc0 = share0 / divisor
	negS := (modulus - share1) % modulus
	trunc1 = (modulus - negS/divisor) % modulus
	return
}

// AsymmetricLocalHadamardProduct computes a Beaver product and applies the
// deterministic local truncation convention to the resulting share pair.
func AsymmetricLocalHadamardProduct(
	state0 BatchedMultState, beaver0 BeaverTripleVec, msg1 MultGateMessage,
	state1 BatchedMultState, beaver1 BeaverTripleVec, msg0 MultGateMessage,
	fracBits int, r Ring63) (res0, res1 []uint64) {

	raw0 := GenerateBatchedMultiplicationOutputPartyZero(state0, beaver0, msg1, r)
	raw1 := GenerateBatchedMultiplicationOutputPartyOne(state1, beaver1, msg0, r)

	divisor := uint64(1) << fracBits
	res0 = make([]uint64, len(raw0))
	res1 = make([]uint64, len(raw1))
	for i := range raw0 {
		res0[i], res1[i] = AsymmetricLocalTruncatePair(raw0[i], raw1[i], divisor, r.Modulus)
	}
	return
}

// CorrelatedStochasticTruncate is retained as a source-compatible alias for
// older internal tests. The historical name was incorrect: adding a carry to
// one share and subtracting it from the other cancels on reconstruction.
// Deprecated: use AsymmetricLocalTruncatePair.
func CorrelatedStochasticTruncate(share0, share1, divisor, modulus uint64) (uint64, uint64) {
	return AsymmetricLocalTruncatePair(share0, share1, divisor, modulus)
}

// StochasticHadamardProduct is the source-compatible historical name.
// Deprecated: use AsymmetricLocalHadamardProduct.
func StochasticHadamardProduct(
	state0 BatchedMultState, beaver0 BeaverTripleVec, msg1 MultGateMessage,
	state1 BatchedMultState, beaver1 BeaverTripleVec, msg0 MultGateMessage,
	fracBits int, r Ring63) (res0, res1 []uint64) {
	return AsymmetricLocalHadamardProduct(
		state0, beaver0, msg1, state1, beaver1, msg0, fracBits, r,
	)
}

// Legacy single-party wrappers retain the deterministic production behavior.
func StochasticHadamardProductPartyZero(
	state BatchedMultState, beaver BeaverTripleVec, otherMsg MultGateMessage,
	fracBits int, r Ring63) []uint64 {
	return HadamardProductPartyZero(state, beaver, otherMsg, fracBits, r)
}

func StochasticHadamardProductPartyOne(
	state BatchedMultState, beaver BeaverTripleVec, otherMsg MultGateMessage,
	fracBits int, r Ring63) []uint64 {
	return HadamardProductPartyOne(state, beaver, otherMsg, fracBits, r)
}
