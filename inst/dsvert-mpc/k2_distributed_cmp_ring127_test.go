// k2_distributed_cmp_ring127_test.go — end-to-end tests for the Ring127
// distributed comparison protocol: preprocessing → round 1 → round 2 →
// reconstruct. Includes the DCF batch serialization round-trip.

package main

import (
	"bytes"
	"math/rand"
	"testing"
)

// reconstructShares127: share0 + share1 mod 2^127.
func reconstructShares127(ring Ring127, a, b Uint128) Uint128 {
	return ring.Add(a, b)
}

// TestDistributedCmpRing127_EndToEnd exercises the full DCF-backed
// comparison protocol and verifies share reconstruction.
func TestDistributedCmpRing127_EndToEnd(t *testing.T) {
	ring := NewRing127(50) // matches Ring127 Beaver fracBits
	n := 50

	// Plaintext eta values, mixed positive / negative, skipping exact zero
	// (float64 accumulation lands within 1 ULP of zero for some steps).
	etaFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		// Range approximately [-2.95, 1.95], avoids exact zero.
		etaFloat[i] = -2.95 + float64(i)*0.1
	}
	threshold := 0.0

	// FP encode eta and split into shares.
	etaFP := make([]Uint128, n)
	etaSh0 := make([]Uint128, n)
	etaSh1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		etaFP[i] = ring.FromDouble(etaFloat[i])
		etaSh0[i], etaSh1[i] = ring.SplitShare(etaFP[i])
	}

	// Dealer: preprocess against threshold 0.
	p0Preproc, p1Preproc := cmpGeneratePreprocess127(ring, n, ring.FromDouble(threshold))

	// Round 1: each party masks its share.
	msg0 := cmpRound1_127(ring, 0, etaSh0, p0Preproc)
	msg1 := cmpRound1_127(ring, 1, etaSh1, p1Preproc)

	// Round 2: each party evaluates DCF at (ownMsg + peerMsg).
	res0 := cmpRound2_127(ring, 0, p0Preproc, msg0, msg1)
	res1 := cmpRound2_127(ring, 1, p1Preproc, msg1, msg0)

	// Reconstruct: share0 + share1 should be 1 if eta < threshold, else 0.
	for i := 0; i < n; i++ {
		sum := reconstructShares127(ring, res0.Shares[i], res1.Shares[i])
		var expected Uint128
		if etaFloat[i] < threshold {
			expected = Uint128{Lo: 1}
		}
		if sum.Cmp(expected) != 0 {
			t.Fatalf("i=%d eta=%v thresh=%v: got sum={%x,%x}, want {%x,%x}",
				i, etaFloat[i], threshold, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
		}
	}
}

// TestDistributedCmpRing127_NonzeroThreshold: comparison against a non-zero
// threshold — exercises the threshShifted arithmetic path.
func TestDistributedCmpRing127_NonzeroThreshold(t *testing.T) {
	ring := NewRing127(50)
	n := 40
	threshold := 1.5

	etaFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		etaFloat[i] = float64(i) * 0.1 // 0.0, 0.1, ..., 3.9
	}

	etaSh0 := make([]Uint128, n)
	etaSh1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		etaSh0[i], etaSh1[i] = ring.SplitShare(ring.FromDouble(etaFloat[i]))
	}

	p0, p1 := cmpGeneratePreprocess127(ring, n, ring.FromDouble(threshold))

	msg0 := cmpRound1_127(ring, 0, etaSh0, p0)
	msg1 := cmpRound1_127(ring, 1, etaSh1, p1)

	res0 := cmpRound2_127(ring, 0, p0, msg0, msg1)
	res1 := cmpRound2_127(ring, 1, p1, msg1, msg0)

	for i := 0; i < n; i++ {
		sum := ring.Add(res0.Shares[i], res1.Shares[i])
		var expected Uint128
		if etaFloat[i] < threshold {
			expected = Uint128{Lo: 1}
		}
		if sum.Cmp(expected) != 0 {
			t.Fatalf("i=%d eta=%v thresh=%v: got sum={%x,%x}, want {%x,%x}",
				i, etaFloat[i], threshold, sum.Hi, sum.Lo, expected.Hi, expected.Lo)
		}
	}
}

// TestSerializeDcfBatch127_RoundTrip: serialize → deserialize → serialize
// produces identical bytes; post-deserialization keys evaluate identically.
func TestSerializeDcfBatch127_RoundTrip(t *testing.T) {
	ring := NewRing127(50)
	n := 8
	numThresh := 3
	thresholds := []float64{-1.0, 0.0, 1.0}

	// Generate numThresh preprocessings.
	p0Keys := make([]CmpPreprocessPerParty127, numThresh)
	p1Keys := make([]CmpPreprocessPerParty127, numThresh)
	for ti := 0; ti < numThresh; ti++ {
		p0Keys[ti], p1Keys[ti] = cmpGeneratePreprocess127(ring, n, ring.FromDouble(thresholds[ti]))
	}

	// Serialize, deserialize, re-serialize — bytes must be identical.
	buf0 := serializeDcfBatch127(p0Keys, n, numThresh)
	deser := deserializeDcfBatch127(buf0, n, numThresh)
	buf0Again := serializeDcfBatch127(deser, n, numThresh)

	if !bytes.Equal(buf0, buf0Again) {
		t.Fatalf("serialize→deserialize→serialize not idempotent: lens %d vs %d",
			len(buf0), len(buf0Again))
	}

	// Confirm deserialized keys evaluate identically to originals on 20 random x.
	rng := rand.New(rand.NewSource(7))
	maskHi := (uint64(1) << 63) - 1
	for ti := 0; ti < numThresh; ti++ {
		for i := 0; i < n; i++ {
			for k := 0; k < 20; k++ {
				x := Uint128{Hi: rng.Uint64() & maskHi, Lo: rng.Uint64()}
				origEval := DCFEval127(0, p0Keys[ti].Keys[i], x)
				deserEval := DCFEval127(0, deser[ti].Keys[i], x)
				if origEval.Cmp(deserEval) != 0 {
					t.Fatalf("ti=%d i=%d k=%d: orig={%x,%x} != deser={%x,%x}",
						ti, i, k, origEval.Hi, origEval.Lo, deserEval.Hi, deserEval.Lo)
				}
			}
			if p0Keys[ti].MaskShare[i].Cmp(deser[ti].MaskShare[i]) != 0 {
				t.Fatalf("ti=%d i=%d mask mismatch", ti, i)
			}
		}
	}
}

// TestSerializeDcfBatch127_Size: sanity-check the computed byte layout.
func TestSerializeDcfBatch127_Size(t *testing.T) {
	n := 5
	numThresh := 2
	ring := NewRing127(50)
	p0, _ := cmpGeneratePreprocess127(ring, n, Uint128{})
	keys := []CmpPreprocessPerParty127{p0, p0}

	buf := serializeDcfBatch127(keys, n, numThresh)
	expected := numThresh * n * ring127DcfElemSize
	if len(buf) != expected {
		t.Fatalf("serialized size %d != expected %d (numThresh=%d n=%d elemSize=%d)",
			len(buf), expected, numThresh, n, ring127DcfElemSize)
	}

	// Known-good size per element: 16 + 1 + 127·34 + 16 + 16 = 4367.
	if ring127DcfElemSize != 4367 {
		t.Fatalf("ring127DcfElemSize %d != 4367 (layout regression)", ring127DcfElemSize)
	}
}

// TestDistributedCmpRing127_FullEndToEndWithSerialization: end-to-end round
// trip through the serialization layer, matching the intended over-the-wire
// usage (GenBatch → bytes → Phase 1/2 uses keys from deserialized bytes).
func TestDistributedCmpRing127_FullEndToEndWithSerialization(t *testing.T) {
	ring := NewRing127(50)
	n := 20
	threshold := 0.5

	etaFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		etaFloat[i] = -1.0 + float64(i)*0.1 // -1.0, -0.9, ..., 0.9
	}

	etaSh0 := make([]Uint128, n)
	etaSh1 := make([]Uint128, n)
	for i := 0; i < n; i++ {
		etaSh0[i], etaSh1[i] = ring.SplitShare(ring.FromDouble(etaFloat[i]))
	}

	// Dealer
	p0, p1 := cmpGeneratePreprocess127(ring, n, ring.FromDouble(threshold))

	// Serialize (as handler would), then deserialize (as phase handlers would).
	p0Bytes := serializeDcfBatch127([]CmpPreprocessPerParty127{p0}, n, 1)
	p1Bytes := serializeDcfBatch127([]CmpPreprocessPerParty127{p1}, n, 1)
	p0Restored := deserializeDcfBatch127(p0Bytes, n, 1)[0]
	p1Restored := deserializeDcfBatch127(p1Bytes, n, 1)[0]

	// Protocol from restored keys
	msg0 := cmpRound1_127(ring, 0, etaSh0, p0Restored)
	msg1 := cmpRound1_127(ring, 1, etaSh1, p1Restored)
	res0 := cmpRound2_127(ring, 0, p0Restored, msg0, msg1)
	res1 := cmpRound2_127(ring, 1, p1Restored, msg1, msg0)

	for i := 0; i < n; i++ {
		sum := ring.Add(res0.Shares[i], res1.Shares[i])
		var expected Uint128
		if etaFloat[i] < threshold {
			expected = Uint128{Lo: 1}
		}
		if sum.Cmp(expected) != 0 {
			t.Fatalf("i=%d eta=%v: got sum={%x,%x}, want {%x,%x}",
				i, etaFloat[i], sum.Hi, sum.Lo, expected.Hi, expected.Lo)
		}
	}
}
