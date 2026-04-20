// k2_dcf_commands.go: dsvert-mpc commands for DCF-based wide spline evaluation
// in the DataSHIELD relay model.
//
// Protocol flow (orchestrated by client):
//   1. Client calls k2-dcf-gen-batch → DCF keys for both parties
//   2. Client sends keys to respective servers
//   3. Each server calls k2-dcf-eval phase=1 → masked values
//   4. Client relays masked values between servers
//   5. Each server calls k2-dcf-eval phase=2 → comparison shares
//   6. Each server calls k2-spline-indicators → slope/intercept/indicator shares
//   7. Beaver AND for I_mid (reuse existing k2-beaver-round)
//   8. Beaver Hadamard for slope*x and I_mid*spline (reuse existing)

package main

import (
	"encoding/binary"
	"math"
)

// ============================================================================
// Command: k2-dcf-gen-batch
// Generates DCF preprocessing for ALL wide spline thresholds in one batch.
// Called by client, returns keys for both parties.
// ============================================================================

type K2DcfGenBatchInput struct {
	Family       string  `json:"family"`        // "binomial" | "poisson" | "softplus" | "reciprocal" | "log"
	N            int     `json:"n"`             // number of elements
	FracBits     int     `json:"frac_bits"`
	NumIntervals int     `json:"num_intervals"` // 0 = use default from K2Config
	// Optional domain override for "reciprocal" / "log". If zero,
	// defaults to K2ReciprocalLower / K2ReciprocalUpper or K2LogLower /
	// K2LogUpper. Ignored for other families which have fixed domains.
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
	// Ring selects the secret-share ring for DCF preprocessing.
	// "" or "ring63" (default): uses the Ring63 path (uint64 shares, 63-bit
	// DCF domain, 8-byte VCW) — the only path currently wired into
	// handleK2DcfGenBatch. "ring127": reserved for the Cox/LMM selective
	// migration; accepted as a forward-compat stub but NOT dispatched in
	// step 2 (handler panics if used). Dispatch + uint128 share blob
	// serialization land in P1 step 3.
	Ring string `json:"ring"`
}

type K2DcfGenBatchOutput struct {
	Party0Keys string    `json:"party0_keys"` // base64: serialized DCF keys + mask shares
	Party1Keys string    `json:"party1_keys"`
	Thresholds []float64 `json:"thresholds"`  // all thresholds (broad + sub-interval)
	NumBroad   int       `json:"num_broad"`   // number of broad thresholds (2)
}

func handleK2DcfGenBatch() {
	var input K2DcfGenBatchInput
	mpcReadInput(&input)
	if input.FracBits <= 0 {
		input.FracBits = K2DefaultFracBits
	}
	// Ring selector — step 2 accepts the field as forward-compat but only
	// the Ring63 path is wired into this handler. Ring127 dispatch (with
	// 16-byte share blob serialization) lands in P1 step 3.
	if input.Ring != "" && input.Ring != "ring63" {
		panic("k2-dcf-gen-batch: ring='" + input.Ring + "' not yet dispatched (P1 step 3)")
	}

	ring := NewRing63(input.FracBits)
	n := input.N

	// Determine thresholds based on family
	var lower, upper float64
	numInt := input.NumIntervals
	logSpaced := false
	switch input.Family {
	case "poisson":
		lower, upper = -3.0, 8.0
		if numInt <= 0 {
			numInt = K2ExpIntervals
		}
	case "softplus":
		lower, upper = -8.0, 8.0
		if numInt <= 0 {
			numInt = 80
		}
	case "reciprocal":
		lower, upper = K2ReciprocalLower, K2ReciprocalUpper
		if input.Lower > 0 {
			lower = input.Lower
		}
		if input.Upper > 0 {
			upper = input.Upper
		}
		if numInt <= 0 {
			numInt = K2ReciprocalIntervals
		}
		logSpaced = true
	case "log":
		lower, upper = K2LogLower, K2LogUpper
		if input.Lower > 0 {
			lower = input.Lower
		}
		if input.Upper > 0 {
			upper = input.Upper
		}
		if numInt <= 0 {
			numInt = K2LogIntervals
		}
		logSpaced = true
	default: // binomial
		lower, upper = -5.0, 5.0
		if numInt <= 0 {
			numInt = K2SigmoidIntervals
		}
	}

	// Build ALL thresholds: 2 broad + (numInt-1) sub-interval
	thresholds := make([]float64, 0, numInt+1)
	// Broad thresholds (always lower, upper)
	thresholds = append(thresholds, lower) // c_low: x < lower
	thresholds = append(thresholds, upper) // c_high: x < upper

	if logSpaced {
		// Log-spaced sub-interval breakpoints for 1/x and log(x): gives
		// uniform relative (reciprocal) / absolute (log) error across
		// the domain, matching the sigmoid baseline at equal K.
		logL := math.Log(lower)
		logU := math.Log(upper)
		for j := 0; j < numInt-1; j++ {
			thresholds = append(thresholds,
				math.Exp(logL+(logU-logL)*float64(j+1)/float64(numInt)))
		}
	} else {
		// Uniform sub-interval breakpoints for sigmoid / softplus / exp
		width := (upper - lower) / float64(numInt)
		for j := 0; j < numInt-1; j++ {
			thresholds = append(thresholds, lower+float64(j+1)*width)
		}
	}

	numThresh := len(thresholds)

	// Generate DCF preprocessing for each threshold
	allP0Keys := make([]CmpPreprocessPerParty, numThresh)
	allP1Keys := make([]CmpPreprocessPerParty, numThresh)
	for t := 0; t < numThresh; t++ {
		threshFP := ring.FromDouble(thresholds[t])
		allP0Keys[t], allP1Keys[t] = cmpGeneratePreprocess(ring, n, threshFP)
	}

	// Serialize all keys into compact binary blobs
	p0Bytes := serializeDcfBatch(allP0Keys, n, numThresh)
	p1Bytes := serializeDcfBatch(allP1Keys, n, numThresh)

	mpcWriteOutput(K2DcfGenBatchOutput{
		Party0Keys: bytesToBase64(p0Bytes),
		Party1Keys: bytesToBase64(p1Bytes),
		Thresholds: thresholds,
		NumBroad:   2,
	})
}

// ============================================================================
// DCF Batch Serialization
// ============================================================================

// serializeDcfBatch packs all DCF keys + mask shares into a single byte slice.
// Layout: for each threshold t, for each element i:
//   DCFKey: Seed0(16) + T0(1) + 63 * dcfCW(26) + FinalCW(8) = 1663 bytes
//   dcfCW: SeedCW(16) + VCW(8) + TCW_L(1) + TCW_R(1) = 26 bytes
//   MaskShare: 8 bytes
//   Total per element per threshold: 1671 bytes
func serializeDcfBatch(keys []CmpPreprocessPerParty, n, numThresh int) []byte {
	numBits := 63
	cwSize := 16 + 8 + 1 + 1 // SeedCW(16) + VCW(8) + TCW_L(1) + TCW_R(1)
	keySize := 16 + 1 + numBits*cwSize + 8 // Seed0 + T0 + CW array + FinalCW
	elemSize := keySize + 8 // + MaskShare

	buf := make([]byte, numThresh*n*elemSize)

	for t := 0; t < numThresh; t++ {
		for i := 0; i < n; i++ {
			offset := (t*n + i) * elemSize
			key := keys[t].Keys[i]

			// Seed0
			copy(buf[offset:offset+16], key.Seed0[:])
			// T0
			buf[offset+16] = key.T0
			// CW array
			for b := 0; b < numBits; b++ {
				cwOff := offset + 17 + b*cwSize
				copy(buf[cwOff:cwOff+16], key.CW[b].SeedCW[:])
				binary.LittleEndian.PutUint64(buf[cwOff+16:], uint64(key.CW[b].VCW))
				buf[cwOff+24] = key.CW[b].TCW_L
				buf[cwOff+25] = key.CW[b].TCW_R
			}
			// FinalCW
			binary.LittleEndian.PutUint64(buf[offset+17+numBits*cwSize:], uint64(key.FinalCW))
			// MaskShare
			binary.LittleEndian.PutUint64(buf[offset+keySize:], keys[t].MaskShare[i])
		}
	}

	return buf
}

func deserializeDcfBatch(buf []byte, n, numThresh int) []CmpPreprocessPerParty {
	numBits := 63
	cwSize := 16 + 8 + 1 + 1
	keySize := 16 + 1 + numBits*cwSize + 8
	elemSize := keySize + 8

	keys := make([]CmpPreprocessPerParty, numThresh)
	for t := 0; t < numThresh; t++ {
		keys[t].Keys = make([]DCFKey, n)
		keys[t].MaskShare = make([]uint64, n)

		for i := 0; i < n; i++ {
			offset := (t*n + i) * elemSize

			// Seed0
			copy(keys[t].Keys[i].Seed0[:], buf[offset:offset+16])
			// T0
			keys[t].Keys[i].T0 = buf[offset+16]
			// CW array
			keys[t].Keys[i].CW = make([]dcfCW, numBits)
			keys[t].Keys[i].NumBits = numBits
			for b := 0; b < numBits; b++ {
				cwOff := offset + 17 + b*cwSize
				copy(keys[t].Keys[i].CW[b].SeedCW[:], buf[cwOff:cwOff+16])
				keys[t].Keys[i].CW[b].VCW = int64(binary.LittleEndian.Uint64(buf[cwOff+16:]))
				keys[t].Keys[i].CW[b].TCW_L = buf[cwOff+24]
				keys[t].Keys[i].CW[b].TCW_R = buf[cwOff+25]
			}
			// FinalCW
			keys[t].Keys[i].FinalCW = int64(binary.LittleEndian.Uint64(buf[offset+17+numBits*cwSize:]))
			// MaskShare
			keys[t].MaskShare[i] = binary.LittleEndian.Uint64(buf[offset+keySize:])
		}
	}

	return keys
}

