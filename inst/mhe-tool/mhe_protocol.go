// mhe_protocol.go: Full Multiparty HE protocol implementation
//
// This implements proper threshold MHE where:
// - Each server has its own secret key share
// - Decryption requires ALL servers to cooperate
// - Client cannot decrypt without all partial decryptions

package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// ============================================================================
// Phase 1: Setup - Each server generates their key shares
// ============================================================================

type MHESetupInput struct {
	PartyID     int    `json:"party_id"`
	CRP         string `json:"crp,omitempty"`          // Base64, empty for party 0
	GKGSeed     string `json:"gkg_seed,omitempty"`     // Base64, shared seed for deterministic GKG CRPs (empty for party 0)
	NumObs      int    `json:"num_obs"`                // Number of observations (for minimal galois keys)
	LogN        int    `json:"log_n"`
	LogScale    int    `json:"log_scale"`
	GenerateRLK bool   `json:"generate_rlk,omitempty"` // Generate relinearization key share (for ct×ct multiplication)
}

type MHESetupOutput struct {
	// Secret key stays on server (stored in session)
	SecretKey      string `json:"secret_key"`       // Base64 - NEVER sent to client
	PublicKeyShare string `json:"public_key_share"` // Base64 - sent for combining

	// CRP (only party 0 generates)
	CRP string `json:"crp,omitempty"` // Base64

	// Shared seed for deterministic GKG CRP generation (only party 0 returns this)
	GKGSeed string `json:"gkg_seed,omitempty"` // Base64

	// Galois key shares for collaborative generation (one per rotation)
	GaloisKeyShares []string `json:"galois_key_shares"` // Base64 array

	// RLK round 1 share (for ct×ct multiplication, only when GenerateRLK=true)
	// The RLK protocol is two-round: round 1 shares are aggregated, then
	// each party generates a round 2 share using the aggregated round 1.
	RLKRound1Share  string `json:"rlk_round1_share,omitempty"`  // Base64
	RLKEphemeralSK  string `json:"rlk_ephemeral_sk,omitempty"`  // Base64 - stored locally, NEVER sent to client

	PartyID int `json:"party_id"`
}

func mheSetup(input *MHESetupInput) (*MHESetupOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	kgen := rlwe.NewKeyGenerator(params)

	// Generate this party's secret key
	sk := kgen.GenSecretKeyNew()
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize secret key: %v", err)
	}

	// Initialize PKG protocol
	pkg := multiparty.NewPublicKeyGenProtocol(params)

	var crp multiparty.PublicKeyGenCRP
	var crpB64, gkgSeedB64 string

	if input.PartyID == 0 {
		// Party 0 generates PKG CRP
		prng, err := sampling.NewPRNG()
		if err != nil {
			return nil, fmt.Errorf("failed to create PRNG: %v", err)
		}
		crp = pkg.SampleCRP(prng)
		crpBytes, err := crp.Value.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize CRP: %v", err)
		}
		crpB64 = base64.StdEncoding.EncodeToString(crpBytes)

		// Party 0 generates a random seed for deterministic GKG CRPs
		gkgSeed := make([]byte, 32)
		if _, err := crand.Read(gkgSeed); err != nil {
			return nil, fmt.Errorf("failed to generate GKG seed: %v", err)
		}
		gkgSeedB64 = base64.StdEncoding.EncodeToString(gkgSeed)
	} else {
		// Other parties use received CRP
		crpBytes, err := base64.StdEncoding.DecodeString(input.CRP)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CRP: %v", err)
		}
		if err := crp.Value.UnmarshalBinary(crpBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize CRP: %v", err)
		}
		// Use the shared GKG seed from party 0
		gkgSeedB64 = input.GKGSeed
	}

	// Generate public key share
	pkShare := pkg.AllocateShare()
	pkg.GenShare(sk, crp, &pkShare)
	pkShareBytes, err := pkShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key share: %v", err)
	}

	// Generate Galois key shares using SHARED deterministic PRNG
	// All parties use the same seed → same CRPs → shares can be aggregated
	gkgSeed, err := base64.StdEncoding.DecodeString(gkgSeedB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode GKG seed: %v", err)
	}
	gkgPRNG, err := sampling.NewKeyedPRNG(gkgSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyed PRNG for GKG: %v", err)
	}

	// Use Lattigo's GaloisElementsForInnerSum to get the exact set of
	// Galois elements needed for InnerSum(ct, 1, numObs, ctOut)
	galEls := params.GaloisElementsForInnerSum(1, input.NumObs)
	sort.Slice(galEls, func(i, j int) bool { return galEls[i] < galEls[j] })

	gkg := multiparty.NewGaloisKeyGenProtocol(params)
	galoisSharesB64 := make([]string, len(galEls))
	for i, galEl := range galEls {
		gkgCRP := gkg.SampleCRP(gkgPRNG)
		gkgShare := gkg.AllocateShare()
		gkg.GenShare(sk, galEl, gkgCRP, &gkgShare)
		shareBytes, err := gkgShare.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize galois key share %d: %v", i, err)
		}
		galoisSharesB64[i] = base64.StdEncoding.EncodeToString(shareBytes)
	}

	// Generate RLK round 1 share if requested (for ct×ct multiplication in HE-Link mode).
	// The Lattigo RLK protocol is two-round:
	//   Round 1: Each party generates ephSk + round1 share, broadcasts round1
	//   Round 2: After aggregating round1, each party generates round2 share
	//   Finalize: Aggregate round2, generate RLK from (aggR1, aggR2)
	var rlkR1B64, rlkEphSkB64 string
	if input.GenerateRLK {
		rlkSeedBytes := append(append([]byte{}, gkgSeed...), []byte("rlk")...)
		rlkPRNG, err := sampling.NewKeyedPRNG(rlkSeedBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create RLK PRNG: %v", err)
		}

		rlkGen := multiparty.NewRelinearizationKeyGenProtocol(params)
		rlkCRP := rlkGen.SampleCRP(rlkPRNG)
		ephSk, r1Share, _ := rlkGen.AllocateShare()
		rlkGen.GenShareRoundOne(sk, rlkCRP, ephSk, &r1Share)

		r1Bytes, err := r1Share.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize RLK round1 share: %v", err)
		}
		rlkR1B64 = base64.StdEncoding.EncodeToString(r1Bytes)

		ephSkBytes, err := ephSk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize RLK ephemeral SK: %v", err)
		}
		rlkEphSkB64 = base64.StdEncoding.EncodeToString(ephSkBytes)
	}

	return &MHESetupOutput{
		SecretKey:       base64.StdEncoding.EncodeToString(skBytes),
		PublicKeyShare:  base64.StdEncoding.EncodeToString(pkShareBytes),
		CRP:             crpB64,
		GKGSeed:         gkgSeedB64,
		GaloisKeyShares: galoisSharesB64,
		RLKRound1Share:  rlkR1B64,
		RLKEphemeralSK:  rlkEphSkB64,
		PartyID:         input.PartyID,
	}, nil
}

// ============================================================================
// Phase 2: Combine shares into collective keys
// ============================================================================

type MHECombineInput struct {
	PublicKeyShares    []string   `json:"public_key_shares"`              // Base64 array
	GaloisKeyShares    [][]string `json:"galois_key_shares"`              // Base64 [party][galEl]
	GKGSeed            string     `json:"gkg_seed,omitempty"`             // Shared seed for CRP recreation
	CRP                string     `json:"crp"`                            // Base64
	RLKRound1Aggregated string    `json:"rlk_round1_aggregated,omitempty"` // Base64: aggregated round1 shares
	RLKRound2Shares    []string   `json:"rlk_round2_shares,omitempty"`     // Base64 array: per-party round2 shares
	NumObs             int        `json:"num_obs"`
	LogN               int        `json:"log_n"`
	LogScale           int        `json:"log_scale"`
}

type MHECombineOutput struct {
	CollectivePublicKey string   `json:"collective_public_key"` // Base64
	GaloisKeys          []string `json:"galois_keys"`           // Base64 array (one per rotation)
	RelinearizationKey  string   `json:"relinearization_key"`   // Base64
}

func mheCombine(input *MHECombineInput) (*MHECombineOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	numParties := len(input.PublicKeyShares)
	if numParties == 0 {
		return nil, fmt.Errorf("no public key shares provided")
	}

	// Deserialize CRP
	crpBytes, err := base64.StdEncoding.DecodeString(input.CRP)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CRP: %v", err)
	}
	var crp multiparty.PublicKeyGenCRP
	if err := crp.Value.UnmarshalBinary(crpBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize CRP: %v", err)
	}

	// Combine public key shares
	pkg := multiparty.NewPublicKeyGenProtocol(params)
	aggregatedPKShare := pkg.AllocateShare()

	for i, shareB64 := range input.PublicKeyShares {
		shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode PK share %d: %v", i, err)
		}
		share := pkg.AllocateShare()
		if err := share.UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize PK share %d: %v", i, err)
		}
		pkg.AggregateShares(share, aggregatedPKShare, &aggregatedPKShare)
	}

	cpk := rlwe.NewPublicKey(params)
	pkg.GenPublicKey(aggregatedPKShare, crp, cpk)

	cpkBytes, err := cpk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CPK: %v", err)
	}

	// Use Lattigo's GaloisElementsForInnerSum (must match mhe-setup exactly)
	galEls := params.GaloisElementsForInnerSum(1, input.NumObs)
	sort.Slice(galEls, func(i, j int) bool { return galEls[i] < galEls[j] })

	// Decode GKG seed (shared across Galois key gen and RLK gen)
	var gkgSeed []byte
	if len(input.GKGSeed) > 0 {
		gkgSeed, err = base64.StdEncoding.DecodeString(input.GKGSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode GKG seed: %v", err)
		}
	}

	var gksB64 []string

	if len(input.GaloisKeyShares) == numParties && len(gkgSeed) > 0 {
		// Proper threshold GKG: recreate deterministic PRNG from shared seed,
		// aggregate per-party shares, generate correct Galois keys
		gkgPRNG, err := sampling.NewKeyedPRNG(gkgSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to create keyed PRNG for GKG: %v", err)
		}

		gkg := multiparty.NewGaloisKeyGenProtocol(params)
		gksB64 = make([]string, len(galEls))

		for elIdx := range galEls {
			// Recreate the same CRP that all parties used during setup
			gkgCRP := gkg.SampleCRP(gkgPRNG)

			// Aggregate shares from all parties for this Galois element.
			// Use first party's share as the initial accumulator (AllocateShare
			// returns GaloisElement=0 which would cause AggregateShares to fail).
			var aggregatedGKShare multiparty.GaloisKeyGenShare
			for partyIdx := 0; partyIdx < numParties; partyIdx++ {
				if elIdx >= len(input.GaloisKeyShares[partyIdx]) {
					return nil, fmt.Errorf("party %d has fewer GKG shares than expected", partyIdx)
				}
				shareBytes, err := base64.StdEncoding.DecodeString(input.GaloisKeyShares[partyIdx][elIdx])
				if err != nil {
					return nil, fmt.Errorf("failed to decode GKG share [party=%d, el=%d]: %v", partyIdx, elIdx, err)
				}
				share := gkg.AllocateShare()
				if err := share.UnmarshalBinary(shareBytes); err != nil {
					return nil, fmt.Errorf("failed to deserialize GKG share [party=%d, el=%d]: %v", partyIdx, elIdx, err)
				}
				if partyIdx == 0 {
					aggregatedGKShare = share
				} else {
					if err := gkg.AggregateShares(share, aggregatedGKShare, &aggregatedGKShare); err != nil {
						return nil, fmt.Errorf("failed to aggregate GKG shares [party=%d, el=%d]: %v", partyIdx, elIdx, err)
					}
				}
			}

			// Generate final Galois key from aggregated share + CRP
			gk := rlwe.NewGaloisKey(params)
			gkg.GenGaloisKey(aggregatedGKShare, gkgCRP, gk)

			gkBytes, err := gk.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize galois key %d: %v", elIdx, err)
			}
			gksB64[elIdx] = base64.StdEncoding.EncodeToString(gkBytes)
		}
	} else {
		// No GKG shares provided — return empty (Galois keys unavailable)
		gksB64 = make([]string, 0)
	}

	// Generate collective RLK from aggregated round1 + per-party round2 shares
	rlkB64 := ""
	if len(input.RLKRound1Aggregated) > 0 && len(input.RLKRound2Shares) > 0 {
		rlkGen := multiparty.NewRelinearizationKeyGenProtocol(params)

		// Deserialize aggregated round 1
		aggR1Bytes, err := base64.StdEncoding.DecodeString(input.RLKRound1Aggregated)
		if err != nil {
			return nil, fmt.Errorf("failed to decode aggregated RLK round1: %v", err)
		}
		_, aggR1, _ := rlkGen.AllocateShare()
		if err := aggR1.UnmarshalBinary(aggR1Bytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize aggregated RLK round1: %v", err)
		}

		// Aggregate round 2 shares
		var aggR2 multiparty.RelinearizationKeyGenShare
		for i, shareB64 := range input.RLKRound2Shares {
			shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RLK round2 share %d: %v", i, err)
			}
			_, _, r2 := rlkGen.AllocateShare()
			if err := r2.UnmarshalBinary(shareBytes); err != nil {
				return nil, fmt.Errorf("failed to deserialize RLK round2 share %d: %v", i, err)
			}
			if i == 0 {
				aggR2 = r2
			} else {
				rlkGen.AggregateShares(r2, aggR2, &aggR2)
			}
		}

		// Generate collective RLK from (aggregated round1, aggregated round2)
		rlk := rlwe.NewRelinearizationKey(params)
		rlkGen.GenRelinearizationKey(aggR1, aggR2, rlk)

		rlkBytes, err := rlk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize RLK: %v", err)
		}
		rlkB64 = base64.StdEncoding.EncodeToString(rlkBytes)
	}

	return &MHECombineOutput{
		CollectivePublicKey: base64.StdEncoding.EncodeToString(cpkBytes),
		GaloisKeys:          gksB64,
		RelinearizationKey:  rlkB64,
	}, nil
}

// ============================================================================
// Phase 2b: RLK Round 1 Aggregation + Round 2 Generation
// ============================================================================

type RLKAggregateR1Input struct {
	RLKRound1Shares []string `json:"rlk_round1_shares"` // Base64 array: per-party round 1 shares
	LogN            int      `json:"log_n"`
	LogScale        int      `json:"log_scale"`
}

type RLKAggregateR1Output struct {
	AggregatedRound1 string `json:"aggregated_round1"` // Base64: aggregated round 1
}

func mheRLKAggregateR1(input *RLKAggregateR1Input) (*RLKAggregateR1Output, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	rlkGen := multiparty.NewRelinearizationKeyGenProtocol(params)

	var aggR1 multiparty.RelinearizationKeyGenShare
	for i, shareB64 := range input.RLKRound1Shares {
		shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RLK R1 share %d: %v", i, err)
		}
		_, r1, _ := rlkGen.AllocateShare()
		if err := r1.UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize RLK R1 share %d: %v", i, err)
		}
		if i == 0 {
			aggR1 = r1
		} else {
			rlkGen.AggregateShares(r1, aggR1, &aggR1)
		}
	}

	aggR1Bytes, err := aggR1.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize aggregated R1: %v", err)
	}

	return &RLKAggregateR1Output{
		AggregatedRound1: base64.StdEncoding.EncodeToString(aggR1Bytes),
	}, nil
}

type RLKRound2Input struct {
	SecretKey        string `json:"secret_key"`         // Base64: this party's secret key
	RLKEphemeralSK   string `json:"rlk_ephemeral_sk"`   // Base64: ephemeral SK from round 1
	AggregatedRound1 string `json:"aggregated_round1"`  // Base64: aggregated round 1 shares
	LogN             int    `json:"log_n"`
	LogScale         int    `json:"log_scale"`
}

type RLKRound2Output struct {
	RLKRound2Share string `json:"rlk_round2_share"` // Base64
}

func mheRLKRound2(input *RLKRound2Input) (*RLKRound2Output, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	// Deserialize secret key
	skBytes, err := base64.StdEncoding.DecodeString(input.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}
	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Deserialize ephemeral SK
	ephSkBytes, err := base64.StdEncoding.DecodeString(input.RLKEphemeralSK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral SK: %v", err)
	}
	ephSk := rlwe.NewSecretKey(params)
	if err := ephSk.UnmarshalBinary(ephSkBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ephemeral SK: %v", err)
	}

	// Deserialize aggregated round 1
	aggR1Bytes, err := base64.StdEncoding.DecodeString(input.AggregatedRound1)
	if err != nil {
		return nil, fmt.Errorf("failed to decode aggregated round1: %v", err)
	}

	rlkGen := multiparty.NewRelinearizationKeyGenProtocol(params)
	_, aggR1, _ := rlkGen.AllocateShare()
	if err := aggR1.UnmarshalBinary(aggR1Bytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize aggregated round1: %v", err)
	}

	// Generate round 2 share
	_, _, r2Share := rlkGen.AllocateShare()
	rlkGen.GenShareRoundTwo(ephSk, sk, aggR1, &r2Share)

	r2Bytes, err := r2Share.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize round2 share: %v", err)
	}

	return &RLKRound2Output{
		RLKRound2Share: base64.StdEncoding.EncodeToString(r2Bytes),
	}, nil
}

// ============================================================================
// Phase 3: Cross-product (returns ENCRYPTED result)
// ============================================================================

type MHECrossProductInput struct {
	PlaintextColumns [][]float64 `json:"plaintext_columns"`
	EncryptedColumns []string    `json:"encrypted_columns"`
	LogN             int         `json:"log_n"`
	LogScale         int         `json:"log_scale"`
}

type MHECrossProductOutput struct {
	// Each result[i][j] is an encrypted element-wise product z_A_i * enc(z_B_j)
	// Client decrypts the full vector, then sums to get the inner product
	EncryptedResults [][]string `json:"encrypted_results"` // Base64 [pA][pB] ciphertexts
}

func mheCrossProduct(input *MHECrossProductInput) (*MHECrossProductOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	pA := len(input.PlaintextColumns)
	pB := len(input.EncryptedColumns)
	if pA == 0 || pB == 0 {
		return nil, fmt.Errorf("empty input")
	}

	encoder := ckks.NewEncoder(params)

	// No eval keys needed: plaintext * ciphertext stays degree 1
	// We create a minimal evaluator (no eval keys)
	evaluator := ckks.NewEvaluator(params, nil)

	// Decode encrypted columns
	encCols := make([]*rlwe.Ciphertext, pB)
	for j := 0; j < pB; j++ {
		ctBytes, err := base64.StdEncoding.DecodeString(input.EncryptedColumns[j])
		if err != nil {
			return nil, fmt.Errorf("failed to decode encrypted column %d: %v", j, err)
		}
		ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := ct.UnmarshalBinary(ctBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize encrypted column %d: %v", j, err)
		}
		encCols[j] = ct
	}

	// Compute element-wise products (NO sum-reduce, NO eval keys needed)
	// plaintext * ciphertext = degree-1 ciphertext (no relinearization)
	// Summation done by client after decryption
	results := make([][]string, pA)

	for i := 0; i < pA; i++ {
		results[i] = make([]string, pB)

		ptCol := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(input.PlaintextColumns[i], ptCol); err != nil {
			return nil, fmt.Errorf("failed to encode column %d: %v", i, err)
		}

		for j := 0; j < pB; j++ {
			// Element-wise multiply: plaintext * ciphertext → degree-1 ciphertext
			product, err := evaluator.MulNew(encCols[j], ptCol)
			if err != nil {
				return nil, fmt.Errorf("failed to multiply [%d,%d]: %v", i, j, err)
			}
			if err := evaluator.Rescale(product, product); err != nil {
				return nil, fmt.Errorf("failed to rescale [%d,%d]: %v", i, j, err)
			}

			// Serialize encrypted result (full vector, NOT summed)
			ctBytes, err := product.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to serialize result [%d,%d]: %v", i, j, err)
			}
			results[i][j] = base64.StdEncoding.EncodeToString(ctBytes)
		}
	}

	return &MHECrossProductOutput{
		EncryptedResults: results,
	}, nil
}

// ============================================================================
// Phase 4: Threshold Decryption
// ============================================================================

type MHEPartialDecryptInput struct {
	Ciphertext string `json:"ciphertext"` // Base64
	SecretKey  string `json:"secret_key"` // Base64
	LogN       int    `json:"log_n"`
	LogScale   int    `json:"log_scale"`
}

type MHEPartialDecryptOutput struct {
	DecryptionShare string `json:"decryption_share"` // Base64
}

func mhePartialDecrypt(input *MHEPartialDecryptInput) (*MHEPartialDecryptOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(input.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Decode secret key
	skBytes, err := base64.StdEncoding.DecodeString(input.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}
	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Create decryption share using KeySwitch protocol.
	// Noise smudging σ must be large enough to mask the secret key's contribution
	// to the decryption share. With σ_smudge >> σ_sk (secret key noise),
	// the share reveals no information about sk beyond what the final plaintext
	// reveals. σ=128, Bound=6σ≈768 provides ~40 bits of statistical security
	// for IND-CPAD against Li-Micciancio / Guo et al. attacks.
	noise := ring.DiscreteGaussian{Sigma: 128.0, Bound: 768.0}
	ks, err := multiparty.NewKeySwitchProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeySwitch protocol: %v", err)
	}

	// GenShare for decryption to zero (skOut = zero key)
	zeroSK := rlwe.NewSecretKey(params) // Zero key
	share := ks.AllocateShare(ct.Level())
	ks.GenShare(sk, zeroSK, ct, &share)

	shareBytes, err := share.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize share: %v", err)
	}

	return &MHEPartialDecryptOutput{
		DecryptionShare: base64.StdEncoding.EncodeToString(shareBytes),
	}, nil
}

// ============================================================================
// Phase 5: Fuse decryption shares (client-side)
// ============================================================================

type MHEFuseInput struct {
	Ciphertext       string   `json:"ciphertext"`        // Base64
	DecryptionShares []string `json:"decryption_shares"` // Base64 array
	NumSlots         int      `json:"num_slots"`         // Number of valid slots to return (0 = return slot 0 only)
	LogN             int      `json:"log_n"`
	LogScale         int      `json:"log_scale"`
}

type MHEFuseOutput struct {
	Value  float64   `json:"value"`            // Sum of first num_slots values (inner product)
	Values []float64 `json:"values,omitempty"` // Individual slot values (if num_slots > 0)
}

func mheFuse(input *MHEFuseInput) (*MHEFuseOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(input.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Initialize KeySwitch protocol with noise smudging consistent with
	// mhePartialDecrypt. σ=128, Bound=6σ≈768 for IND-CPAD security.
	noise := ring.DiscreteGaussian{Sigma: 128.0, Bound: 768.0}
	ks, err := multiparty.NewKeySwitchProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeySwitch protocol: %v", err)
	}

	// Aggregate all shares
	aggregatedShare := ks.AllocateShare(ct.Level())
	for i, shareB64 := range input.DecryptionShares {
		shareBytes, err := base64.StdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share %d: %v", i, err)
		}
		share := ks.AllocateShare(ct.Level())
		if err := share.UnmarshalBinary(shareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize share %d: %v", i, err)
		}
		if err := ks.AggregateShares(share, aggregatedShare, &aggregatedShare); err != nil {
			return nil, fmt.Errorf("failed to aggregate share %d: %v", i, err)
		}
	}

	// Apply key switch to get decrypted ciphertext
	ctOut := rlwe.NewCiphertext(params, 1, ct.Level())
	ks.KeySwitch(ct, aggregatedShare, ctOut)

	// Decode using DecodePublic to prevent IND-CPAD / Key Recovery attacks.
	// Standard Decode exposes the full CKKS noise, which an adversary can use
	// to recover the secret key (Li & Micciancio 2021, Guo et al. USENIX 2024).
	// DecodePublic adds noise flooding (σ_smudge) to sanitize the output,
	// making noise indistinguishable from uniform.
	encoder := ckks.NewEncoder(params)
	pt := ckks.NewPlaintext(params, ctOut.Level())
	pt.Value = ctOut.Value[0]
	pt.MetaData = ctOut.MetaData

	values := make([]float64, params.MaxSlots())
	// DecodePublic(pt, values, logprec): logprec controls the noise flooding
	// precision. Lower logprec = more noise = more security but less precision.
	// With logScale=40, logprec=32 gives ~8 bits of smudging noise,
	// sufficient to prevent key recovery while preserving ~1e-5 precision.
	if err := encoder.DecodePublic(pt, values, 32); err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}

	numSlots := input.NumSlots
	if numSlots <= 0 {
		// Legacy mode: return slot 0 only
		return &MHEFuseOutput{Value: values[0]}, nil
	}

	// Sum the first numSlots values (inner product)
	sum := 0.0
	slotValues := make([]float64, numSlots)
	for i := 0; i < numSlots && i < len(values); i++ {
		slotValues[i] = values[i]
		sum += values[i]
	}

	return &MHEFuseOutput{
		Value:  sum,
		Values: slotValues,
	}, nil
}

// ============================================================================
// Phase 5b: Server-side fusion (share-wrapping)
// ============================================================================
// The fusion server (party 0) unwraps transport-encrypted shares from other
// servers, computes its own partial decryption share, aggregates all shares,
// and applies DecodePublic. The client never sees raw shares or unsanitized
// plaintext — it only receives the final aggregate statistic.

type MHEFuseServerInput struct {
	Ciphertext         string   `json:"ciphertext"`           // Base64: the ciphertext to decrypt
	SecretKey          string   `json:"secret_key"`           // Base64: fusion server's MHE secret key share
	WrappedShares      []string `json:"wrapped_shares"`       // Base64: transport-encrypted shares from other servers
	TransportSecretKey string   `json:"transport_secret_key"` // Base64: fusion server's X25519 secret key
	NumSlots           int      `json:"num_slots"`
	LogN               int      `json:"log_n"`
	LogScale           int      `json:"log_scale"`
}

func mheFuseServer(input *MHEFuseServerInput) (*MHEFuseOutput, error) {
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	// Decode ciphertext
	ctBytes, err := base64.StdEncoding.DecodeString(input.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	ct := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(ctBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %v", err)
	}

	// Decode fusion server's MHE secret key
	skBytes, err := base64.StdEncoding.DecodeString(input.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %v", err)
	}
	sk := rlwe.NewSecretKey(params)
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to deserialize secret key: %v", err)
	}

	// Decode transport secret key for unwrapping
	transportSK, err := base64.StdEncoding.DecodeString(input.TransportSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transport secret key: %v", err)
	}

	// Initialize KeySwitch protocol with noise smudging
	noise := ring.DiscreteGaussian{Sigma: 128.0, Bound: 768.0}
	ks, err := multiparty.NewKeySwitchProtocol(params, noise)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeySwitch protocol: %v", err)
	}

	// Step 1: Compute fusion server's own partial decryption share
	zeroSK := rlwe.NewSecretKey(params)
	ownShare := ks.AllocateShare(ct.Level())
	ks.GenShare(sk, zeroSK, ct, &ownShare)

	// Step 2: Unwrap and aggregate other servers' shares
	aggregatedShare := ownShare // Start with own share
	for i, wrappedB64 := range input.WrappedShares {
		// Decode the wrapped (transport-encrypted) share
		wrappedBytes, err := base64.StdEncoding.DecodeString(wrappedB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode wrapped share %d: %v", i, err)
		}

		// Transport-decrypt to get raw share bytes
		rawShareBytes, err := transportDecryptBytes(wrappedBytes, transportSK)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap share %d: %v", i, err)
		}

		// Deserialize KeySwitch share
		share := ks.AllocateShare(ct.Level())
		if err := share.UnmarshalBinary(rawShareBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize unwrapped share %d: %v", i, err)
		}

		if err := ks.AggregateShares(share, aggregatedShare, &aggregatedShare); err != nil {
			return nil, fmt.Errorf("failed to aggregate share %d: %v", i, err)
		}
	}

	// Step 3: KeySwitch to decrypt
	ctOut := rlwe.NewCiphertext(params, 1, ct.Level())
	ks.KeySwitch(ct, aggregatedShare, ctOut)

	// Step 4: DecodePublic (noise sanitization for IND-CPAD security)
	encoder := ckks.NewEncoder(params)
	pt := ckks.NewPlaintext(params, ctOut.Level())
	pt.Value = ctOut.Value[0]
	pt.MetaData = ctOut.MetaData

	values := make([]float64, params.MaxSlots())
	if err := encoder.DecodePublic(pt, values, 32); err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}

	numSlots := input.NumSlots
	if numSlots <= 0 {
		return &MHEFuseOutput{Value: values[0]}, nil
	}

	sum := 0.0
	slotValues := make([]float64, numSlots)
	for i := 0; i < numSlots && i < len(values); i++ {
		slotValues[i] = values[i]
		sum += values[i]
	}

	return &MHEFuseOutput{
		Value:  sum,
		Values: slotValues,
	}, nil
}
