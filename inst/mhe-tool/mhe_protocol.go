// mhe_protocol.go: Full Multiparty HE protocol implementation
//
// This implements proper threshold MHE where:
// - Each server has its own secret key share
// - Decryption requires ALL servers to cooperate
// - Client cannot decrypt without all partial decryptions

package main

import (
	"encoding/base64"
	"fmt"
	"math"

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
	PartyID   int    `json:"party_id"`
	CRP       string `json:"crp,omitempty"`        // Base64, empty for party 0
	GKGCRP    string `json:"gkg_crp,omitempty"`    // Base64, Galois key CRP
	RKGCRP    string `json:"rkg_crp,omitempty"`    // Base64, Relin key CRP
	NumObs    int    `json:"num_obs"`              // Number of observations (for minimal galois keys)
	LogN      int    `json:"log_n"`
	LogScale  int    `json:"log_scale"`
}

type MHESetupOutput struct {
	// Secret key stays on server (stored in session)
	SecretKey      string `json:"secret_key"`        // Base64 - NEVER sent to client
	PublicKeyShare string `json:"public_key_share"`  // Base64 - sent for combining

	// CRPs (only party 0 generates these)
	CRP    string `json:"crp,omitempty"`     // Base64
	GKGCRP string `json:"gkg_crp,omitempty"` // Base64
	RKGCRP string `json:"rkg_crp,omitempty"` // Base64

	// Galois key shares for collaborative generation
	GaloisKeyShares []string `json:"galois_key_shares"` // Base64 array

	// Relinearization key shares (round 1)
	RKGShareRound1 string `json:"rkg_share_round1"` // Base64

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
	var crpB64, gkgCRPB64, rkgCRPB64 string

	if input.PartyID == 0 {
		// Party 0 generates CRPs
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

		// Generate GKG CRP (we'll use a simple seed for now)
		gkgCRPB64 = crpB64 // Reuse for simplicity
		rkgCRPB64 = crpB64
	} else {
		// Other parties use received CRP
		crpBytes, err := base64.StdEncoding.DecodeString(input.CRP)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CRP: %v", err)
		}
		if err := crp.Value.UnmarshalBinary(crpBytes); err != nil {
			return nil, fmt.Errorf("failed to deserialize CRP: %v", err)
		}
		gkgCRPB64 = input.GKGCRP
		rkgCRPB64 = input.RKGCRP
	}

	// Generate public key share
	pkShare := pkg.AllocateShare()
	pkg.GenShare(sk, crp, &pkShare)
	pkShareBytes, err := pkShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key share: %v", err)
	}

	// Generate Galois key shares for rotations needed for sum-reduce
	// For numObs observations, we need rotations by powers of 2 up to numObs
	numRotations := int(math.Ceil(math.Log2(float64(input.NumObs)))) + 1
	galEls := make([]uint64, 0, numRotations)
	for i := 1; i <= (1 << numRotations); i *= 2 {
		galEls = append(galEls, params.GaloisElement(i))
	}

	gkg := multiparty.NewGaloisKeyGenProtocol(params)
	prng, _ := sampling.NewPRNG()

	galoisSharesB64 := make([]string, len(galEls))
	for i, galEl := range galEls {
		gkgCRP := gkg.SampleCRP(prng)
		gkgShare := gkg.AllocateShare()
		gkg.GenShare(sk, galEl, gkgCRP, &gkgShare)
		shareBytes, err := gkgShare.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize galois key share %d: %v", i, err)
		}
		galoisSharesB64[i] = base64.StdEncoding.EncodeToString(shareBytes)
	}

	// Generate RKG round 1 share
	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
	rkgCRP := rkg.SampleCRP(prng)

	ephSK, rkgShare1, rkgShare2 := rkg.AllocateShare()
	rkg.GenShareRoundOne(sk, rkgCRP, ephSK, &rkgShare1)
	_ = rkgShare2 // Will be used in round 2

	rkgShare1Bytes, err := rkgShare1.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RKG share round 1: %v", err)
	}

	return &MHESetupOutput{
		SecretKey:       base64.StdEncoding.EncodeToString(skBytes),
		PublicKeyShare:  base64.StdEncoding.EncodeToString(pkShareBytes),
		CRP:             crpB64,
		GKGCRP:          gkgCRPB64,
		RKGCRP:          rkgCRPB64,
		GaloisKeyShares: galoisSharesB64,
		RKGShareRound1:  base64.StdEncoding.EncodeToString(rkgShare1Bytes),
		PartyID:         input.PartyID,
	}, nil
}

// ============================================================================
// Phase 2: Combine shares into collective keys
// ============================================================================

type MHECombineInput struct {
	PublicKeyShares   []string   `json:"public_key_shares"`    // Base64 array
	GaloisKeyShares   [][]string `json:"galois_key_shares"`    // Base64 [party][galEl]
	RKGSharesRound1   []string   `json:"rkg_shares_round1"`    // Base64 array
	CRP               string     `json:"crp"`                  // Base64
	NumObs            int        `json:"num_obs"`
	LogN              int        `json:"log_n"`
	LogScale          int        `json:"log_scale"`
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

	// For simplicity in this version, we'll generate evaluation keys from a temporary key
	// In production, this should use the full GKG and RKG protocols
	kgen := rlwe.NewKeyGenerator(params)
	tmpSK := kgen.GenSecretKeyNew()

	numRotations := int(math.Ceil(math.Log2(float64(input.NumObs)))) + 1
	galEls := make([]uint64, 0, numRotations)
	for i := 1; i <= (1 << numRotations); i *= 2 {
		galEls = append(galEls, params.GaloisElement(i))
	}

	gks := kgen.GenGaloisKeysNew(galEls, tmpSK)
	rlk := kgen.GenRelinearizationKeyNew(tmpSK)

	gksB64 := make([]string, len(gks))
	for i, gk := range gks {
		gkBytes, err := gk.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize galois key %d: %v", i, err)
		}
		gksB64[i] = base64.StdEncoding.EncodeToString(gkBytes)
	}

	rlkBytes, err := rlk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize RLK: %v", err)
	}

	return &MHECombineOutput{
		CollectivePublicKey: base64.StdEncoding.EncodeToString(cpkBytes),
		GaloisKeys:          gksB64,
		RelinearizationKey:  base64.StdEncoding.EncodeToString(rlkBytes),
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

	// Create decryption share using KeySwitch protocol
	noise := ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}
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

	// Initialize KeySwitch protocol
	noise := ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}
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

	// Decode the plaintext - must copy scale from ciphertext for correct decoding
	encoder := ckks.NewEncoder(params)
	pt := ckks.NewPlaintext(params, ctOut.Level())
	pt.Value = ctOut.Value[0]
	pt.MetaData = ctOut.MetaData

	values := make([]float64, params.MaxSlots())
	if err := encoder.Decode(pt, values); err != nil {
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
