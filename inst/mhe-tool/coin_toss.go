// coin_toss.go: Distributed coin-tossing for CRP generation
//
// Replaces Party 0's unilateral CRP generation with a commit-reveal protocol
// where ALL servers contribute randomness. No single server or the client
// can predict or control the CKKS key setup seed.
//
// Protocol:
//   1. Each server generates r_k (32 bytes), commits H(r_k) = SHA-256(r_k)
//   2. After all commitments collected, each server reveals r_k
//   3. Shared seed = SHA-256(r_0 || r_1 || ... || r_{K-1})
//   4. PKG CRP = PKG.SampleCRP(NewKeyedPRNG(seed))
//   5. GKG seed = HMAC-SHA256(seed, "gkg_seed")
//
// Security: no single party can predict or control the CRP seed because
// each party commits to their contribution before seeing others' reveals.
// The commit-reveal prevents adaptive selection of contributions.

package main

import (
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// ============================================================================
// mhe-coin-toss-commit: Generate random contribution + SHA-256 commitment
// ============================================================================

type CoinTossCommitOutput struct {
	Contribution string `json:"contribution"` // Base64: 32-byte random r_k
	Commitment   string `json:"commitment"`   // Base64: SHA-256(r_k)
}

func mheCoinTossCommit() (*CoinTossCommitOutput, error) {
	rk := make([]byte, 32)
	if _, err := crand.Read(rk); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	hash := sha256.Sum256(rk)
	return &CoinTossCommitOutput{
		Contribution: base64.StdEncoding.EncodeToString(rk),
		Commitment:   base64.StdEncoding.EncodeToString(hash[:]),
	}, nil
}

// ============================================================================
// mhe-coin-toss-derive-crp: Verify commitments, derive CRP + GKG seed
// ============================================================================

type CoinTossDeriveCRPInput struct {
	Contributions []string `json:"contributions"` // Base64: [r_0, ..., r_{K-1}]
	Commitments   []string `json:"commitments"`   // Base64: [H(r_0), ..., H(r_{K-1})]
	LogN          int      `json:"log_n"`
	LogScale      int      `json:"log_scale"`
}

type CoinTossDeriveCRPOutput struct {
	CRP     string `json:"crp"`      // Base64: serialized PKG CRP
	GKGSeed string `json:"gkg_seed"` // Base64: 32-byte derived GKG seed
}

func mheCoinTossDeriveCRP(input *CoinTossDeriveCRPInput) (*CoinTossDeriveCRPOutput, error) {
	K := len(input.Contributions)
	if K != len(input.Commitments) {
		return nil, fmt.Errorf("contribution count (%d) != commitment count (%d)",
			K, len(input.Commitments))
	}
	if K < 2 {
		return nil, fmt.Errorf("coin-tossing requires at least 2 parties (got %d)", K)
	}

	// Verify commitments and concatenate contributions
	allContribs := make([]byte, 0, 32*K)
	for i := 0; i < K; i++ {
		contrib, err := base64.StdEncoding.DecodeString(input.Contributions[i])
		if err != nil {
			return nil, fmt.Errorf("failed to decode contribution %d: %v", i, err)
		}
		if len(contrib) != 32 {
			return nil, fmt.Errorf("contribution %d wrong length: %d (expected 32)", i, len(contrib))
		}

		commitment, err := base64.StdEncoding.DecodeString(input.Commitments[i])
		if err != nil {
			return nil, fmt.Errorf("failed to decode commitment %d: %v", i, err)
		}

		hash := sha256.Sum256(contrib)
		if !bytes.Equal(hash[:], commitment) {
			return nil, fmt.Errorf("commitment FAILED for party %d: randomness manipulation detected", i)
		}

		allContribs = append(allContribs, contrib...)
	}

	// Shared seed = SHA-256(r_0 || r_1 || ... || r_{K-1})
	sharedSeed := sha256.Sum256(allContribs)

	// PKG CRP from shared seed
	params, err := getParams(input.LogN, input.LogScale)
	if err != nil {
		return nil, err
	}

	prng, err := sampling.NewKeyedPRNG(sharedSeed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create keyed PRNG: %v", err)
	}

	pkg := multiparty.NewPublicKeyGenProtocol(params)
	crp := pkg.SampleCRP(prng)

	crpBytes, err := crp.Value.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CRP: %v", err)
	}

	// GKG seed = HMAC-SHA256(sharedSeed, "gkg_seed")
	mac := hmac.New(sha256.New, sharedSeed[:])
	mac.Write([]byte("gkg_seed"))
	gkgSeed := mac.Sum(nil)

	return &CoinTossDeriveCRPOutput{
		CRP:     base64.StdEncoding.EncodeToString(crpBytes),
		GKGSeed: base64.StdEncoding.EncodeToString(gkgSeed),
	}, nil
}
