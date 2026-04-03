package main

// MPC operations for K=2 binomial/Poisson GLMs.
// These are stateless commands called via the same JSON stdin/stdout pattern
// as all other mhe-tool commands. The client orchestrates the MPC protocol
// by relaying transport-encrypted shares between servers.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// ============================================================================
// Command: mpc-split-eta
// Party splits its eta_k = X_k * beta_k into additive shares.
// Own share is stored locally; peer's share is transport-encrypted.
// ============================================================================

type MpcSplitEtaInput struct {
	Eta         []float64 `json:"eta"`          // eta_k = X_k * beta_k (plaintext)
	PeerPK      string    `json:"peer_pk"`      // peer's transport public key (base64)
	FracBits    int       `json:"frac_bits"`    // fixed-point fractional bits
}

type MpcSplitEtaOutput struct {
	OwnShare      string `json:"own_share"`       // base64, this party's share (stored locally)
	PeerShareEnc  string `json:"peer_share_enc"`  // base64, peer's share transport-encrypted
}

func handleMpcSplitEta() {
	var input MpcSplitEtaInput
	mpcReadInput(&input)

	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	n := len(input.Eta)
	etaFP := FloatVecToFP(input.Eta, input.FracBits)

	// Split into additive shares
	ownShares := make([]FixedPoint, n)
	peerShares := make([]FixedPoint, n)
	buf := make([]byte, n*8)
	if _, err := rand.Read(buf); err != nil {
		outputError(fmt.Sprintf("crypto/rand failed: %v", err))
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		ownShares[i] = FixedPoint(binary.LittleEndian.Uint64(buf[i*8 : (i+1)*8]))
		peerShares[i] = etaFP[i] - ownShares[i]
	}

	// Encode own share as base64 (int64 array → binary → base64)
	ownBytes := fpVecToBytes(ownShares)
	ownB64 := bytesToBase64(ownBytes)

	// Transport-encrypt peer's share under their PK
	peerBytes := fpVecToBytes(peerShares)
	peerPKBytes := base64ToBytes(input.PeerPK)

	sealed, err := transportEncryptRaw(peerBytes, peerPKBytes)
	if err != nil {
		outputError(fmt.Sprintf("transport encrypt failed: %v", err))
		os.Exit(1)
	}

	mpcWriteOutput(MpcSplitEtaOutput{
		OwnShare:     ownB64,
		PeerShareEnc: bytesToBase64(sealed),
	})
}

// ============================================================================
// Command: mpc-link-eval
// Evaluates the inverse link function (sigmoid or exp) on eta_total.
// Both parties' shares are combined, piecewise polynomial applied, then
// result is split into new shares.
// ============================================================================

type MpcLinkEvalInput struct {
	OwnEtaShare  string `json:"own_eta_share"`  // base64, own share of eta_k
	PeerEtaShare string `json:"peer_eta_share"` // base64, decrypted peer's share of eta_k
	Family       string `json:"family"`         // "binomial" or "poisson"
	FracBits     int    `json:"frac_bits"`
	PeerPK       string `json:"peer_pk"`        // peer's transport PK for output shares
}

type MpcLinkEvalOutput struct {
	OwnMuShare      string    `json:"own_mu_share"`       // base64, own share of mu
	PeerMuShareEnc  string    `json:"peer_mu_share_enc"`  // base64, peer's mu share (transport-encrypted)
	Weights         []float64 `json:"weights"`            // IRLS weights mu*(1-mu) for binomial
}

func handleMpcLinkEval() {
	var input MpcLinkEvalInput
	mpcReadInput(&input)

	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	// Decode shares
	ownEta := bytesToFPVec(base64ToBytes(input.OwnEtaShare))
	peerEta := bytesToFPVec(base64ToBytes(input.PeerEtaShare))
	n := len(ownEta)

	// Reconstruct eta_total = own + peer
	etaTotal := ReconstructVec(ownEta, peerEta)

	// Evaluate piecewise link function
	var intervals []PiecewiseInterval
	var clampLow, clampHigh float64
	switch input.Family {
	case "binomial":
		intervals = SigmoidIntervals()
		clampLow = 0.0
		clampHigh = 1.0
	case "poisson":
		intervals = ExpIntervals()
		clampLow = math.Exp(-3.0)
		clampHigh = math.Exp(3.0)
	default:
		outputError(fmt.Sprintf("unsupported family: %s", input.Family))
		os.Exit(1)
	}

	mu := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		etaVal := etaTotal[i].ToFloat64(input.FracBits)
		if input.Family == "poisson" {
			// Clip for Poisson
			if etaVal < -3.0 {
				etaVal = -3.0
			} else if etaVal > 3.0 {
				etaVal = 3.0
			}
		}
		muVal := EvalPiecewise(etaVal, intervals, clampLow, clampHigh)
		mu[i] = FromFloat64(muVal, input.FracBits)
	}

	// Compute IRLS weights: w = mu*(1-mu) for binomial, w = mu for Poisson
	weights := make([]float64, n)
	for i := 0; i < n; i++ {
		muVal := mu[i].ToFloat64(input.FracBits)
		switch input.Family {
		case "binomial":
			weights[i] = muVal * (1 - muVal)
			if weights[i] < 1e-10 {
				weights[i] = 1e-10 // prevent division by zero
			}
		case "poisson":
			weights[i] = muVal
			if weights[i] < 1e-10 {
				weights[i] = 1e-10
			}
		}
	}

	// Split mu into shares for both parties
	ownMu, peerMu := SplitVec(mu)

	// Encode own share
	ownB64 := bytesToBase64(fpVecToBytes(ownMu))

	// Transport-encrypt peer's share
	peerBytes := fpVecToBytes(peerMu)
	peerPKBytes := base64ToBytes(input.PeerPK)
	sealed, err := transportEncryptRaw(peerBytes, peerPKBytes)
	if err != nil {
		outputError(fmt.Sprintf("transport encrypt failed: %v", err))
		os.Exit(1)
	}

	mpcWriteOutput(MpcLinkEvalOutput{
		OwnMuShare:     ownB64,
		PeerMuShareEnc: bytesToBase64(sealed),
		Weights:        weights,
	})
}

// ============================================================================
// Command: mpc-gradient
// Compute gradient share: g_k = X_k^T * residual_share
// X_k is plaintext (this party's features), residual is secret-shared.
// This is a LOCAL operation — no communication needed.
// ============================================================================

type MpcGradientInput struct {
	X              [][]float64 `json:"x"`               // feature matrix (n x p_k)
	ResidualShare  string      `json:"residual_share"`  // base64, this party's share of (mu - y)
	FracBits       int         `json:"frac_bits"`
	NObs           int         `json:"n_obs"`
}

type MpcGradientOutput struct {
	GradientShare string `json:"gradient_share"` // base64, share of X^T * residual
}

func handleMpcGradient() {
	var input MpcGradientInput
	mpcReadInput(&input)

	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	n := len(input.X)
	p := len(input.X[0])

	// Convert X to fixed-point
	XFP := make([][]FixedPoint, n)
	for i := 0; i < n; i++ {
		XFP[i] = FloatVecToFP(input.X[i], input.FracBits)
	}

	// Decode residual share
	residualShare := bytesToFPVec(base64ToBytes(input.ResidualShare))

	// Compute gradient share: g_share = X^T * residual_share
	// This is plaintext × share = share (no Beaver triples needed)
	gradShare := make([]FixedPoint, p)
	for j := 0; j < p; j++ {
		var sum FixedPoint
		for i := 0; i < n; i++ {
			sum = FPAdd(sum, FPMulLocal(XFP[i][j], residualShare[i], input.FracBits))
		}
		gradShare[j] = sum
	}

	mpcWriteOutput(MpcGradientOutput{
		GradientShare: bytesToBase64(fpVecToBytes(gradShare)),
	})
}

// ============================================================================
// Command: mpc-residual
// Compute residual share: r_share = mu_share - y_share
// Label party subtracts y from its mu share; nonlabel just passes mu share.
// ============================================================================

type MpcResidualInput struct {
	MuShare  string    `json:"mu_share"`  // base64, this party's share of mu
	Y        []float64 `json:"y"`         // response vector (label party only, empty for nonlabel)
	Role     string    `json:"role"`      // "label" or "nonlabel"
	FracBits int       `json:"frac_bits"`
}

type MpcResidualOutput struct {
	ResidualShare string `json:"residual_share"` // base64, share of (mu - y)
}

func handleMpcResidual() {
	var input MpcResidualInput
	mpcReadInput(&input)

	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	muShare := bytesToFPVec(base64ToBytes(input.MuShare))

	if input.Role == "label" && len(input.Y) > 0 {
		// Label party: compute y - mu (not mu - y) to match HE gradient convention
		// HE gradient is X^T(Enc(y) - Enc(mu)), so MPC must match: residual = y - mu
		yFP := FloatVecToFP(input.Y, input.FracBits)
		for i := range muShare {
			muShare[i] = FPSub(yFP[i], muShare[i])
		}
	} else {
		// Nonlabel: negate mu_share (since residual = y - mu = -mu for nonlabel's share)
		for i := range muShare {
			muShare[i] = FPNeg(muShare[i])
		}
	}

	mpcWriteOutput(MpcResidualOutput{
		ResidualShare: bytesToBase64(fpVecToBytes(muShare)),
	})
}

// ============================================================================
// Command: mpc-reveal-gradient
// Reconstruct OWN gradient from own share + peer's transport-encrypted share.
// Each party gets ONLY its own gradient (not the peer's).
// ============================================================================

type MpcRevealGradientInput struct {
	OwnGradientShare  string `json:"own_gradient_share"`   // base64, own share
	PeerGradientShare string `json:"peer_gradient_share"`  // base64, peer's share (transport-decrypted)
	NObs              int    `json:"n_obs"`
	FracBits          int    `json:"frac_bits"`
}

type MpcRevealGradientOutput struct {
	Gradient []float64 `json:"gradient"` // reconstructed gradient (float64)
}

func handleMpcRevealGradient() {
	var input MpcRevealGradientInput
	mpcReadInput(&input)

	if input.FracBits <= 0 {
		input.FracBits = 20
	}

	ownShare := bytesToFPVec(base64ToBytes(input.OwnGradientShare))
	peerShare := bytesToFPVec(base64ToBytes(input.PeerGradientShare))

	gradient := ReconstructVec(ownShare, peerShare)
	gradFloat := FPVecToFloat(gradient, input.FracBits)

	mpcWriteOutput(MpcRevealGradientOutput{
		Gradient: gradFloat,
	})
}

// ============================================================================
// Helpers: binary encoding of FixedPoint vectors
// ============================================================================

func fpVecToBytes(v []FixedPoint) []byte {
	buf := make([]byte, len(v)*8)
	for i, fp := range v {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], uint64(fp))
	}
	return buf
}

func bytesToFPVec(buf []byte) []FixedPoint {
	n := len(buf) / 8
	v := make([]FixedPoint, n)
	for i := 0; i < n; i++ {
		v[i] = FixedPoint(binary.LittleEndian.Uint64(buf[i*8 : (i+1)*8]))
	}
	return v
}

// ============================================================================
// Helpers: JSON I/O (same pattern as existing mhe-tool commands)
// ============================================================================

func mpcReadInput(v interface{}) {
	inputBytes, err := readInput()
	if err != nil {
		outputError(fmt.Sprintf("failed to read input: %v", err))
		os.Exit(1)
	}
	if err := json.Unmarshal(inputBytes, v); err != nil {
		outputError(fmt.Sprintf("failed to parse input: %v", err))
		os.Exit(1)
	}
}

func mpcWriteOutput(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.Encode(v)
}

// bytesToBase64 and base64ToBytes using standard base64
func bytesToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func base64ToBytes(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return data
}

// transportEncryptRaw wraps the existing transportEncryptBytes from transport_ops.go
func transportEncryptRaw(data, recipientPK []byte) ([]byte, error) {
	return transportEncryptBytes(data, recipientPK)
}
