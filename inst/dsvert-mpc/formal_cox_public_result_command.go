package main

// Read-only command for a completed formal-Cox sticky opening.  It validates
// the full two-authority certificate before projecting ordinary public model
// numbers.  It never opens a Rock path, receives a share, or starts source or
// MPC work.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
)

const (
	formalCoxPublicResultVersion    = "dsvert-formal-cox-public-result-v1"
	formalCoxPublicResultCommandMax = 16 << 20
)

type formalCoxPublicResultRequestV1 struct {
	CertificateJSON string            `json:"certificate_json"`
	Pins            map[string]string `json:"pins"`
}

type formalCoxPublicResultCoefficientV1 struct {
	Index               int     `json:"index"`
	BetaSteps           string  `json:"beta_steps"`
	FractionBits        int     `json:"fraction_bits"`
	Beta                float64 `json:"beta"`
	HazardRatioLower    float64 `json:"hazard_ratio_lower"`
	HazardRatioUpper    float64 `json:"hazard_ratio_upper"`
	HazardRatioMidpoint float64 `json:"hazard_ratio_midpoint"`
}

type formalCoxPublicResultResponseV1 struct {
	Version           string                               `json:"version"`
	ArtifactID        string                               `json:"artifact_id"`
	CertificateSHA256 string                               `json:"certificate_sha256"`
	Valid             bool                                 `json:"valid"`
	Coefficients      []formalCoxPublicResultCoefficientV1 `json:"coefficients"`
	ProductionReady   bool                                 `json:"production_ready"`
}

func formalCoxPublicResultDecodeStrictV1(encoded []byte, output any) error {
	if len(encoded) < 2 || len(encoded) > formalCoxPublicResultCommandMax ||
		encoded[0] != '{' {
		return fmt.Errorf("formal-cox public result: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("formal-cox public result: invalid command")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-cox public result: trailing command")
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-cox public result: non-canonical command")
	}
	return nil
}

func formalCoxPublicResultDecodePinsV1(
	values map[string]string,
) (map[string]ed25519.PublicKey, error) {
	if len(values) < 2 || len(values) > formalCoxPhase1MaxCustodians {
		return nil, fmt.Errorf("formal-cox public result: invalid pinset")
	}
	pins := make(map[string]ed25519.PublicKey, len(values))
	seen := make(map[string]bool, len(values))
	for peer, encoded := range values {
		if !formalCoxCompilerRLabel(peer) || seen[encoded] {
			return nil, fmt.Errorf("formal-cox public result: invalid pinset")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			clear(decoded)
			return nil, fmt.Errorf("formal-cox public result: invalid pinset")
		}
		seen[encoded] = true
		pins[peer] = ed25519.PublicKey(decoded)
	}
	return pins, nil
}

func formalCoxPublicResultClearPinsV1(pins map[string]ed25519.PublicKey) {
	for peer, pin := range pins {
		clear(pin)
		delete(pins, peer)
	}
}

func formalCoxPublicResultFloat64V1(value string) (float64, error) {
	rational, ok := new(big.Rat).SetString(value)
	if !ok || rational.RatString() != value {
		return 0, fmt.Errorf("formal-cox public result: invalid rational")
	}
	result, _ := new(big.Float).SetPrec(256).SetRat(rational).Float64()
	if math.IsNaN(result) || math.IsInf(result, 0) {
		return 0, fmt.Errorf("formal-cox public result: non-finite public value")
	}
	return result, nil
}

func formalCoxPublicResultEqualV1(
	left, right formalCoxPublicResultResponseV1,
) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// formalCoxPublicResultFromCertificateV1 is the one public projection used by
// both the read-only registry command and a completed fresh finalizer.  Its
// caller must already have authenticated the certificate against its pinned
// authority set; this function deliberately accepts no Rock location, source
// input, or opening material.
func formalCoxPublicResultFromCertificateV1(
	certificate formalCoxBlockwiseOpeningCertificate,
	certificateSHA256 string,
) (formalCoxPublicResultResponseV1, error) {
	var zero formalCoxPublicResultResponseV1
	if !certificate.Candidate.Valid ||
		!formalCoxIsSHA256(certificate.Candidate.ArtifactID) ||
		!formalCoxIsSHA256(certificateSHA256) {
		return zero, fmt.Errorf("formal-cox public result: invalid public release")
	}
	coefficients := make([]formalCoxPublicResultCoefficientV1,
		len(certificate.Candidate.Coefficients))
	for index, coefficient := range certificate.Candidate.Coefficients {
		beta, betaErr := formalCoxPublicResultFloat64V1(coefficient.BetaRational)
		lower, lowerErr := formalCoxPublicResultFloat64V1(
			coefficient.HazardRatioLowerRational)
		upper, upperErr := formalCoxPublicResultFloat64V1(
			coefficient.HazardRatioUpperRational)
		midpoint, midpointErr := formalCoxPublicResultFloat64V1(
			coefficient.HazardRatioMidpointRational)
		if betaErr != nil || lowerErr != nil || upperErr != nil ||
			midpointErr != nil || lower <= 0 || upper < lower ||
			midpoint < lower || midpoint > upper {
			return zero, fmt.Errorf("formal-cox public result: invalid public coefficient")
		}
		coefficients[index] = formalCoxPublicResultCoefficientV1{
			Index: index, BetaSteps: coefficient.BetaSteps,
			FractionBits: certificate.Candidate.FractionBits, Beta: beta,
			HazardRatioLower: lower, HazardRatioUpper: upper,
			HazardRatioMidpoint: midpoint,
		}
	}
	return formalCoxPublicResultResponseV1{
		Version:           formalCoxPublicResultVersion,
		ArtifactID:        certificate.Candidate.ArtifactID,
		CertificateSHA256: certificateSHA256, Valid: true,
		Coefficients: coefficients, ProductionReady: false,
	}, nil
}

func formalCoxRunPublicResultV1(encoded []byte) (formalCoxPublicResultResponseV1, error) {
	var zero formalCoxPublicResultResponseV1
	var request formalCoxPublicResultRequestV1
	if err := formalCoxPublicResultDecodeStrictV1(encoded, &request); err != nil ||
		len(request.CertificateJSON) < 2 ||
		len(request.CertificateJSON) > formalCoxPublicResultCommandMax {
		return zero, fmt.Errorf("formal-cox public result: invalid request")
	}
	pins, err := formalCoxPublicResultDecodePinsV1(request.Pins)
	if err != nil {
		return zero, err
	}
	defer formalCoxPublicResultClearPinsV1(pins)
	var certificate formalCoxBlockwiseOpeningCertificate
	if err := formalCoxPublicResultDecodeStrictV1(
		[]byte(request.CertificateJSON), &certificate); err != nil ||
		formalCoxBlockwiseValidateOpeningCertificate(certificate, pins) != nil ||
		!certificate.Candidate.Valid {
		return zero, fmt.Errorf("formal-cox public result: invalid public release")
	}
	certificateSHA256 := formalCoxBlockwiseOpeningCertificateSHA256(
		[]byte(request.CertificateJSON))
	return formalCoxPublicResultFromCertificateV1(certificate, certificateSHA256)
}

func handleFormalCoxPublicResultV1() {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalCoxPublicResultCommandMax)+1))
	if err != nil || len(encoded) > formalCoxPublicResultCommandMax {
		mpcFatalError("formal-cox public result failed")
	}
	defer clear(encoded)
	result, err := formalCoxRunPublicResultV1(encoded)
	if err != nil {
		mpcFatalError("formal-cox public result failed")
	}
	output(result)
}
