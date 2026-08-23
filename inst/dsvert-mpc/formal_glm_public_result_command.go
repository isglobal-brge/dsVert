package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
)

const (
	formalGLMPublicResultVersion        = "dsvert-formal-glm-public-result-v1"
	formalGLMPublicResultCommandMaxJSON = 16 << 20
)

// formalGLMPublicResultRequestV1 contains only a completed public release and
// the server-owned pinset used to verify it.  It cannot request source work,
// select a privacy mechanism, or name a Rock path.
type formalGLMPublicResultRequestV1 struct {
	CertificateJSON string            `json:"certificate_json"`
	Pins            map[string]string `json:"pins"`
}

type formalGLMPublicResultCoefficientV1 struct {
	Coefficient       string  `json:"coefficient"`
	SignedSteps       string  `json:"signed_steps"`
	OutputLatticeBits int     `json:"output_lattice_bits"`
	Value             float64 `json:"value"`
}

type formalGLMPublicResultResponseV1 struct {
	Version           string                               `json:"version"`
	ArtifactID        string                               `json:"artifact_id"`
	CertificateSHA256 string                               `json:"certificate_sha256"`
	Family            string                               `json:"family"`
	FormulaSHA256     string                               `json:"formula_sha256"`
	Coefficients      []formalGLMPublicResultCoefficientV1 `json:"coefficients"`
	ProductionReady   bool                                 `json:"production_ready"`
}

func formalGLMPublicResultDecodeStrictV1(encoded []byte, output any) error {
	if len(encoded) < 2 || len(encoded) > formalGLMPublicResultCommandMaxJSON ||
		encoded[0] != '{' {
		return fmt.Errorf("formal-glm public result: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("formal-glm public result: invalid command")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("formal-glm public result: trailing command")
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("formal-glm public result: non-canonical command")
	}
	return nil
}

func formalGLMPublicResultFloat64V1(steps string, latticeBits int) (float64, error) {
	if latticeBits < 0 || latticeBits > 127 {
		return 0, fmt.Errorf("formal-glm public result: invalid lattice")
	}
	integer, ok := new(big.Int).SetString(steps, 10)
	if !ok || integer.String() != steps {
		return 0, fmt.Errorf("formal-glm public result: invalid coordinate")
	}
	value, _ := new(big.Float).SetPrec(256).SetMantExp(
		new(big.Float).SetPrec(256).SetInt(integer), -latticeBits).Float64()
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("formal-glm public result: non-finite coefficient")
	}
	return value, nil
}

func formalGLMRunPublicResultV1(encoded []byte) (formalGLMPublicResultResponseV1, error) {
	var zero formalGLMPublicResultResponseV1
	var request formalGLMPublicResultRequestV1
	if err := formalGLMPublicResultDecodeStrictV1(encoded, &request); err != nil ||
		len(request.CertificateJSON) < 2 || len(request.CertificateJSON) > formalGLMPublicResultCommandMaxJSON {
		return zero, fmt.Errorf("formal-glm public result: invalid request")
	}
	pins, err := formalGLMPublicModelDecodePinsV1(request.Pins)
	if err != nil {
		return zero, fmt.Errorf("formal-glm public result: invalid pinset")
	}
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	var certificate formalGLMPhase21PublicCertificateV2
	if err := formalGLMPublicResultDecodeStrictV1(
		[]byte(request.CertificateJSON), &certificate); err != nil ||
		formalGLMPhase21ValidatePublicCertificateV2(certificate, pins) != nil ||
		certificate.PublicDescriptor == nil {
		return zero, fmt.Errorf("formal-glm public result: invalid public release")
	}
	digest, err := formalGLMPhase21RockPublicCertificateDigest(certificate)
	if err != nil {
		return zero, fmt.Errorf("formal-glm public result: invalid certificate")
	}
	named, err := formalGLMPhase21DecodeNamedPublicV2(certificate, pins)
	if err != nil {
		return zero, fmt.Errorf("formal-glm public result: invalid named release")
	}
	coefficients := make([]formalGLMPublicResultCoefficientV1, len(named))
	for index, coefficient := range named {
		value, valueErr := formalGLMPublicResultFloat64V1(
			coefficient.SignedSteps, coefficient.OutputLatticeBits)
		if valueErr != nil {
			return zero, valueErr
		}
		coefficients[index] = formalGLMPublicResultCoefficientV1{
			Coefficient: coefficient.Coefficient, SignedSteps: coefficient.SignedSteps,
			OutputLatticeBits: coefficient.OutputLatticeBits, Value: value,
		}
	}
	descriptor := certificate.PublicDescriptor.Descriptor
	if !formalGLMPublicSupportedFamilyV1(descriptor.Family) {
		return zero, fmt.Errorf("formal-glm public result: unsupported family")
	}
	return formalGLMPublicResultResponseV1{
		Version: formalGLMPublicResultVersion, ArtifactID: certificate.ArtifactID,
		CertificateSHA256: digest, Family: descriptor.Family,
		FormulaSHA256: descriptor.FormulaSHA256, Coefficients: coefficients,
		ProductionReady: false,
	}, nil
}

func handleFormalGLMPublicResultV1() {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalGLMPublicResultCommandMaxJSON)+1))
	if err != nil || len(encoded) > formalGLMPublicResultCommandMaxJSON {
		mpcFatalError("formal-glm public result failed")
	}
	defer clear(encoded)
	response, err := formalGLMRunPublicResultV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm public result failed")
	}
	output(response)
}
