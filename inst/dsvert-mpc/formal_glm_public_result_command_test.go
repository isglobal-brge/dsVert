package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"testing"
)

func formalGLMPublicResultTestCertificate(t testing.TB, custodians int,
	family string,
) (formalGLMPhase21PublicCertificateV2, map[string]string) {
	t.Helper()
	fixture := formalGLMPhase21SamplerV2TestSetup(
		t, custodians, formalGLMPhase21SamplerV2OneDraw)
	formalGLMRegistryDescriptorTestNormalizeArtifact(&fixture)
	core := formalGLMRegistryDescriptorTestCore(t, fixture)
	if family == "poisson" {
		fixture.artifact.Family = family
		core.Family = family
		for index := range core.UsedColumns {
			if core.UsedColumns[index].Role == "response" {
				core.UsedColumns[index].Kind = "count"
			}
		}
	}
	coreSHA256, err := formalGLMPublicDescriptorCoreSHA256V1(core)
	if err != nil {
		t.Fatal(err)
	}
	artifact := fixture.artifact
	artifact.DescriptorCoreSHA256 = coreSHA256
	artifactID, err := formalGLMPhase21StickyArtifactID(artifact)
	if err != nil {
		t.Fatal(err)
	}
	fixture.artifact, fixture.artifactID = artifact, artifactID
	fixture.contract = formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.pins, fixture.keys, fixture.roots)
	descriptor := formalGLMRegistryDescriptorTestSignedDescriptor(
		t, fixture, core, artifactID)
	internal := formalGLMPhase21SamplerV2TestUnsignedCertificate(t, fixture)
	internal.Artifact, internal.ArtifactID = artifact, artifactID
	internal.ClampedScaledValues = make([]string, len(core.ShiftedUpperBounds))
	for index, signed := range []int64{524288, -262144} {
		upper, ok := new(big.Int).SetString(core.ShiftedUpperBounds[index], 10)
		if !ok {
			t.Fatal("invalid test shifted upper bound")
		}
		value := new(big.Int).Rsh(upper, 1)
		value.Add(value, big.NewInt(signed))
		internal.ClampedScaledValues[index] = value.String()
	}
	vectorSHA256, err := jointDPBiomedicalGaussianOneDrawVectorSHA256(
		internal.ClampedScaledValues)
	if err != nil {
		t.Fatal(err)
	}
	internal.VectorSHA256 = vectorSHA256
	contract := formalGLMPhase21SamplerV2TestContractForArtifact(
		t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
		fixture.pins, fixture.keys, fixture.roots)
	internal.SamplerV2Contract = &contract
	promoted, err := formalGLMPhase21PromoteDurableV2(internal, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := formalGLMPhase21BuildRegisteredPublicCertificateV2(
		promoted, formalGLMArtifactRegistryResolutionV1{
			ArtifactID: artifactID, Descriptor: descriptor,
		}, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]jointDPBiomedicalGaussianSignature, 0, 2)
	for _, authority := range artifact.NoiseAuthorities {
		receipt, signErr := formalGLMPhase21SignPublicCertificateV2(
			certificate, authority.PeerName, fixture.keys[authority.PeerName],
			fixture.pins)
		if signErr != nil {
			t.Fatal(signErr)
		}
		receipts = append(receipts, receipt)
	}
	certificate, err = formalGLMPhase21SealPublicCertificateV2(
		certificate, receipts, fixture.pins)
	if err != nil {
		t.Fatal(err)
	}
	pins := make(map[string]string, len(fixture.pins))
	for peer, key := range fixture.pins {
		pins[peer] = base64.RawURLEncoding.EncodeToString(key)
	}
	return certificate, pins
}

func TestFormalGLMPublicResultCommandK2K3K5(t *testing.T) {
	for _, testcase := range []struct {
		custodians int
		family     string
	}{
		{custodians: 2, family: "binomial"},
		{custodians: 2, family: "poisson"},
		{custodians: 3, family: "binomial"},
		{custodians: 5, family: "binomial"},
	} {
		t.Run(fmt.Sprintf("K%d/%s", testcase.custodians, testcase.family), func(t *testing.T) {
			certificate, pins := formalGLMPublicResultTestCertificate(
				t, testcase.custodians, testcase.family)
			certificateJSON, err := json.Marshal(certificate)
			if err != nil {
				t.Fatal(err)
			}
			requestJSON, err := json.Marshal(formalGLMPublicResultRequestV1{
				CertificateJSON: string(certificateJSON), Pins: pins,
			})
			if err != nil {
				t.Fatal(err)
			}
			response, err := formalGLMRunPublicResultV1(requestJSON)
			if err != nil || response.Version != formalGLMPublicResultVersion ||
				response.ArtifactID != certificate.ArtifactID ||
				response.Family != testcase.family ||
				response.FormulaSHA256 != certificate.PublicDescriptor.Descriptor.FormulaSHA256 ||
				response.ProductionReady ||
				len(response.Coefficients) != len(certificate.ClampedScaledValues) {
				t.Fatalf("public result: %+v / %v", response, err)
			}
			for index, coefficient := range response.Coefficients {
				if coefficient.Coefficient != certificate.PublicDescriptor.Descriptor.CoefficientOrder[index] ||
					coefficient.OutputLatticeBits != certificate.PublicDescriptor.Descriptor.OutputLatticeBits ||
					coefficient.SignedSteps != []string{"524288", "-262144"}[index] ||
					math.Abs(coefficient.Value-
						float64([]int{524288, -262144}[index])/float64(uint64(1)<<20)) > 1e-18 {
					t.Fatalf("invalid coefficient %d: %+v", index, coefficient)
				}
			}
			if _, err := formalGLMRunPublicResultV1(requestJSON); err != nil {
				t.Fatalf("exact public replay: %v", err)
			}
		})
	}
}

func TestFormalGLMPublicResultCommandRejectsTampering(t *testing.T) {
	certificate, pins := formalGLMPublicResultTestCertificate(t, 2, "binomial")
	certificateJSON, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	request := formalGLMPublicResultRequestV1{
		CertificateJSON: string(certificateJSON), Pins: pins,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRunPublicResultV1(append(encoded, '\n')); err == nil {
		t.Fatal("non-canonical request was accepted")
	}
	certificate.ClampedScaledValues[0] = "0"
	tamperedCertificate, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	request.CertificateJSON = string(tamperedCertificate)
	tampered, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalGLMRunPublicResultV1(tampered); err == nil {
		t.Fatal("tampered public release was accepted")
	}
}
