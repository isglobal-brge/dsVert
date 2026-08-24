package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func formalGLMRegisteredPhase21PublicationContextTestBuildV1(
	t testing.TB,
	fixture formalGLMSourceContractTestFixtureV1,
) formalGLMRegisteredPhase21PublicationContextV1 {
	t.Helper()
	unsigned := fixture.contract.Core.SamplerV2ContractCore
	signatures := make([]jointDPBiomedicalGaussianSignature, 0,
		len(unsigned.CustodianPeers))
	for _, peer := range unsigned.CustodianPeers {
		signature, err := formalGLMPhase21SignSamplerV2Contract(
			unsigned, peer, fixture.inputs.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	sampler, err := formalGLMPhase21SealSamplerV2Contract(
		unsigned, signatures, fixture.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string][32]byte, len(sampler.Artifact.NoiseAuthorities))
	for _, authority := range sampler.Artifact.NoiseAuthorities {
		roots[authority.PeerName] = sha256.Sum256([]byte(
			"registered-execution/authority-root/" + authority.PeerName))
	}
	context := formalGLMRegisteredPhase21PublicationContextV1{
		Version:                  formalGLMRegisteredPhase21PublicationContextVersionV1,
		Purpose:                  formalGLMRegisteredPhase21PublicationContextPurposeV1,
		SourceContractCoreSHA256: fixture.contract.CoreSHA256,
		SamplerContract:          sampler,
		RegistryResolution:       fixture.inputs.resolution,
		SamplerAuthorizations: formalGLMPhase21SamplerV2TestAuthorize(
			t, sampler, fixture.inputs.identities.public,
			fixture.inputs.identities.private, roots),
		ProductionReady: false,
	}
	return context
}

func TestFormalGLMRegisteredPhase21PublicationContextBindsSignedSampler(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			context := formalGLMRegisteredPhase21PublicationContextTestBuildV1(t, fixture)
			encoded, err := formalGLMRegisteredPhase21PublicationContextEncodeV1(
				context, fixture.contract, fixture.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encoded)
			decoded, err := formalGLMRegisteredPhase21PublicationContextDecodeV1(
				encoded, fixture.contract, fixture.inputs.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.SourceContractCoreSHA256 != fixture.contract.CoreSHA256 ||
				decoded.ProductionReady ||
				formalGLMPhase21ValidateSamplerV2Authorizations(
					decoded.SamplerContract, decoded.SamplerAuthorizations,
					fixture.inputs.identities.public) != nil {
				t.Fatalf("publication context did not preserve its signed binding: %+v", decoded)
			}

			tampered := append([]byte(nil), encoded...)
			for index := range tampered {
				if tampered[index] == 'a' {
					tampered[index] = 'b'
					break
				}
			}
			if _, err := formalGLMRegisteredPhase21PublicationContextDecodeV1(
				tampered, fixture.contract, fixture.inputs.identities.public); err == nil {
				t.Fatal("tampered publication context was accepted")
			}

			missingResolution := context
			missingResolution.RegistryResolution = formalGLMArtifactRegistryResolutionV1{}
			if _, err := formalGLMRegisteredPhase21PublicationContextEncodeV1(
				missingResolution, fixture.contract, fixture.inputs.identities.public); err == nil {
				t.Fatal("publication context accepted a missing registry resolution")
			}
		})
	}
}
