package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFormalGLMRegisteredPhase21PublicationAssetsK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMSourceContractTestFixture(t, custodians)
			publication := formalGLMRegisteredPhase21PublicationContextTestBuildV1(t, fixture)
			peer := publication.SamplerContract.Artifact.NoiseAuthorities[0].PeerName
			stateRoot, rootErr := filepath.EvalSymlinks(t.TempDir())
			if rootErr != nil {
				t.Fatal(rootErr)
			}
			authorityRoot := filepath.Join(stateRoot, peer)
			if err := os.Mkdir(authorityRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			assets, replayed, err := formalGLMRegisteredPhase21PersistPublicationAssetsV1(
				authorityRoot, publication, fixture.contract,
				fixture.inputs.identities.public)
			if err != nil || replayed {
				t.Fatalf("first asset persistence: %+v / %v", assets, err)
			}
			if assets.stageReady || assets.capsulePath != "" || assets.requestPath != "" ||
				assets.backendSignaturesPath != "" || assets.workerSignaturesPath != "" ||
				assets.samplerAuthorizationsPath != "" {
				t.Fatal("incomplete preflight context acquired durable Stage inputs")
			}
			partial := publication
			partial.BackendSignatures = []jointDPBiomedicalGaussianSignature{{}}
			if _, _, partialErr := formalGLMRegisteredPhase21PersistPublicationAssetsV1(
				authorityRoot, partial, fixture.contract, fixture.inputs.identities.public); partialErr == nil {
				t.Fatal("partial Stage context was persisted")
			}
			encoded, marshalErr := json.Marshal(assets)
			if marshalErr != nil || string(encoded) != "{}" {
				t.Fatalf("asset handle exposed Rock paths: %q / %v", encoded, marshalErr)
			}
			for _, path := range []string{assets.contractPath, assets.pinsetPath, assets.resolutionPath} {
				info, statErr := os.Lstat(path)
				if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("unsafe durable Phase21 asset %q: %v / %#v", path, statErr, info)
				}
			}
			replay, replayed, replayErr := formalGLMRegisteredPhase21PersistPublicationAssetsV1(
				authorityRoot, publication, fixture.contract,
				fixture.inputs.identities.public)
			if replayErr != nil || !replayed || replay.contractPath != assets.contractPath ||
				replay.pinsetPath != assets.pinsetPath || replay.resolutionPath != assets.resolutionPath ||
				replay.stageReady || replay.capsulePath != "" || replay.requestPath != "" ||
				replay.backendSignaturesPath != "" || replay.workerSignaturesPath != "" ||
				replay.samplerAuthorizationsPath != "" {
				t.Fatalf("asset replay changed the Phase21 input: %+v / %v", replay, replayErr)
			}
			if err := os.WriteFile(assets.contractPath, []byte(`{"tampered":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := formalGLMRegisteredPhase21PersistPublicationAssetsV1(
				authorityRoot, publication, fixture.contract,
				fixture.inputs.identities.public); err == nil {
				t.Fatal("tampered Phase21 asset was accepted")
			}
		})
	}
}
