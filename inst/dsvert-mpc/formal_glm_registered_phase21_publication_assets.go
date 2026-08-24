package main

// The registered Phase20 host keeps the signed Phase21 context private until
// its Selected result exists.  These are the three signed, non-secret assets
// that the existing Phase21 lifecycle can then reopen from the local
// authority Rock root.  Stage-specific secrets and the selected DP share are
// deliberately not part of this projection.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21PublicationAssetsDirV1 = "formal-glm-registered-phase21-assets-v1"

// This handle has no JSON surface.  The paths are used only by the private
// host when it invokes the already-existing Phase21 action machine.
type formalGLMRegisteredPhase21PublicationAssetsV1 struct {
	contractPath   string
	pinsetPath     string
	resolutionPath string
}

func formalGLMRegisteredPhase21PublicationAssetsPathsV1(
	authorityRoot, artifactID string,
) (formalGLMRegisteredPhase21PublicationAssetsV1, error) {
	var zero formalGLMRegisteredPhase21PublicationAssetsV1
	if !formalGLMIsSHA256(artifactID) {
		return zero, fmt.Errorf("formal-glm registered Phase21 assets: invalid artifact")
	}
	base := filepath.Join(authorityRoot,
		formalGLMRegisteredPhase21PublicationAssetsDirV1, artifactID)
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return zero, fmt.Errorf("formal-glm registered Phase21 assets: invalid Rock root")
	}
	return formalGLMRegisteredPhase21PublicationAssetsV1{
		contractPath:   filepath.Join(base, "sampler-contract.json"),
		pinsetPath:     filepath.Join(base, "pinset.json"),
		resolutionPath: filepath.Join(base, "registry-resolution.json"),
	}, nil
}

// formalGLMRegisteredPhase21PersistPublicationAssetsV1 writes only canonical
// signed data.  A later invocation with identical data is a replay; any
// different bytes in the same artifact slot fail closed before Phase21 can
// sample or publish a result.
func formalGLMRegisteredPhase21PersistPublicationAssetsV1(
	authorityRoot string,
	publication formalGLMRegisteredPhase21PublicationContextV1,
	contract formalGLMSourceContractV1,
	pins map[string]ed25519.PublicKey,
) (formalGLMRegisteredPhase21PublicationAssetsV1, bool, error) {
	var zero formalGLMRegisteredPhase21PublicationAssetsV1
	if err := formalGLMRegisteredPhase21PublicationContextValidateV1(
		publication, contract, pins); err != nil {
		return zero, false, err
	}
	if err := formalFinalizerHandoffEnsurePrivateDir(authorityRoot); err != nil {
		return zero, false, err
	}
	assets, err := formalGLMRegisteredPhase21PublicationAssetsPathsV1(
		authorityRoot, publication.SamplerContract.ArtifactID)
	if err != nil {
		return zero, false, err
	}
	pinned := make(map[string]string, len(pins))
	for peer, pin := range pins {
		if len(pin) == 0 {
			return zero, false, fmt.Errorf("formal-glm registered Phase21 assets: invalid pinset")
		}
		pinned[peer] = base64.StdEncoding.EncodeToString(pin)
	}
	_, contractReplay, err := formalGLMPhase21RockWriteJSON(
		authorityRoot, assets.contractPath, publication.SamplerContract)
	if err != nil {
		return zero, false, err
	}
	_, pinsetReplay, err := formalGLMPhase21RockWriteJSON(
		authorityRoot, assets.pinsetPath, formalGLMPhase21RockPinset{
			Version:         formalGLMPhase21RockPinsetVersion,
			Family:          formalFinalizerHandoffFamilyGLM,
			Purpose:         formalGLMPhase21RockPurpose,
			PinnedPublicKey: pinned,
		})
	if err != nil {
		return zero, false, err
	}
	_, resolutionReplay, err := formalGLMPhase21RockWriteJSON(
		authorityRoot, assets.resolutionPath, publication.RegistryResolution)
	if err != nil {
		return zero, false, err
	}
	loaded, err := formalGLMPhase21RockLoadContext(
		authorityRoot, assets.contractPath, assets.pinsetPath)
	if err != nil || loaded.artifactID != publication.SamplerContract.ArtifactID ||
		loaded.contract.ArtifactID != publication.SamplerContract.ArtifactID {
		return zero, false, fmt.Errorf("formal-glm registered Phase21 assets: durable context mismatch")
	}
	resolution, err := formalGLMPhase21RockLoadRegistryResolution(
		authorityRoot, assets.resolutionPath, loaded)
	if err != nil || resolution.ArtifactID != publication.SamplerContract.ArtifactID {
		return zero, false, fmt.Errorf("formal-glm registered Phase21 assets: durable resolution mismatch")
	}
	for peer := range loaded.pins {
		clear(loaded.pins[peer])
		delete(loaded.pins, peer)
	}
	return assets, contractReplay && pinsetReplay && resolutionReplay, nil
}
