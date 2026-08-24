package main

// Read a completed Phase21 public terminal from the custodian-owned Rock
// state.  The analyst can select only a server provisioned analysis; this
// command deliberately accepts no path, seed, action, or private output.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const formalGLMPhase21PublicTerminalCommandMaxJSON = 16 << 20

type formalGLMPhase21PublicTerminalRequestV1 struct {
	AuthorityPeer  string            `json:"authority_peer"`
	ContractJSON   string            `json:"contract_json"`
	ResolutionJSON string            `json:"resolution_json"`
	Pins           map[string]string `json:"pins"`
}

func formalGLMRunPhase21PublicTerminalAtRootV1(
	encoded []byte, stateRoot string,
) (formalGLMPublicResultResponseV1, error) {
	var zero formalGLMPublicResultResponseV1
	var request formalGLMPhase21PublicTerminalRequestV1
	if err := formalGLMPublicResultDecodeStrictV1(encoded, &request); err != nil ||
		!formalFinalizerHandoffPathSafePeerName(request.AuthorityPeer) ||
		len(request.ContractJSON) < 2 ||
		len(request.ContractJSON) > formalGLMPhase21PublicTerminalCommandMaxJSON ||
		len(request.ResolutionJSON) < 2 ||
		len(request.ResolutionJSON) > formalGLMPhase21PublicTerminalCommandMaxJSON {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: invalid request")
	}
	pins, err := formalGLMPublicModelDecodePinsV1(request.Pins)
	if err != nil {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: invalid pinset")
	}
	defer formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	var contract formalGLMPhase21SamplerV2Contract
	var resolution formalGLMArtifactRegistryResolutionV1
	if formalGLMPublicResultDecodeStrictV1(
		[]byte(request.ContractJSON), &contract) != nil ||
		formalGLMPublicResultDecodeStrictV1(
			[]byte(request.ResolutionJSON), &resolution) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, pins) != nil ||
		resolution.ArtifactID != contract.ArtifactID ||
		formalGLMValidatePublicDescriptorAgainstArtifactV1(
			resolution.Descriptor, contract.Artifact) != nil {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: invalid durable context")
	}
	if _, err := formalGLMPhase21RockAuthority(
		contract.Artifact, request.AuthorityPeer); err != nil {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: invalid authority")
	}
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: invalid state root")
	}
	root := filepath.Join(stateRoot, request.AuthorityPeer)
	driver, err := newFormalGLMPublicPhase21TerminalDriverV1(root, contract, pins)
	if err != nil {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: unavailable")
	}
	defer driver.Close()
	observation, err := driver.AdvanceV1(formalGLMPublicAdvanceContextV1{
		Resolution: resolution,
	})
	if err != nil || observation.Failed || observation.Terminal == nil {
		return zero, fmt.Errorf("formal-glm Phase21 public terminal: unavailable")
	}
	return formalGLMPublicResultFromCertificateV1(
		observation.Terminal.Publication, pins)
}

func formalGLMRunPhase21PublicTerminalV1(
	encoded []byte,
) (formalGLMPublicResultResponseV1, error) {
	return formalGLMRunPhase21PublicTerminalAtRootV1(
		encoded, formalFinalizerHandoffStateRoot)
}

func handleFormalGLMPhase21PublicTerminalV1() {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, int64(formalGLMPhase21PublicTerminalCommandMaxJSON)+1))
	if err != nil || len(encoded) > formalGLMPhase21PublicTerminalCommandMaxJSON {
		mpcFatalError("formal-glm Phase21 public terminal failed")
	}
	defer clear(encoded)
	response, err := formalGLMRunPhase21PublicTerminalV1(encoded)
	if err != nil {
		mpcFatalError("formal-glm Phase21 public terminal failed")
	}
	output(response)
}
