package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
)

const formalGLMRegisteredPhase21CommitSecretFileV1 = "registered-phase21-commit-secret.json"

func formalGLMRegisteredPhase21CommitInboxPathV1(root, artifactID, role string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !formalGLMIsSHA256(artifactID) || (role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm registered Phase21 commit: invalid inbox")
	}
	return filepath.Join(root, "inbox-v1", "commit-"+role+".json"), nil
}

func formalGLMRegisteredPhase21CommitPublicationV1(state formalGLMRegisteredPhase21StageHostStateV1, publication formalGLMPhase21PublicCertificateV2) (formalGLMPhase21RockCommitRecord, error) {
	var zero formalGLMPhase21RockCommitRecord
	context, _, _, _, local, _, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || formalGLMPhase21ValidatePublicCertificateV2(publication, context.pins) != nil || publication.ArtifactID != context.artifactID {
		return zero, fmt.Errorf("formal-glm registered Phase21 commit: invalid publication")
	}
	secretPath := filepath.Join(state.rockRoot, "commands-v1", formalGLMRegisteredPhase21CommitSecretFileV1)
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, secretPath, formalGLMPhase21RockCommitPublicationSecret{
		Version: formalGLMPhase21RockSecretVersion, Family: formalFinalizerHandoffFamilyGLM,
		Purpose: formalGLMPhase21RockPurpose, Action: formalGLMPhase21RockActionCommitPublication,
		StickyStorageRoot: base64.StdEncoding.EncodeToString(state.stickyRoot[:]), SigningPrivateKey: base64.StdEncoding.EncodeToString(state.signing),
	})
	if err != nil {
		return zero, err
	}
	operation, err := json.Marshal(formalGLMPhase21RockCommitPublicationOperation{
		ArtifactContractPath: state.operation.ArtifactContractPath, PinsetPath: state.operation.PinsetPath,
		PeerName: local.PeerName, Publication: publication, SecretBundlePath: secretPath,
	})
	if err != nil {
		return zero, err
	}
	defer clear(operation)
	response, err := formalGLMPhase21RockRun(state.rockRoot, false, formalGLMPhase21RockActionCommitPublication, operation)
	if err != nil || response.Commit == nil || response.State != formalGLMPhase21RockStatePublicationCommit || response.ArtifactID != context.artifactID || response.ProductionReady ||
		formalGLMPhase21RockValidateCommitRecord(*response.Commit, context, local) != nil {
		return zero, fmt.Errorf("formal-glm registered Phase21 commit: lifecycle failed")
	}
	encoded, err := json.Marshal(*response.Commit)
	if err != nil {
		return zero, err
	}
	defer clear(encoded)
	var cloned formalGLMPhase21RockCommitRecord
	if err := formalGLMPhase21RockStrictDecode(encoded, &cloned); err != nil {
		return zero, err
	}
	return cloned, nil
}

func formalGLMRegisteredPhase21ImportPeerCommitV1(state formalGLMRegisteredPhase21StageHostStateV1, record formalGLMPhase21RockCommitRecord) error {
	context, _, _, _, local, _, _, _, _, err := formalGLMRegisteredPhase21AuthorizationStateV1(state)
	if err != nil || record.Receipt.PeerName == local.PeerName {
		return fmt.Errorf("formal-glm registered Phase21 commit: invalid peer record")
	}
	peer, peerErr := formalGLMPhase21RockAuthority(context.contract.Artifact, record.Receipt.PeerName)
	if peerErr != nil || formalGLMPhase21RockValidateCommitRecord(record, context, peer) != nil {
		return fmt.Errorf("formal-glm registered Phase21 commit: invalid peer record")
	}
	path, err := formalGLMRegisteredPhase21CommitInboxPathV1(state.rockRoot, context.artifactID, record.Receipt.Role)
	if err != nil {
		return err
	}
	_, _, err = formalGLMPhase21RockWriteJSON(state.rockRoot, path, record)
	return err
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) RunPhase21CommitV1(
	publication formalGLMPhase21PublicCertificateV2,
) (formalGLMPhase21RockCommitRecord, error) {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return formalGLMPhase21RockCommitRecord{}, err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return formalGLMPhase21RockCommitRecord{}, err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21CommitPublicationV1(state, publication)
}

func (host *formalGLMRegisteredPhase20JobControlHostV1) ImportPhase21PeerCommitV1(
	record formalGLMPhase21RockCommitRecord,
) error {
	owner, done, err := host.beginOpV1()
	if err != nil {
		return err
	}
	defer done()
	state, err := host.phase21StageStateV1(owner)
	if err != nil {
		return err
	}
	defer state.clearV1()
	return formalGLMRegisteredPhase21ImportPeerCommitV1(state, record)
}
