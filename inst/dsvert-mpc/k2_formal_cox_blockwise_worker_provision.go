package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const formalCoxBlockwiseWorkerProvisionVersion = "dsvert-formal-cox-blockwise-worker-provision-v1"

const (
	formalCoxBlockwiseWorkerAttachmentVersion = "dsvert-formal-cox-blockwise-worker-attachment-v1"
	formalCoxBlockwiseWorkerAttachmentFile    = "worker-attachment.json"
)

// The provision command is server-local.  It accepts the already-signed
// recipient bootstrap, derives the only permitted Rock slot and returns a
// non-secret selector for the host process.  A caller never chooses a path.
type formalCoxBlockwiseWorkerProvisionCommand struct {
	Version string                             `json:"version"`
	Config  formalCoxBlockwiseWorkerHostConfig `json:"config"`
}

type formalCoxBlockwiseWorkerProvisionReceipt struct {
	Version    string `json:"version"`
	PeerName   string `json:"peer_name"`
	PlanSHA256 string `json:"plan_sha256"`
	AttemptID  string `json:"attempt_id"`
	Replayed   bool   `json:"replayed"`
}

// The attachment descriptor is durable only while the attempt's Rock state
// exists. It excludes the local Ed25519 private key; each control attachment
// supplies that key through the server-local invocation boundary instead.
type formalCoxBlockwiseWorkerAttachmentDescriptor struct {
	Version   string                                `json:"version"`
	Source    formalCoxBlockwiseSourceImportCommand `json:"source"`
	AttemptID string                                `json:"attempt_id"`
}

func formalCoxBlockwiseWorkerHostConfigPathForSelector(stateRoot, peer,
	planSHA, attempt string,
) (string, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot ||
		!formalCoxCompilerRLabel(peer) || !formalCoxIsSHA256(planSHA) ||
		!formalCoxIsSHA256(attempt) {
		return "", fmt.Errorf("formal-cox: invalid worker host selector")
	}
	return filepath.Join(stateRoot, peer, formalCoxBlockwiseWorkerHostDir,
		planSHA, attempt, "worker-config.json"), nil
}

func formalCoxBlockwiseWorkerAttachmentPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), formalCoxBlockwiseWorkerAttachmentFile)
}

func formalCoxBlockwiseWorkerAttachmentForConfig(
	config formalCoxBlockwiseWorkerHostConfig,
) (formalCoxBlockwiseWorkerAttachmentDescriptor, error) {
	if _, _, _, _, err := formalCoxBlockwiseWorkerHostIdentity(config); err != nil {
		return formalCoxBlockwiseWorkerAttachmentDescriptor{}, err
	}
	source := config.Bootstrap.Source
	source.RecipientSigningKey = ""
	return formalCoxBlockwiseWorkerAttachmentDescriptor{
		Version: formalCoxBlockwiseWorkerAttachmentVersion,
		Source:  source, AttemptID: config.Bootstrap.AttemptID,
	}, nil
}

func formalCoxBlockwiseWorkerAttachmentDecode(encoded []byte) (
	formalCoxBlockwiseWorkerAttachmentDescriptor, error,
) {
	var descriptor formalCoxBlockwiseWorkerAttachmentDescriptor
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseWorkerHostMax ||
		encoded[0] != '{' {
		return descriptor, fmt.Errorf("formal-cox: invalid worker attachment")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return formalCoxBlockwiseWorkerAttachmentDescriptor{},
			fmt.Errorf("formal-cox: invalid worker attachment")
	}
	var trailing any
	canonical, err := json.Marshal(descriptor)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) ||
		descriptor.Version != formalCoxBlockwiseWorkerAttachmentVersion ||
		descriptor.Source.RecipientSigningKey != "" ||
		!formalCoxIsSHA256(descriptor.AttemptID) {
		clear(canonical)
		return formalCoxBlockwiseWorkerAttachmentDescriptor{},
			fmt.Errorf("formal-cox: invalid worker attachment")
	}
	clear(canonical)
	return descriptor, nil
}

func formalCoxBlockwiseWorkerAttachmentReadAtRoot(peer, planSHA, attempt,
	stateRoot string, production bool,
) (formalCoxBlockwiseWorkerAttachmentDescriptor, error) {
	var zero formalCoxBlockwiseWorkerAttachmentDescriptor
	configPath, err := formalCoxBlockwiseWorkerHostConfigPathForSelector(
		stateRoot, peer, planSHA, attempt)
	if err != nil {
		return zero, err
	}
	rootPath, err := formalTypedFinalizerLifecycleRootAt(configPath, stateRoot)
	if err != nil || rootPath != filepath.Join(stateRoot, peer) ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) {
		return zero, fmt.Errorf("formal-cox: invalid worker attachment root")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	attachmentPath := formalCoxBlockwiseWorkerAttachmentPath(configPath)
	relative, err := filepath.Rel(rootPath, attachmentPath)
	if err != nil || filepath.IsAbs(relative) || relative == "." ||
		filepath.Clean(relative) != relative {
		return zero, fmt.Errorf("formal-cox: invalid worker attachment path")
	}
	encoded, err := formalGLMPhase21RootReadRecord(
		root, relative, formalCoxBlockwiseWorkerHostMax)
	if err != nil {
		return zero, fmt.Errorf("formal-cox: unavailable worker attachment")
	}
	defer clear(encoded)
	descriptor, err := formalCoxBlockwiseWorkerAttachmentDecode(encoded)
	if err != nil || descriptor.AttemptID != attempt {
		return zero, fmt.Errorf("formal-cox: invalid worker attachment")
	}
	return descriptor, nil
}

func formalCoxBlockwiseWorkerHostDecodeConfig(encoded []byte) (
	formalCoxBlockwiseWorkerHostConfig, error,
) {
	var config formalCoxBlockwiseWorkerHostConfig
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseWorkerHostMax ||
		encoded[0] != '{' {
		return config, fmt.Errorf("formal-cox: invalid worker host config")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return formalCoxBlockwiseWorkerHostConfig{},
			fmt.Errorf("formal-cox: invalid worker host config")
	}
	var trailing any
	canonical, err := json.Marshal(config)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) {
		clear(canonical)
		return formalCoxBlockwiseWorkerHostConfig{},
			fmt.Errorf("formal-cox: non-canonical worker host config")
	}
	clear(canonical)
	if _, _, _, _, err := formalCoxBlockwiseWorkerHostIdentity(config); err != nil {
		return formalCoxBlockwiseWorkerHostConfig{}, err
	}
	return config, nil
}

func formalCoxBlockwiseWorkerProvisionDecode(encoded []byte) (
	formalCoxBlockwiseWorkerProvisionCommand, error,
) {
	var command formalCoxBlockwiseWorkerProvisionCommand
	if len(encoded) < 2 || len(encoded) > formalCoxBlockwiseWorkerHostMax ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-cox: invalid worker provision command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalCoxBlockwiseWorkerProvisionCommand{},
			fmt.Errorf("formal-cox: invalid worker provision command")
	}
	var trailing any
	canonical, err := json.Marshal(command)
	if decoder.Decode(&trailing) != io.EOF || err != nil ||
		!bytes.Equal(canonical, encoded) ||
		command.Version != formalCoxBlockwiseWorkerProvisionVersion {
		clear(canonical)
		return formalCoxBlockwiseWorkerProvisionCommand{},
			fmt.Errorf("formal-cox: invalid worker provision command")
	}
	clear(canonical)
	configJSON, err := json.Marshal(command.Config)
	if err != nil {
		return formalCoxBlockwiseWorkerProvisionCommand{}, err
	}
	defer clear(configJSON)
	if _, err := formalCoxBlockwiseWorkerHostDecodeConfig(configJSON); err != nil {
		return formalCoxBlockwiseWorkerProvisionCommand{}, err
	}
	return command, nil
}

func formalCoxBlockwiseWorkerProvisionRunAtRoot(encoded []byte, stateRoot string,
	production bool,
) (formalCoxBlockwiseWorkerProvisionReceipt, error) {
	var zero formalCoxBlockwiseWorkerProvisionReceipt
	command, err := formalCoxBlockwiseWorkerProvisionDecode(encoded)
	if err != nil {
		return zero, err
	}
	_, peer, attempt, planSHA, err := formalCoxBlockwiseWorkerHostIdentity(command.Config)
	if err != nil {
		return zero, err
	}
	path, err := formalCoxBlockwiseWorkerHostConfigPath(stateRoot, command.Config)
	if err != nil {
		return zero, err
	}
	rootPath, err := formalTypedFinalizerLifecycleRootAt(path, stateRoot)
	if err != nil || rootPath != filepath.Join(stateRoot, peer) ||
		(production && stateRoot != formalFinalizerHandoffStateRoot) {
		return zero, fmt.Errorf("formal-cox: invalid worker provision root")
	}
	for _, directory := range []string{
		stateRoot,
		rootPath,
		filepath.Join(rootPath, formalCoxBlockwiseWorkerHostDir),
		filepath.Join(rootPath, formalCoxBlockwiseWorkerHostDir, planSHA),
		filepath.Dir(path),
	} {
		if err := formalCoxBlockwiseSourceEnsurePrivateDir(directory); err != nil {
			return zero, err
		}
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return zero, err
	}
	defer root.Close()
	relative, err := filepath.Rel(rootPath, path)
	if err != nil || filepath.IsAbs(relative) || relative == "." ||
		filepath.Clean(relative) != relative {
		return zero, fmt.Errorf("formal-cox: invalid worker provision path")
	}
	if burned, burnErr := formalCoxBlockwiseWorkerHostBurnedAtRoot(
		root, rootPath, path, command.Config); burnErr != nil || burned {
		if burnErr != nil {
			return zero, burnErr
		}
		return zero, fmt.Errorf("formal-cox: worker provision is burned")
	}
	configJSON, err := json.Marshal(command.Config)
	if err != nil {
		return zero, err
	}
	defer clear(configJSON)
	created, err := formalGLMPhase21RootCreateRecord(root, relative, configJSON)
	if err != nil {
		return zero, err
	}
	replayed := !created
	if replayed {
		persisted, readErr := formalGLMPhase21RootReadRecord(
			root, relative, formalCoxBlockwiseWorkerHostMax)
		if readErr != nil {
			return zero, readErr
		}
		if !bytes.Equal(persisted, configJSON) {
			clear(persisted)
			return zero, fmt.Errorf("formal-cox: conflicting worker provision")
		}
		clear(persisted)
	}
	if burned, burnErr := formalCoxBlockwiseWorkerHostBurnedAtRoot(
		root, rootPath, path, command.Config); burnErr != nil || burned {
		if burnErr != nil {
			return zero, burnErr
		}
		return zero, fmt.Errorf("formal-cox: worker provision is burned")
	}
	descriptor, err := formalCoxBlockwiseWorkerAttachmentForConfig(command.Config)
	if err != nil {
		return zero, err
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return zero, err
	}
	defer clear(descriptorJSON)
	attachmentRelative, err := filepath.Rel(rootPath,
		formalCoxBlockwiseWorkerAttachmentPath(path))
	if err != nil || filepath.IsAbs(attachmentRelative) || attachmentRelative == "." ||
		filepath.Clean(attachmentRelative) != attachmentRelative {
		return zero, fmt.Errorf("formal-cox: invalid worker attachment path")
	}
	attachmentCreated, err := formalGLMPhase21RootCreateRecord(
		root, attachmentRelative, descriptorJSON)
	if err != nil {
		return zero, err
	}
	if !attachmentCreated {
		persisted, readErr := formalGLMPhase21RootReadRecord(
			root, attachmentRelative, formalCoxBlockwiseWorkerHostMax)
		if readErr != nil {
			return zero, readErr
		}
		if !bytes.Equal(persisted, descriptorJSON) {
			clear(persisted)
			return zero, fmt.Errorf("formal-cox: conflicting worker attachment")
		}
		clear(persisted)
	}
	if burned, burnErr := formalCoxBlockwiseWorkerHostBurnedAtRoot(
		root, rootPath, path, command.Config); burnErr != nil || burned {
		if burnErr != nil {
			return zero, burnErr
		}
		return zero, fmt.Errorf("formal-cox: worker provision is burned")
	}
	if _, err := formalCoxBlockwiseWorkerHostReadConfigAtRoot(path, stateRoot, production); err != nil {
		return zero, err
	}
	return formalCoxBlockwiseWorkerProvisionReceipt{
		Version: formalCoxBlockwiseWorkerProvisionVersion, PeerName: peer,
		PlanSHA256: planSHA, AttemptID: fmt.Sprintf("%x", attempt), Replayed: replayed,
	}, nil
}

func handleFormalCoxBlockwiseWorkerProvision() {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin,
		formalCoxBlockwiseWorkerHostMax+1))
	if err != nil || len(encoded) > formalCoxBlockwiseWorkerHostMax ||
		!bytes.HasPrefix(encoded, []byte("{")) {
		clear(encoded)
		outputError("Formal Cox worker provision failed")
		return
	}
	defer clear(encoded)
	result, err := formalCoxBlockwiseWorkerProvisionRunAtRoot(
		encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		outputError("Formal Cox worker provision failed")
		return
	}
	output(result)
}
