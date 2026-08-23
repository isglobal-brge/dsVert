package main

// A Cox exact-GC attempt has one live owner.  This closed process boundary
// starts that owner from a Rock-local sensitive config, then accepts only
// authenticated, source-bound daemon operations through a fresh attachment.
// It is deliberately not a public analytical or DSI command.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const (
	formalCoxBlockwiseWorkerHostConfigVersion  = "dsvert-formal-cox-blockwise-worker-host-v1"
	formalCoxBlockwiseWorkerHostControlVersion = "dsvert-formal-cox-blockwise-worker-control-v1"
	formalCoxBlockwiseWorkerHostDir            = "formal-cox-blockwise-worker-host-v1"
	formalCoxBlockwiseWorkerHostMax            = 16 << 20
)

type formalCoxBlockwiseWorkerHostConfig struct {
	Version   string                                   `json:"version"`
	Bootstrap formalCoxBlockwiseWorkerBootstrapCommand `json:"bootstrap"`
}

type formalCoxBlockwiseWorkerControlCommand struct {
	Version             string          `json:"version"`
	PeerName            string          `json:"peer_name"`
	PlanSHA256          string          `json:"plan_sha256"`
	AttemptID           string          `json:"attempt_id"`
	RecipientSigningKey string          `json:"recipient_signing_key"`
	Action              string          `json:"action"`
	Payload             json.RawMessage `json:"payload"`
}

type formalCoxBlockwiseWorkerControlResponse struct {
	Version string          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

func formalCoxBlockwiseWorkerHostIdentity(config formalCoxBlockwiseWorkerHostConfig) (
	formalCoxBlockwisePlan, string, [32]byte, string, error,
) {
	var zero formalCoxBlockwisePlan
	var noAttempt [32]byte
	if config.Version != formalCoxBlockwiseWorkerHostConfigVersion ||
		config.Bootstrap.Version != formalCoxBlockwiseWorkerBootstrapVersion {
		return zero, "", noAttempt, "", fmt.Errorf("formal-cox: invalid worker host config")
	}
	encoded, err := json.Marshal(config.Bootstrap.Source)
	if err != nil {
		return zero, "", noAttempt, "", err
	}
	defer clear(encoded)
	source, err := formalCoxBlockwiseSourceImportDecodeCommand(encoded)
	if err != nil {
		return zero, "", noAttempt, "", fmt.Errorf("formal-cox: invalid worker host source")
	}
	compiled, err := formalCoxCompileSignedRSchema(source.Schema)
	if err != nil {
		return zero, "", noAttempt, "", err
	}
	plan, err := buildFormalCoxBlockwisePlan(compiled.Policy, source.BlockCapacity, source.RunID)
	if err != nil {
		return zero, "", noAttempt, "", err
	}
	attempt, err := formalCoxBlockwiseWorkerBootstrapDecodeAttempt(config.Bootstrap.AttemptID)
	if err != nil {
		return zero, "", noAttempt, "", err
	}
	planSHA, err := formalCoxBlockwisePlanSHA256(plan)
	if err != nil {
		return zero, "", noAttempt, "", err
	}
	return plan, source.RecipientPeerName, attempt, planSHA, nil
}

func formalCoxBlockwiseWorkerHostConfigPath(stateRoot string,
	config formalCoxBlockwiseWorkerHostConfig,
) (string, error) {
	_, peer, attempt, planSHA, err := formalCoxBlockwiseWorkerHostIdentity(config)
	if err != nil {
		return "", err
	}
	return formalCoxBlockwiseWorkerHostConfigPathForSelector(
		stateRoot, peer, planSHA, fmt.Sprintf("%x", attempt))
}

func formalCoxBlockwiseWorkerHostConfigDir(path string) string { return filepath.Dir(path) }

func formalCoxBlockwiseWorkerHostReadConfigAtRoot(path, stateRoot string,
	production bool,
) (formalCoxBlockwiseWorkerHostConfig, error) {
	var config formalCoxBlockwiseWorkerHostConfig
	rootPath, err := formalTypedFinalizerLifecycleRootAt(path, stateRoot)
	if err != nil || (production && stateRoot != formalFinalizerHandoffStateRoot) ||
		formalCoxBlockwiseSourceEnsurePrivateDir(stateRoot) != nil ||
		formalCoxBlockwiseSourceEnsurePrivateDir(rootPath) != nil {
		return config, fmt.Errorf("formal-cox: invalid worker host config location")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return config, err
	}
	defer root.Close()
	relative, err := filepath.Rel(rootPath, path)
	if err != nil || filepath.IsAbs(relative) || relative == "." || filepath.Clean(relative) != relative {
		return config, fmt.Errorf("formal-cox: invalid worker host config location")
	}
	encoded, err := formalGLMPhase21RootReadRecord(root, relative, formalCoxBlockwiseWorkerHostMax)
	if err != nil {
		return config, fmt.Errorf("formal-cox: unreadable worker host config")
	}
	defer clear(encoded)
	config, err = formalCoxBlockwiseWorkerHostDecodeConfig(encoded)
	if err != nil {
		return formalCoxBlockwiseWorkerHostConfig{}, err
	}
	_, peer, _, _, err := formalCoxBlockwiseWorkerHostIdentity(config)
	if err != nil || rootPath != filepath.Join(stateRoot, peer) {
		return formalCoxBlockwiseWorkerHostConfig{}, fmt.Errorf("formal-cox: invalid worker host config")
	}
	want, err := formalCoxBlockwiseWorkerHostConfigPath(stateRoot, config)
	if err != nil || want != path {
		return formalCoxBlockwiseWorkerHostConfig{}, fmt.Errorf("formal-cox: invalid worker host config location")
	}
	return config, nil
}

func runFormalCoxBlockwiseWorkerHostAtRoot(path, stateRoot string, production bool,
	stop <-chan struct{}, ready chan<- struct{},
) error {
	config, err := formalCoxBlockwiseWorkerHostReadConfigAtRoot(path, stateRoot, production)
	if err != nil {
		return err
	}
	_, peer, attempt, planSHA, err := formalCoxBlockwiseWorkerHostIdentity(config)
	if err != nil {
		return err
	}
	wantAttachment, err := formalCoxBlockwiseWorkerAttachmentForConfig(config)
	if err != nil {
		return err
	}
	gotAttachment, err := formalCoxBlockwiseWorkerAttachmentReadAtRoot(
		peer, planSHA, fmt.Sprintf("%x", attempt), stateRoot, production)
	if err != nil {
		return err
	}
	wantAttachmentJSON, err := json.Marshal(wantAttachment)
	if err != nil {
		return err
	}
	defer clear(wantAttachmentJSON)
	gotAttachmentJSON, err := json.Marshal(gotAttachment)
	if err != nil {
		return err
	}
	defer clear(gotAttachmentJSON)
	if !bytes.Equal(wantAttachmentJSON, gotAttachmentJSON) {
		return fmt.Errorf("formal-cox: worker attachment does not match config")
	}
	rootPath := filepath.Join(stateRoot, peer)
	if err := formalTypedFinalizerLifecycleRemoveConfig(path, rootPath); err != nil {
		return err
	}
	encoded, err := json.Marshal(config.Bootstrap)
	if err != nil {
		return err
	}
	defer clear(encoded)
	config.Bootstrap.Source.RecipientSigningKey = ""
	bootstrap, err := openFormalCoxBlockwiseWorkerBootstrapAtRoot(encoded, stateRoot, production)
	if err != nil {
		return err
	}
	if ready != nil {
		close(ready)
	}
	if stop != nil {
		<-stop
	}
	return bootstrap.Close()
}

func formalCoxBlockwiseWorkerControlValidate(action string, payload json.RawMessage) error {
	switch action {
	case "bind":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonBindV1{})
	case "root_claim":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonRootV1{})
	case "start":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonStartV1{})
	case "poll":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonPollV1{})
	case "relay":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonRelayV1{})
	case "result":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &struct{}{})
	case "commit":
		return formalCoxBlockwiseExchangeDaemonPayload(payload, &formalCoxBlockwiseExchangeDaemonCommitV1{})
	default:
		return fmt.Errorf("formal-cox: unsupported worker control action")
	}
}

func formalCoxBlockwiseWorkerControlRunAtRoot(encoded []byte, stateRoot string,
	production bool,
) (formalCoxBlockwiseWorkerControlResponse, error) {
	var command formalCoxBlockwiseWorkerControlCommand
	if err := formalCoxBlockwiseSourceDecodeCanonical(encoded,
		formalCoxBlockwiseWorkerHostMax, "worker control command", &command); err != nil ||
		command.Version != formalCoxBlockwiseWorkerHostControlVersion ||
		!formalCoxCompilerRLabel(command.PeerName) ||
		!formalCoxIsSHA256(command.PlanSHA256) ||
		!formalCoxIsSHA256(command.AttemptID) ||
		command.RecipientSigningKey == "" ||
		len(command.Payload) < 2 || command.Payload[0] != '{' ||
		formalCoxBlockwiseWorkerControlValidate(command.Action, command.Payload) != nil {
		return formalCoxBlockwiseWorkerControlResponse{}, fmt.Errorf("formal-cox: invalid worker control command")
	}
	descriptor, err := formalCoxBlockwiseWorkerAttachmentReadAtRoot(
		command.PeerName, command.PlanSHA256, command.AttemptID, stateRoot, production)
	if err != nil {
		return formalCoxBlockwiseWorkerControlResponse{}, err
	}
	source := descriptor.Source
	source.RecipientSigningKey = command.RecipientSigningKey
	bootstrap := formalCoxBlockwiseWorkerBootstrapCommand{
		Version: formalCoxBlockwiseWorkerBootstrapVersion,
		Source:  source, AttemptID: descriptor.AttemptID,
	}
	_, peer, attempt, planSHA, identityErr := formalCoxBlockwiseWorkerHostIdentity(
		formalCoxBlockwiseWorkerHostConfig{
			Version: formalCoxBlockwiseWorkerHostConfigVersion, Bootstrap: bootstrap,
		})
	if identityErr != nil || peer != command.PeerName || planSHA != command.PlanSHA256 ||
		fmt.Sprintf("%x", attempt) != command.AttemptID {
		return formalCoxBlockwiseWorkerControlResponse{},
			fmt.Errorf("formal-cox: worker attachment selector mismatch")
	}
	bootstrapEncoded, err := json.Marshal(bootstrap)
	if err != nil {
		return formalCoxBlockwiseWorkerControlResponse{}, err
	}
	defer clear(bootstrapEncoded)
	attachment, err := openFormalCoxBlockwiseWorkerBootstrapAttachmentAtRoot(bootstrapEncoded, stateRoot, production)
	if err != nil {
		return formalCoxBlockwiseWorkerControlResponse{}, err
	}
	defer attachment.Close()
	var response json.RawMessage
	if err := attachment.client.callV1(command.Action, command.Payload, &response); err != nil {
		return formalCoxBlockwiseWorkerControlResponse{}, err
	}
	return formalCoxBlockwiseWorkerControlResponse{Version: formalCoxBlockwiseWorkerHostControlVersion, Payload: response}, nil
}

func runFormalCoxBlockwiseWorkerHostSelectorAtRoot(peer, planSHA, attempt,
	stateRoot string, production bool, stop <-chan struct{}, ready chan<- struct{},
) error {
	configPath, err := formalCoxBlockwiseWorkerHostConfigPathForSelector(
		stateRoot, peer, planSHA, attempt)
	if err != nil {
		return err
	}
	return runFormalCoxBlockwiseWorkerHostAtRoot(
		configPath, stateRoot, production, stop, ready)
}

func handleFormalCoxBlockwiseWorkerHost(peer, planSHA, attempt string) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	stop := make(chan struct{})
	go func() { <-signals; close(stop) }()
	return runFormalCoxBlockwiseWorkerHostSelectorAtRoot(
		peer, planSHA, attempt, formalFinalizerHandoffStateRoot, true, stop, nil)
}

func handleFormalCoxBlockwiseWorkerControl() {
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, formalCoxBlockwiseWorkerHostMax+1))
	if err != nil || len(encoded) > formalCoxBlockwiseWorkerHostMax || !bytes.HasPrefix(encoded, []byte("{")) {
		clear(encoded)
		outputError("Formal Cox worker control failed")
		return
	}
	defer clear(encoded)
	response, err := formalCoxBlockwiseWorkerControlRunAtRoot(encoded, formalFinalizerHandoffStateRoot, true)
	if err != nil {
		outputError("Formal Cox worker control failed")
		return
	}
	output(response)
}
