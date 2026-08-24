package main

// The host and the short-lived control command derive their local control
// channel from the same provisioned Rock bootstrap.  The request contains
// only public selectors and already-authenticated job frames; it never names a
// filesystem location or carries a daemon key.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const (
	formalGLMRegisteredPhase20JobControlCommandVersionV1 = "dsvert-formal-glm-registered-phase20-job-control-v1"
)

type formalGLMRegisteredPhase20JobControlCommandV1 struct {
	Version          string          `json:"version"`
	Peer             string          `json:"peer"`
	ArtifactID       string          `json:"artifact_id"`
	ReceiptSetSHA256 string          `json:"receipt_set_sha256"`
	Action           string          `json:"action"`
	Payload          json.RawMessage `json:"payload"`
}

type formalGLMRegisteredPhase20JobControlResponseV1 struct {
	Version string          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

func formalGLMRegisteredPhase20JobControlLoadConfigV1(
	rockRoot, peer, artifactID, receiptSetSHA256 string,
) (formalGLMRegisteredPhase20JobControlHostConfigV1, error) {
	var zero formalGLMRegisteredPhase20JobControlHostConfigV1
	root, err := formalGLMRegisteredPhase19OpenRockRootV1(rockRoot)
	if err != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	defer root.Close()
	relative, err := formalGLMRegisteredPhase20JobControlHostProvisionRelativePathV1(
		peer, artifactID, receiptSetSHA256)
	if err != nil {
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: invalid selector")
	}
	config, _, err := formalGLMRegisteredPhase20JobControlHostProvisionReadConfigV1(root, relative)
	if err != nil || config.Peer != peer || config.Start.ArtifactID != artifactID ||
		config.Start.ReceiptSetSHA256 != receiptSetSHA256 {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	return config, nil
}

func formalGLMRegisteredPhase20JobControlMACV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1, purpose string,
) ([]byte, error) {
	if err := formalGLMRegisteredPhase20JobControlHostValidateV1(config); err != nil ||
		purpose == "" {
		return nil, fmt.Errorf("formal-glm registered Phase20 job control: invalid bootstrap")
	}
	mac := hmac.New(sha256.New, config.Signing)
	_, _ = mac.Write([]byte(formalGLMRegisteredPhase20JobControlDomainV1 + "|" + purpose + "|"))
	_, _ = mac.Write([]byte(config.Peer))
	_, _ = mac.Write([]byte("|" + config.Start.ArtifactID + "|" + config.Start.ReceiptSetSHA256))
	return mac.Sum(nil), nil
}

func formalGLMRegisteredPhase20JobControlCredentialsV1(
	config formalGLMRegisteredPhase20JobControlHostConfigV1,
) ([]byte, string, error) {
	key, err := formalGLMRegisteredPhase20JobControlMACV1(config, "daemon-key")
	if err != nil || len(key) != sha256.Size {
		clear(key)
		return nil, "", fmt.Errorf("formal-glm registered Phase20 job control: invalid bootstrap")
	}
	socket, err := formalGLMRegisteredPhase20JobControlMACV1(config, "daemon-socket")
	if err != nil {
		clear(key)
		return nil, "", err
	}
	directory := filepath.Join(os.TempDir(), "dsv-g-"+hex.EncodeToString(socket[:12]))
	clear(socket)
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		len(directory) >= 96 {
		clear(key)
		return nil, "", fmt.Errorf("formal-glm registered Phase20 job control: socket path too long")
	}
	return key, directory, nil
}

func formalGLMRegisteredPhase20JobControlPayloadValidV1(
	action string, payload json.RawMessage,
) bool {
	if len(payload) < 2 || payload[0] != '{' {
		return false
	}
	switch action {
	case "negotiate":
		_, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonInboundV1](payload)
		return err == nil
	case "start", "health", "job_ref", "heartbeat", "compute", "terminal":
		_, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[struct{}](payload)
		return err == nil
	case "bind":
		_, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonBindV1](payload)
		return err == nil
	case "poll":
		_, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonPollV1](payload)
		return err == nil
	case "relay":
		_, err := formalGLMRegisteredPhase20JobControlHostDaemonPayloadV1[formalGLMRegisteredPhase20JobControlHostDaemonRelayV1](payload)
		return err == nil
	default:
		return false
	}
}

func formalGLMRegisteredPhase20JobControlDecodeV1(
	encoded []byte,
) (formalGLMRegisteredPhase20JobControlCommandV1, error) {
	var command formalGLMRegisteredPhase20JobControlCommandV1
	if len(encoded) < 2 || len(encoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 ||
		encoded[0] != '{' {
		return command, fmt.Errorf("formal-glm registered Phase20 job control: invalid command")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return formalGLMRegisteredPhase20JobControlCommandV1{}, fmt.Errorf("formal-glm registered Phase20 job control: invalid command")
	}
	var trailing any
	canonical, err := json.Marshal(command)
	if err != nil || decoder.Decode(&trailing) != io.EOF || !bytes.Equal(canonical, encoded) ||
		command.Version != formalGLMRegisteredPhase20JobControlCommandVersionV1 ||
		!formalGLMRegistryLabelV1(command.Peer, 128) ||
		!formalGLMIsSHA256(command.ArtifactID) || !formalGLMIsSHA256(command.ReceiptSetSHA256) ||
		!formalGLMRegisteredPhase20JobControlPayloadValidV1(command.Action, command.Payload) {
		clear(canonical)
		return formalGLMRegisteredPhase20JobControlCommandV1{}, fmt.Errorf("formal-glm registered Phase20 job control: invalid command")
	}
	clear(canonical)
	return command, nil
}

func formalGLMRegisteredPhase20JobControlRunAtRootV1(
	encoded []byte, rockRoot string,
) (formalGLMRegisteredPhase20JobControlResponseV1, error) {
	var zero formalGLMRegisteredPhase20JobControlResponseV1
	command, err := formalGLMRegisteredPhase20JobControlDecodeV1(encoded)
	if err != nil {
		return zero, err
	}
	config, err := formalGLMRegisteredPhase20JobControlLoadConfigV1(
		rockRoot, command.Peer, command.ArtifactID, command.ReceiptSetSHA256)
	if err != nil {
		return zero, err
	}
	defer formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
	key, socketDir, err := formalGLMRegisteredPhase20JobControlCredentialsV1(config)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	client, err := newFormalGLMRegisteredPhase20JobControlHostDaemonClientV1(
		filepath.Join(socketDir, formalGLMRegisteredPhase20JobControlHostDaemonSocketV1), key)
	if err != nil {
		return zero, err
	}
	defer client.Close()
	var response json.RawMessage
	if err := client.callV1(command.Action, command.Payload, &response); err != nil {
		clear(response)
		return zero, fmt.Errorf("formal-glm registered Phase20 job control: unavailable")
	}
	return formalGLMRegisteredPhase20JobControlResponseV1{
		Version: formalGLMRegisteredPhase20JobControlCommandVersionV1,
		Payload: append(json.RawMessage(nil), response...),
	}, nil
}

func runFormalGLMRegisteredPhase20JobControlHostAtRootV1(
	peer, artifactID, receiptSetSHA256, rockRoot string,
	stop <-chan struct{}, ready chan<- struct{},
) error {
	config, err := formalGLMRegisteredPhase20JobControlLoadConfigV1(
		rockRoot, peer, artifactID, receiptSetSHA256)
	if err != nil {
		return err
	}
	key, socketDir, err := formalGLMRegisteredPhase20JobControlCredentialsV1(config)
	if err != nil {
		formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
		return err
	}
	host, err := newFormalGLMRegisteredPhase20JobControlHostV1(rockRoot, config)
	formalGLMRegisteredPhase20JobControlHostClearConfigV1(&config)
	if err != nil {
		clear(key)
		return err
	}
	daemon, err := newFormalGLMRegisteredPhase20JobControlHostDaemonAtDirV1(
		host, key, socketDir)
	clear(key)
	if err != nil {
		_ = host.Close()
		return err
	}
	defer daemon.Close()
	if ready != nil {
		close(ready)
	}
	if stop != nil {
		<-stop
	}
	return nil
}

func handleFormalGLMRegisteredPhase20JobControlHost(
	peer, artifactID, receiptSetSHA256 string,
) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	stop := make(chan struct{})
	go func() { <-signals; close(stop) }()
	return runFormalGLMRegisteredPhase20JobControlHostAtRootV1(
		peer, artifactID, receiptSetSHA256, formalFinalizerHandoffStateRoot, stop, nil)
}

func handleFormalGLMRegisteredPhase20JobControl() {
	encoded, err := io.ReadAll(io.LimitReader(
		os.Stdin, formalGLMRegisteredPhase20JobControlHostDaemonMaxV1+1))
	if err != nil || len(encoded) > formalGLMRegisteredPhase20JobControlHostDaemonMaxV1 {
		clear(encoded)
		mpcFatalError("formal-glm registered Phase20 job control failed")
	}
	defer clear(encoded)
	response, err := formalGLMRegisteredPhase20JobControlRunAtRootV1(
		encoded, formalFinalizerHandoffStateRoot)
	if err != nil {
		mpcFatalError("formal-glm registered Phase20 job control failed")
	}
	output(response)
}
