package main

// Multiprocess boundary for the complete durable Phase-1.9 -> Phase-1.5 ->
// DP-bridge schedule. It reuses the exact-GC bounded spool and persists its
// additive Ring128 DP share only inside the authenticated encrypted Phase-2.0
// handoff. The command remains internal and is not advertised by capabilities.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	formalGLMPhase19ScheduleWorkerVersion     = "dsvert-formal-glm-phase19-durable-schedule-worker-v1"
	formalGLMPhase19ScheduleResultVersion     = "dsvert-formal-glm-phase19-durable-schedule-result-v1"
	formalGLMPhase19ScheduleResultKind        = "formal-glm-phase19-ring128-dp-bridge-share-v1"
	formalGLMPhase19ScheduleCompletionVersion = "dsvert-formal-glm-phase19-durable-schedule-completion-v1"
	formalGLMPhase19ScheduleCompletionKind    = "formal-glm-phase20-encrypted-handoff-only-v1"
)

type formalGLMPhase19ScheduleManifestBlock struct {
	BlockIndex   int      `json:"block_index"`
	IngressPaths []string `json:"ingress_paths"`
}

type formalGLMPhase19ScheduleDurableConfig struct {
	CheckpointDir     string            `json:"checkpoint_dir"`
	CheckpointKey     string            `json:"checkpoint_key"`
	SigningSecretKey  string            `json:"signing_secret_key"`
	PinnedPublicKeys  map[string]string `json:"pinned_public_keys"`
	OutputLatticeBits int               `json:"output_lattice_bits"`
}

type formalGLMPhase19ScheduleWorkerConfig struct {
	Version             string                                `json:"version"`
	Role                string                                `json:"role"`
	LocalTemplate       formalGLMPhase19RuntimeLocalInput     `json:"local_template"`
	BlockManifestPath   string                                `json:"block_manifest_path"`
	BlockManifestSHA256 string                                `json:"block_manifest_sha256"`
	BlockManifestBytes  int64                                 `json:"block_manifest_bytes"`
	MaxBlockStoreBytes  int64                                 `json:"max_block_store_bytes"`
	SemanticRootSHA256  string                                `json:"semantic_root_sha256"`
	ScheduleRootSHA256  string                                `json:"schedule_root_sha256"`
	AttemptID           string                                `json:"attempt_id"`
	HandoffDir          string                                `json:"handoff_dir"`
	SpoolDir            string                                `json:"spool_dir"`
	MaxSpoolBytes       int64                                 `json:"max_spool_bytes"`
	TTLSeconds          int                                   `json:"ttl_seconds"`
	HeartbeatKey        string                                `json:"heartbeat_key"`
	Durable             formalGLMPhase19ScheduleDurableConfig `json:"durable"`
}

type formalGLMPhase19ScheduleResult struct {
	Version                  string                               `json:"version"`
	Kind                     string                               `json:"kind"`
	ContextSHA256            string                               `json:"context_sha256"`
	PlanSHA256               string                               `json:"plan_sha256"`
	SemanticRootSHA256       string                               `json:"semantic_root_sha256"`
	ScheduleRootSHA256       string                               `json:"schedule_root_sha256"`
	Peer                     string                               `json:"peer"`
	AttemptID                string                               `json:"attempt_id"`
	FinalReceipts            []formalGLMPhase15StepReceipt        `json:"final_receipts"`
	DPBridge                 formalGLMPhase15DPBridgePlan         `json:"dp_bridge"`
	DPShare                  string                               `json:"dp_share"`
	PostExecutionToken       formalGLMPhase19PostExecutionToken   `json:"post_execution_token"`
	PostExecutionTokenSeal   string                               `json:"post_execution_token_seal"`
	ExecutionReceiptPair     formalGLMPhase19ExecutionReceiptPair `json:"execution_receipt_pair"`
	ExecutionReceiptPairSeal string                               `json:"execution_receipt_pair_seal"`
	HandoffSHA256            string                               `json:"handoff_sha256"`
	HandoffBytes             int64                                `json:"handoff_bytes"`
	HandoffReplayed          bool                                 `json:"handoff_replayed"`
	ExecutionValidSealed     bool                                 `json:"execution_valid_sealed"`
	ExecutionValidityOpened  bool                                 `json:"execution_validity_opened"`
	OpeningsPerformed        int                                  `json:"openings_performed"`
	ProductionReady          bool                                 `json:"production_ready"`
}

// formalGLMPhase19ScheduleCompletion is the only cleartext terminal record.
// The DP share and its evidence remain inside the authenticated encrypted
// Phase-2.0 handoff and therefore have no worker-spool JSON representation.
type formalGLMPhase19ScheduleCompletion struct {
	Version                 string `json:"version"`
	Kind                    string `json:"kind"`
	ContextSHA256           string `json:"context_sha256"`
	PlanSHA256              string `json:"plan_sha256"`
	SemanticRootSHA256      string `json:"semantic_root_sha256"`
	ScheduleRootSHA256      string `json:"schedule_root_sha256"`
	Peer                    string `json:"peer"`
	AttemptID               string `json:"attempt_id"`
	HandoffSHA256           string `json:"handoff_sha256"`
	HandoffBytes            int64  `json:"handoff_bytes"`
	HandoffReplayed         bool   `json:"handoff_replayed"`
	ExecutionValidSealed    bool   `json:"execution_valid_sealed"`
	ExecutionValidityOpened bool   `json:"execution_validity_opened"`
	OpeningsPerformed       int    `json:"openings_performed"`
	ProductionReady         bool   `json:"production_ready"`
}

type formalGLMPhase19ScheduleWorkerDecoded struct {
	config  formalGLMPhase19ScheduleWorkerConfig
	root    [32]byte
	durable formalGLMPhase19RuntimeDurableConfig
}

func formalGLMPhase19ScheduleDecodeHex32(value, name string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) ||
		hex.EncodeToString(decoded) != value {
		clear(decoded)
		return result, fmt.Errorf("formal-glm: invalid schedule %s", name)
	}
	copy(result[:], decoded)
	clear(decoded)
	if !formalGLMPhase19KeyValid(result) {
		return [32]byte{}, fmt.Errorf("formal-glm: missing schedule %s", name)
	}
	return result, nil
}

func formalGLMPhase19ScheduleDecodeEd25519Private(value string) (
	ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("formal-glm: invalid schedule signing key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func formalGLMPhase19ScheduleDecodePins(values map[string]string,
	expected []string) (map[string]ed25519.PublicKey, error) {
	if len(values) != len(expected) {
		return nil, fmt.Errorf("formal-glm: incomplete schedule pinset")
	}
	result := make(map[string]ed25519.PublicKey, len(values))
	for _, peer := range expected {
		value, ok := values[peer]
		if !ok {
			return nil, fmt.Errorf("formal-glm: incomplete schedule pinset")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != value {
			clear(decoded)
			return nil, fmt.Errorf("formal-glm: invalid schedule pin")
		}
		result[peer] = ed25519.PublicKey(decoded)
	}
	return result, nil
}

func formalGLMPhase19ScheduleValidateManifest(
	config formalGLMPhase19ScheduleWorkerConfig) error {
	path := config.BlockManifestPath
	if formalGLMPhase19RuntimeValidatePath(path, "block manifest") != nil ||
		filepath.Dir(path) != config.SpoolDir ||
		filepath.Base(path) != "formal-block-manifest-v1.jsonl" ||
		config.BlockManifestBytes < 2 ||
		config.BlockManifestBytes > exactGCMaxAbsoluteOffset ||
		!formalGLMIsSHA256(config.BlockManifestSHA256) {
		return fmt.Errorf("formal-glm: invalid private block manifest policy")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !exactGCPrivateOwnedRegular(info) ||
		info.Size() != config.BlockManifestBytes {
		return fmt.Errorf("formal-glm: unsafe private block manifest")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	_, err = io.CopyBuffer(h, file, buffer)
	clear(buffer)
	if err != nil || hex.EncodeToString(h.Sum(nil)) != config.BlockManifestSHA256 {
		return fmt.Errorf("formal-glm: private block manifest hash mismatch")
	}
	return nil
}

type formalGLMPhase19ScheduleManifestReader struct {
	file    *os.File
	scanner *bufio.Scanner
	plan    formalGLMPhase15Plan
	next    int
}

func formalGLMPhase19ScheduleOpenManifest(
	config formalGLMPhase19ScheduleWorkerConfig) (
	*formalGLMPhase19ScheduleManifestReader, error) {
	if err := formalGLMPhase19ScheduleValidateManifest(config); err != nil {
		return nil, err
	}
	file, err := os.Open(config.BlockManifestPath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	return &formalGLMPhase19ScheduleManifestReader{
		file: file, scanner: scanner, plan: config.LocalTemplate.Plan,
	}, nil
}

func (reader *formalGLMPhase19ScheduleManifestReader) Next() (
	formalGLMPhase19ScheduleManifestBlock, error) {
	var zero formalGLMPhase19ScheduleManifestBlock
	if reader == nil || reader.file == nil || reader.scanner == nil ||
		reader.next < 0 || reader.next >= reader.plan.TotalBlocks ||
		!reader.scanner.Scan() {
		if reader != nil && reader.scanner != nil && reader.scanner.Err() != nil {
			return zero, reader.scanner.Err()
		}
		return zero, fmt.Errorf("formal-glm: incomplete private block manifest")
	}
	line := append([]byte(nil), reader.scanner.Bytes()...)
	defer clear(line)
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var block formalGLMPhase19ScheduleManifestBlock
	if err := decoder.Decode(&block); err != nil {
		return zero, fmt.Errorf("formal-glm: invalid private block manifest record")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF ||
		block.BlockIndex != reader.next ||
		len(block.IngressPaths) != len(reader.plan.Kernel.CustodianPeers) {
		return zero, fmt.Errorf("formal-glm: reordered private block manifest")
	}
	seen := make(map[string]bool, len(block.IngressPaths))
	for _, path := range block.IngressPaths {
		if formalGLMPhase19RuntimeValidatePath(path, "manifest ingress") != nil ||
			seen[path] {
			return zero, fmt.Errorf("formal-glm: invalid manifest ingress path")
		}
		seen[path] = true
	}
	reader.next++
	return block, nil
}

func (reader *formalGLMPhase19ScheduleManifestReader) Finish() error {
	if reader == nil || reader.file == nil || reader.scanner == nil ||
		reader.next != reader.plan.TotalBlocks {
		return fmt.Errorf("formal-glm: incomplete private block manifest")
	}
	if reader.scanner.Scan() {
		return fmt.Errorf("formal-glm: trailing private block manifest record")
	}
	return reader.scanner.Err()
}

func (reader *formalGLMPhase19ScheduleManifestReader) Close() error {
	if reader == nil || reader.file == nil {
		return nil
	}
	err := reader.file.Close()
	reader.file = nil
	reader.scanner = nil
	return err
}

func formalGLMPhase19ScheduleValidateRoleBinding(
	plan formalGLMPhase15Plan, pins map[string]ed25519.PublicKey) error {
	roles, err := formalGLMPhase15DPBridgePinnedRoles(plan, pins)
	if err != nil || roles.garblerName != plan.Kernel.ComputePeers[0] ||
		roles.evaluatorName != plan.Kernel.ComputePeers[1] {
		return fmt.Errorf(
			"formal-glm: signed plan changed pinned cryptographic role order")
	}
	return nil
}

func formalGLMPhase19ScheduleValidateConfig(
	config formalGLMPhase19ScheduleWorkerConfig) (
	formalGLMPhase19ScheduleWorkerDecoded, error) {

	var zero formalGLMPhase19ScheduleWorkerDecoded
	plan := config.LocalTemplate.Plan
	if config.Version != formalGLMPhase19ScheduleWorkerVersion ||
		(config.Role != "garbler" && config.Role != "evaluator") ||
		config.LocalTemplate.Version != formalGLMPhase19RuntimePrepareVersion ||
		config.LocalTemplate.BlockIndex != -1 ||
		len(config.LocalTemplate.IngressPaths) != 0 ||
		config.MaxSpoolBytes < 1<<20 || config.MaxSpoolBytes > 64<<30 ||
		config.MaxBlockStoreBytes < 1 ||
		config.MaxBlockStoreBytes > exactGCMaxAbsoluteOffset ||
		config.TTLSeconds < 10 || config.TTLSeconds > 86400 ||
		formalGLMPhase19RuntimeValidatePath(config.SpoolDir, "spool") != nil ||
		formalGLMPhase19RuntimeValidatePath(config.HandoffDir, "handoff") != nil ||
		formalGLMPhase19RuntimeValidatePath(
			config.Durable.CheckpointDir, "checkpoint") != nil {
		return zero, fmt.Errorf("formal-glm: invalid durable schedule policy")
	}
	_, requiredStore, err := formalGLMPhase19StreamStoreRequiredBytes(plan)
	if err != nil || config.MaxBlockStoreBytes < requiredStore ||
		formalGLMPhase19ScheduleValidateManifest(config) != nil {
		return zero, fmt.Errorf("formal-glm: invalid bounded schedule storage")
	}
	expectedPeer := plan.Kernel.ComputePeers[1]
	if config.Role == "garbler" {
		expectedPeer = plan.Kernel.ComputePeers[0]
	}
	if config.LocalTemplate.Recipient != expectedPeer {
		return zero, fmt.Errorf("formal-glm: durable schedule role changed peer")
	}
	root, err := formalGLMPhase19ScheduleDecodeHex32(
		config.ScheduleRootSHA256, "root")
	if err != nil {
		return zero, err
	}
	if _, err := formalGLMPhase19ScheduleDecodeHex32(
		config.AttemptID, "attempt"); err != nil {
		return zero, err
	}
	if _, err := formalGLMPhase19ScheduleDecodeHex32(
		config.SemanticRootSHA256, "semantic root"); err != nil {
		return zero, err
	}
	checkpointKey, err := formalGLMPhase19RuntimeDecodeKey(
		config.Durable.CheckpointKey, "checkpoint key")
	if err != nil {
		return zero, err
	}
	signingKey, err := formalGLMPhase19ScheduleDecodeEd25519Private(
		config.Durable.SigningSecretKey)
	if err != nil {
		clear(checkpointKey[:])
		return zero, err
	}
	pins, err := formalGLMPhase19ScheduleDecodePins(
		config.Durable.PinnedPublicKeys, plan.Kernel.CustodianPeers)
	if err != nil {
		clear(checkpointKey[:])
		clear(signingKey)
		return zero, err
	}
	if err := formalGLMPhase19ScheduleValidateRoleBinding(plan, pins); err != nil {
		clear(checkpointKey[:])
		clear(signingKey)
		for name, pin := range pins {
			clear(pin)
			delete(pins, name)
		}
		return zero, err
	}
	durable := formalGLMPhase19RuntimeDurableConfig{
		CheckpointDir:     config.Durable.CheckpointDir,
		CheckpointKey:     checkpointKey,
		SigningKey:        signingKey,
		Pins:              pins,
		OutputLatticeBits: config.Durable.OutputLatticeBits,
	}
	return formalGLMPhase19ScheduleWorkerDecoded{
		config: config, root: root, durable: durable,
	}, nil
}

func formalGLMPhase19ScheduleClearDecoded(
	decoded *formalGLMPhase19ScheduleWorkerDecoded) {
	if decoded == nil {
		return
	}
	clear(decoded.durable.CheckpointKey[:])
	clear(decoded.durable.SigningKey)
	for key, value := range decoded.durable.Pins {
		clear(value)
		delete(decoded.durable.Pins, key)
	}
	decoded.config.LocalTemplate.LocalIngressKey = ""
	decoded.config.LocalTemplate.RecipientTransportSecretKey = ""
	decoded.config.LocalTemplate.BackendKey = ""
	decoded.config.Durable.CheckpointKey = ""
	decoded.config.Durable.SigningSecretKey = ""
	for key := range decoded.config.Durable.PinnedPublicKeys {
		delete(decoded.config.Durable.PinnedPublicKeys, key)
	}
}

func formalGLMPhase19ScheduleEncodeResult(
	decoded formalGLMPhase19ScheduleWorkerDecoded,
	value formalGLMPhase19RuntimeScheduleResult) (
	formalGLMPhase19ScheduleResult, error) {

	plan := decoded.config.LocalTemplate.Plan
	if err := formalGLMPhase19VerifyPostExecutionToken(
		value.postToken, value.backend); err != nil {
		return formalGLMPhase19ScheduleResult{}, err
	}
	if err := formalGLMPhase15VerifyReceiptPair(
		plan, value.finalReceipts, decoded.durable.Pins); err != nil {
		return formalGLMPhase19ScheduleResult{}, err
	}
	if len(value.dpShares) != plan.Kernel.CoefficientCount ||
		value.executionPair.ExecutionValidityOpened ||
		!value.executionPair.ExecutionValidSealed ||
		value.executionPair.OpeningsPerformed != 0 {
		return formalGLMPhase19ScheduleResult{},
			fmt.Errorf("formal-glm: invalid durable schedule output")
	}
	spec := exactGCCircuitSpec{
		Operation: exactGCFormalGLMDPBridge,
		RingBits:  128, FracBits: 0,
		VectorLen: plan.Kernel.CoefficientCount,
	}
	encodedShare, err := exactGCEncodeWorkerCanonicalShares(value.dpShares, spec)
	if err != nil {
		return formalGLMPhase19ScheduleResult{}, err
	}
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		return formalGLMPhase19ScheduleResult{}, err
	}
	return formalGLMPhase19ScheduleResult{
		Version:            formalGLMPhase19ScheduleResultVersion,
		Kind:               formalGLMPhase19ScheduleResultKind,
		ContextSHA256:      value.context.ContextSHA256ForPhase19(),
		PlanSHA256:         hex.EncodeToString(planDigest[:]),
		SemanticRootSHA256: decoded.config.SemanticRootSHA256,
		ScheduleRootSHA256: decoded.config.ScheduleRootSHA256,
		Peer:               decoded.config.LocalTemplate.Recipient,
		AttemptID:          decoded.config.AttemptID,
		FinalReceipts: append([]formalGLMPhase15StepReceipt(nil),
			value.finalReceipts...),
		DPBridge: value.dpBridge, DPShare: encodedShare,
		PostExecutionToken:       value.postToken,
		PostExecutionTokenSeal:   hex.EncodeToString(value.postToken.seal[:]),
		ExecutionReceiptPair:     value.executionPair,
		ExecutionReceiptPairSeal: hex.EncodeToString(value.executionPair.seal[:]),
		ExecutionValidSealed:     true, ExecutionValidityOpened: false,
		OpeningsPerformed: 0, ProductionReady: false,
	}, nil
}

func formalGLMPhase19ScheduleCompletionFromResult(
	result formalGLMPhase19ScheduleResult,
) (formalGLMPhase19ScheduleCompletion, error) {
	var zero formalGLMPhase19ScheduleCompletion
	if result.Version != formalGLMPhase19ScheduleResultVersion ||
		result.Kind != formalGLMPhase19ScheduleResultKind ||
		!formalGLMIsSHA256(result.ContextSHA256) ||
		!formalGLMIsSHA256(result.PlanSHA256) ||
		!formalGLMIsSHA256(result.SemanticRootSHA256) ||
		!formalGLMIsSHA256(result.ScheduleRootSHA256) ||
		!formalGLMIsSHA256(result.AttemptID) ||
		!formalGLMIsSHA256(result.HandoffSHA256) ||
		result.HandoffBytes < 64 ||
		result.HandoffBytes > formalGLMPhase20HandoffMaxBytes ||
		exactGCValidateLabel("formal schedule completion peer", result.Peer, 128) != nil ||
		!result.ExecutionValidSealed || result.ExecutionValidityOpened ||
		result.OpeningsPerformed != 0 || result.ProductionReady {
		return zero, fmt.Errorf("formal-glm: invalid durable schedule completion")
	}
	return formalGLMPhase19ScheduleCompletion{
		Version:                 formalGLMPhase19ScheduleCompletionVersion,
		Kind:                    formalGLMPhase19ScheduleCompletionKind,
		ContextSHA256:           result.ContextSHA256,
		PlanSHA256:              result.PlanSHA256,
		SemanticRootSHA256:      result.SemanticRootSHA256,
		ScheduleRootSHA256:      result.ScheduleRootSHA256,
		Peer:                    result.Peer,
		AttemptID:               result.AttemptID,
		HandoffSHA256:           result.HandoffSHA256,
		HandoffBytes:            result.HandoffBytes,
		HandoffReplayed:         result.HandoffReplayed,
		ExecutionValidSealed:    true,
		ExecutionValidityOpened: false,
		OpeningsPerformed:       0,
		ProductionReady:         false,
	}, nil
}

func formalGLMPhase19ScheduleWriteCompletion(spool string,
	result formalGLMPhase19ScheduleResult,
) error {
	completion, err := formalGLMPhase19ScheduleCompletionFromResult(result)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	return exactGCPrivateMarker(spool, "result.json", encoded)
}

func formalGLMPhase19ScheduleReadWorkerConfig(path string) (
	formalGLMPhase19ScheduleWorkerConfig, error) {
	var config formalGLMPhase19ScheduleWorkerConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, fmt.Errorf("formal-glm: invalid schedule config path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		!exactGCPrivateOwnedRegular(info) || info.Size() < 2 ||
		info.Size() > formalGLMPhase19RuntimeMaxConfigBytes {
		return config, fmt.Errorf("formal-glm: unsafe schedule worker config")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	if err := formalGLMPhase19RuntimeStrictDecode(
		file, &config, formalGLMPhase19RuntimeMaxConfigBytes); err != nil {
		return config, err
	}
	if filepath.Dir(path) != config.SpoolDir {
		return config, fmt.Errorf("formal-glm: schedule config left its spool")
	}
	return config, nil
}

func handleFormalGLMPhase19ScheduleWorker(configPath string) (returnErr error) {
	config, err := formalGLMPhase19ScheduleReadWorkerConfig(configPath)
	if err != nil {
		return err
	}
	if err := exactGCRemoveSensitiveConfig(configPath); err != nil {
		return err
	}
	decoded, err := formalGLMPhase19ScheduleValidateConfig(config)
	if err != nil {
		return err
	}
	defer formalGLMPhase19ScheduleClearDecoded(&decoded)
	if err := exactGCPrepareWorkerSpool(config.SpoolDir); err != nil {
		return err
	}
	heartbeat, err := exactGCStrictBase64(config.HeartbeatKey, 32)
	if err != nil {
		return fmt.Errorf("formal-glm: invalid schedule heartbeat key")
	}
	clear(heartbeat)
	stopHeartbeat, err := exactGCStartWorkerHeartbeat(
		config.SpoolDir, config.AttemptID, config.HeartbeatKey,
		time.Duration(config.TTLSeconds)*time.Second)
	decoded.config.HeartbeatKey = ""
	config.HeartbeatKey = ""
	if err != nil {
		return err
	}
	heartbeatStopped := false
	defer func() {
		if !heartbeatStopped {
			if stopErr := stopHeartbeat(); returnErr == nil && stopErr != nil {
				returnErr = stopErr
			}
		}
	}()
	if err := exactGCPrivateMarker(config.SpoolDir, "ready", []byte("1")); err != nil {
		return err
	}
	handoffBackend, err := formalGLMPhase19RuntimeDecodeKey(
		decoded.config.LocalTemplate.BackendKey, "backend key")
	if err != nil {
		return err
	}
	handoff, err := newFormalGLMPhase20HandoffStore(
		decoded.config.HandoffDir, decoded.config.SemanticRootSHA256,
		decoded.config.LocalTemplate.Recipient, decoded.durable.CheckpointKey,
		handoffBackend,
		decoded.durable.Pins)
	clear(handoffBackend[:])
	if err != nil {
		return err
	}
	defer handoff.close()
	if source, committed, loadErr := handoff.Load(); loadErr == nil {
		result := source.Result
		source.clear()
		result.ScheduleRootSHA256 = decoded.config.ScheduleRootSHA256
		result.AttemptID = decoded.config.AttemptID
		result.HandoffSHA256 = committed.SHA256
		result.HandoffBytes = committed.Bytes
		result.HandoffReplayed = true
		if err := stopHeartbeat(); err != nil {
			return err
		}
		heartbeatStopped = true
		if err := formalGLMPhase19ScheduleWriteCompletion(
			config.SpoolDir, result); err != nil {
			return err
		}
		return exactGCPrivateMarker(config.SpoolDir, "done", []byte("1"))
	} else if !os.IsNotExist(loadErr) {
		return loadErr
	}
	spool, err := newExactGCSpoolRW(
		config.SpoolDir, config.MaxSpoolBytes,
		time.Duration(config.TTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := spool.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	manifest, err := formalGLMPhase19ScheduleOpenManifest(decoded.config)
	if err != nil {
		return err
	}
	manifestClosed := false
	defer func() {
		if !manifestClosed {
			if closeErr := manifest.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	value, err := formalGLMPhase19RuntimeRunDurableScheduleManifest(
		spool, decoded.config.LocalTemplate, manifest, decoded.root,
		decoded.durable, decoded.config.SpoolDir,
		decoded.config.MaxBlockStoreBytes)
	if err != nil {
		return err
	}
	if err := manifest.Close(); err != nil {
		return err
	}
	manifestClosed = true
	defer func() {
		exactGCZeroBigInts(value.betaShares)
		exactGCZeroBigInts(value.dpShares)
		clear(value.backend[:])
	}()
	if err := spool.Close(); err != nil {
		return err
	}
	closed = true
	result, err := formalGLMPhase19ScheduleEncodeResult(decoded, value)
	if err != nil {
		return err
	}
	committed, err := handoff.Commit(
		decoded.config.LocalTemplate.Plan, value.context, result)
	if err != nil {
		return err
	}
	result.HandoffSHA256 = committed.SHA256
	result.HandoffBytes = committed.Bytes
	result.HandoffReplayed = committed.Replayed
	if err := stopHeartbeat(); err != nil {
		return err
	}
	heartbeatStopped = true
	if err := formalGLMPhase19ScheduleWriteCompletion(
		config.SpoolDir, result); err != nil {
		return err
	}
	if err := exactGCPrivateMarker(config.SpoolDir, "done", []byte("1")); err != nil {
		return err
	}
	return nil
}

func formalGLMPhase19ScheduleCanonicalPeers(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for peer := range values {
		result = append(result, peer)
	}
	sort.Strings(result)
	return result
}

func formalGLMPhase19ScheduleResultDigest(
	value formalGLMPhase19ScheduleResult) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
