package main

// Owner-only restart spool for one authority's one-draw output. The exact
// transit payload is AEAD-encrypted under a key derived from the local Rock
// storage root. It is never a relay/DSI object and never contains both shares.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/crypto/hkdf"
)

const (
	formalGLMPhase21LocalSpoolVersion  = "dsvert-formal-glm-phase21-local-spool-v1"
	formalGLMPhase21LocalSpoolPurpose  = "formal_glm_one_draw_local_restart_v1"
	formalGLMPhase21LocalSpoolDomain   = "dsVert/formal-glm/phase21/local-spool/v1"
	formalGLMPhase21LocalSpoolMaxBytes = formalFinalizerHandoffMaxPayload + (64 << 10)
)

type formalGLMPhase21LocalSpoolRecord struct {
	Version                string `json:"version"`
	Purpose                string `json:"purpose"`
	ArtifactID             string `json:"artifact_id"`
	FinalPairRootSHA256    string `json:"final_pair_root_sha256"`
	PlanSHA256             string `json:"plan_sha256"`
	PinsetSHA256           string `json:"pinset_sha256"`
	SamplerContractSHA256  string `json:"sampler_contract_sha256"`
	PeerName               string `json:"peer_name"`
	PeerID                 string `json:"peer_id"`
	Role                   string `json:"role"`
	SourceReceiptSHA256    string `json:"source_receipt_sha256"`
	CanonicalPayloadSHA256 string `json:"canonical_payload_sha256"`
	Nonce                  []byte `json:"nonce"`
	Ciphertext             []byte `json:"ciphertext"`
	ProductionReady        bool   `json:"-"`
}

type formalGLMPhase21LocalSpoolPayload struct {
	Version             string                             `json:"version"`
	ArtifactID          string                             `json:"artifact_id"`
	FinalPairRootSHA256 string                             `json:"final_pair_root_sha256"`
	PlanSHA256          string                             `json:"plan_sha256"`
	PeerName            string                             `json:"peer_name"`
	PeerID              string                             `json:"peer_id"`
	Role                string                             `json:"role"`
	OneDraw             formalGLMPhase21OneDrawTransitBody `json:"one_draw"`
	ProductionReady     bool                               `json:"-"`
}

func formalGLMPhase21ClearLocalSpoolPayload(
	payload *formalGLMPhase21LocalSpoolPayload,
) {
	if payload == nil {
		return
	}
	for index := range payload.OneDraw.Shares {
		payload.OneDraw.Shares[index] = ""
	}
	*payload = formalGLMPhase21LocalSpoolPayload{}
}

type formalGLMPhase21LocalSpoolOwnerRecord struct {
	Version               string `json:"version"`
	Purpose               string `json:"purpose"`
	ArtifactID            string `json:"artifact_id"`
	FinalPairRootSHA256   string `json:"final_pair_root_sha256"`
	SamplerContractSHA256 string `json:"sampler_contract_sha256"`
	PeerName              string `json:"peer_name"`
	PeerID                string `json:"peer_id"`
	Role                  string `json:"role"`
	ProductionReady       bool   `json:"-"`
}

func formalGLMPhase21LocalSpoolOwnerRelativePath(
	store *formalFinalizerHandoffStore, create bool,
) (string, error) {
	if store == nil || store.root == nil ||
		store.binding.Family != formalFinalizerHandoffFamilyGLM ||
		!formalGLMIsSHA256(store.binding.ArtifactID) {
		return "", fmt.Errorf("formal-glm: invalid local spool owner path")
	}
	artifactID := store.binding.ArtifactID
	shard := filepath.Join(
		"formal-glm-local-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	if err := formalFinalizerHandoffValidateRootOwnedDir(
		store.root, shard); err != nil {
		return "", err
	}
	return filepath.Join(shard, "owner-"+artifactID+".json"), nil
}

func formalGLMPhase21LocalSpoolOwner(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	payload formalGLMPhase21LocalSpoolPayload,
) (formalGLMPhase21LocalSpoolOwnerRecord, error) {
	var zero formalGLMPhase21LocalSpoolOwnerRecord
	contractSHA, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil {
		return zero, err
	}
	authority, err := formalFinalizerHandoffPeer(
		store.binding, payload.Role)
	if err != nil || authority.PeerName != payload.PeerName ||
		authority.PeerID != payload.PeerID {
		return zero, fmt.Errorf("formal-glm: invalid local spool owner")
	}
	return formalGLMPhase21LocalSpoolOwnerRecord{
		Version:               formalGLMPhase21LocalSpoolVersion,
		Purpose:               formalGLMPhase21LocalSpoolPurpose,
		ArtifactID:            store.binding.ArtifactID,
		FinalPairRootSHA256:   store.binding.FinalPairRootSHA256,
		SamplerContractSHA256: contractSHA,
		PeerName:              authority.PeerName,
		PeerID:                authority.PeerID,
		Role:                  authority.Role,
		ProductionReady:       false,
	}, nil
}

func formalGLMPhase21DecodeLocalSpoolOwner(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	encoded []byte,
) (formalGLMPhase21LocalSpoolOwnerRecord, error) {
	var record formalGLMPhase21LocalSpoolOwnerRecord
	if len(encoded) == 0 || len(encoded) > formalFinalizerHandoffMaxRecord ||
		store == nil ||
		formalGLMPhase21RequireProductiveOneDraw(contract.SamplerMode) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil {
		return record, fmt.Errorf("formal-glm: invalid local spool owner record")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return record, fmt.Errorf("formal-glm: trailing local spool owner record")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return record, fmt.Errorf("formal-glm: non-canonical local spool owner")
	}
	payload := formalGLMPhase21LocalSpoolPayload{
		PeerName: record.PeerName,
		PeerID:   record.PeerID,
		Role:     record.Role,
	}
	want, err := formalGLMPhase21LocalSpoolOwner(
		store, contract, payload)
	if err != nil || !reflect.DeepEqual(record, want) {
		return record, fmt.Errorf("formal-glm: local spool owner binding mismatch")
	}
	return record, nil
}

func formalGLMPhase21CommitLocalSpoolOwner(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	payload formalGLMPhase21LocalSpoolPayload,
) error {
	record, err := formalGLMPhase21LocalSpoolOwner(
		store, contract, payload)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	relative, err := formalGLMPhase21LocalSpoolOwnerRelativePath(store, true)
	if err != nil {
		return err
	}
	existing, _, err := store.createAndRead(relative, encoded)
	if err != nil {
		return err
	}
	defer clear(existing)
	stored, err := formalGLMPhase21DecodeLocalSpoolOwner(
		store, contract, existing)
	if err != nil || !reflect.DeepEqual(stored, record) {
		return fmt.Errorf("formal-glm: conflicting local spool owner")
	}
	return nil
}

func formalGLMPhase21LocalSpoolRelativePath(
	store *formalFinalizerHandoffStore, role string, create bool,
) (string, error) {
	if store == nil || store.root == nil ||
		store.binding.Family != formalFinalizerHandoffFamilyGLM ||
		!formalGLMIsSHA256(store.binding.ArtifactID) ||
		(role != "garbler" && role != "evaluator") {
		return "", fmt.Errorf("formal-glm: invalid local spool path")
	}
	artifactID := store.binding.ArtifactID
	shard := filepath.Join(
		"formal-glm-local-v1", artifactID[:2], artifactID[2:4])
	if create {
		if err := formalGLMPhase21EnsureRootPrivateDir(store.root, shard); err != nil {
			return "", err
		}
	} else if err := formalGLMPhase21ValidateRootPrivateDir(
		store.root, shard, false); err != nil {
		return "", err
	}
	if err := formalFinalizerHandoffValidateRootOwnedDir(
		store.root, shard); err != nil {
		return "", err
	}
	return filepath.Join(shard,
		"one-draw-"+role+"-"+artifactID+".bin"), nil
}

func formalGLMPhase21LocalSpoolKey(
	store *formalFinalizerHandoffStore, role string,
) ([32]byte, error) {
	var key [32]byte
	authority, err := formalFinalizerHandoffPeer(store.binding, role)
	if err != nil || !formalGLMPhase19KeyValid(store.atRestKey) {
		return key, fmt.Errorf("formal-glm: invalid local spool key binding")
	}
	info, err := json.Marshal(struct {
		ArtifactID          string `json:"artifact_id"`
		FinalPairRootSHA256 string `json:"final_pair_root_sha256"`
		PeerName            string `json:"peer_name"`
		PeerID              string `json:"peer_id"`
		Role                string `json:"role"`
	}{store.binding.ArtifactID, store.binding.FinalPairRootSHA256,
		authority.PeerName, authority.PeerID, role})
	if err != nil {
		return key, err
	}
	defer clear(info)
	salt := sha256.Sum256([]byte(formalGLMPhase21LocalSpoolDomain + "/salt"))
	reader := hkdf.New(sha256.New, store.atRestKey[:], salt[:], append(
		[]byte(formalGLMPhase21LocalSpoolDomain+"/key|"), info...))
	if _, err := io.ReadFull(reader, key[:]); err != nil ||
		!formalGLMPhase19KeyValid(key) {
		clear(key[:])
		return key, fmt.Errorf("formal-glm: local spool key derivation failed")
	}
	return key, nil
}

func formalGLMPhase21LocalSpoolAAD(
	record formalGLMPhase21LocalSpoolRecord,
) ([]byte, error) {
	record.Ciphertext = nil
	return json.Marshal(record)
}

func formalGLMPhase21LocalSpoolPayloadSHA256(encoded []byte) string {
	digest := sha256.Sum256(append(
		[]byte(formalGLMPhase21LocalSpoolDomain+"/payload|"), encoded...))
	return hex.EncodeToString(digest[:])
}

func formalGLMPhase21LocalSpoolReceiptSHA256(
	receipt jointDPBiomedicalGaussianOneDrawChunkReceipt,
) (string, error) {
	return formalGLMPhase21StickyHash(
		formalGLMPhase21LocalSpoolDomain+"/source-receipt", receipt)
}

func formalGLMPhase21ValidateLocalSpoolPayload(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	payload formalGLMPhase21LocalSpoolPayload,
) error {
	if store == nil ||
		formalGLMPhase21RequireProductiveOneDraw(contract.SamplerMode) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil ||
		contract.ArtifactID != store.binding.ArtifactID ||
		payload.Version != formalGLMPhase21LocalSpoolVersion ||
		payload.ProductionReady || payload.ArtifactID != contract.ArtifactID ||
		payload.FinalPairRootSHA256 != store.binding.FinalPairRootSHA256 ||
		payload.PlanSHA256 != store.binding.PlanSHA256 ||
		payload.OneDraw.Version != formalGLMPhase21BoundReleaseVersion {
		return fmt.Errorf("formal-glm: invalid local spool payload binding")
	}
	authority, err := formalFinalizerHandoffPeer(store.binding, payload.Role)
	receipt := payload.OneDraw.Receipt
	message, messageErr := jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(
		receipt)
	if err != nil || messageErr != nil || payload.PeerName != authority.PeerName ||
		payload.PeerID != authority.PeerID || receipt.PeerName != authority.PeerName ||
		receipt.PeerID != authority.PeerID || receipt.Role != authority.Role ||
		receipt.PlanSHA256 != store.binding.PlanSHA256 || receipt.ChunkStart != 0 ||
		receipt.CoordinateCount != receipt.TotalCoordinateCount ||
		len(receipt.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(store.pins[authority.PeerName], message, receipt.Signature) {
		return fmt.Errorf("formal-glm: invalid local spool receipt")
	}
	shares, err := formalGLMPhase21DecodeOneDrawTransitShares(
		payload.OneDraw.Shares, receipt.CoordinateCount)
	if err != nil {
		return err
	}
	defer exactGCZeroBigInts(shares)
	encoded, validity, err := jointDPBiomedicalGaussianOneDrawEncodeOutputShares(
		shares, receipt.CoordinateCount)
	if err != nil {
		return err
	}
	defer clear(encoded)
	want, err := jointDPBiomedicalGaussianOneDrawOutputShareSHA256(
		receipt.EnvelopePreimageSHA256, receipt.Role, encoded, validity)
	if err != nil || want != receipt.OutputShareSHA256 {
		return fmt.Errorf("formal-glm: local spool share digest mismatch")
	}
	return nil
}

func formalGLMPhase21BuildLocalSpoolPayload(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	output formalGLMPhase21OneDrawLocalOutput,
) (formalGLMPhase21LocalSpoolPayload, error) {
	return formalGLMPhase21BuildLocalSpoolPayloadWithResolution(
		source, store, contract, output, nil)
}

func formalGLMPhase21BuildLocalSpoolPayloadWithResolution(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	output formalGLMPhase21OneDrawLocalOutput,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21LocalSpoolPayload, error) {
	var zero formalGLMPhase21LocalSpoolPayload
	var binding formalFinalizerHandoffBinding
	var err error
	if resolution == nil {
		binding, err = formalGLMPhase21OneDrawFinalizerBinding(source, output)
	} else {
		binding, err = formalGLMPhase21RegisteredOneDrawFinalizerBinding(
			source, output, contract, *resolution)
	}
	if err != nil || store == nil || !reflect.DeepEqual(binding, store.binding) {
		return zero, fmt.Errorf("formal-glm: local spool output binding mismatch")
	}
	shares := make([]string, len(output.Shares))
	for index, share := range output.Shares {
		if share == nil {
			return zero, fmt.Errorf("formal-glm: nil local spool share")
		}
		shares[index] = share.String()
	}
	payload := formalGLMPhase21LocalSpoolPayload{
		Version:             formalGLMPhase21LocalSpoolVersion,
		ArtifactID:          binding.ArtifactID,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256,
		PeerName:            output.Peer, PeerID: output.Receipt.PeerID, Role: output.Role,
		OneDraw: formalGLMPhase21OneDrawTransitBody{
			Version: formalGLMPhase21BoundReleaseVersion,
			Receipt: output.Receipt, Shares: shares,
		},
		ProductionReady: false,
	}
	if err := formalGLMPhase21ValidateLocalSpoolPayload(
		store, contract, payload); err != nil {
		formalGLMPhase21ClearLocalSpoolPayload(&payload)
		return zero, err
	}
	return payload, nil
}

func formalGLMPhase21MarshalLocalSpoolPayloadCanonical(
	payload formalGLMPhase21LocalSpoolPayload,
) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func formalGLMPhase21EncodeLocalSpool(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	payload formalGLMPhase21LocalSpoolPayload,
) ([]byte, error) {
	if formalGLMPhase21ValidateLocalSpoolPayload(
		store, contract, payload) != nil {
		return nil, fmt.Errorf("formal-glm: invalid local spool payload")
	}
	payloadBytes, err := formalGLMPhase21MarshalLocalSpoolPayloadCanonical(payload)
	if err != nil {
		return nil, err
	}
	defer clear(payloadBytes)
	contractSHA, err := formalGLMPhase21SamplerV2ContractSHA256(contract)
	if err != nil {
		return nil, err
	}
	receiptSHA, err := formalGLMPhase21LocalSpoolReceiptSHA256(
		payload.OneDraw.Receipt)
	if err != nil {
		return nil, err
	}
	record := formalGLMPhase21LocalSpoolRecord{
		Version:               formalGLMPhase21LocalSpoolVersion,
		Purpose:               formalGLMPhase21LocalSpoolPurpose,
		ArtifactID:            contract.ArtifactID,
		FinalPairRootSHA256:   store.binding.FinalPairRootSHA256,
		PlanSHA256:            store.binding.PlanSHA256,
		PinsetSHA256:          store.binding.PinsetSHA256,
		SamplerContractSHA256: contractSHA,
		PeerName:              payload.PeerName,
		PeerID:                payload.PeerID,
		Role:                  payload.Role,
		SourceReceiptSHA256:   receiptSHA,
		CanonicalPayloadSHA256: formalGLMPhase21LocalSpoolPayloadSHA256(
			payloadBytes),
		ProductionReady: false,
	}
	key, err := formalGLMPhase21LocalSpoolKey(store, payload.Role)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil {
		return nil, err
	}
	record.Nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, record.Nonce); err != nil {
		clear(record.Nonce)
		return nil, err
	}
	aad, err := formalGLMPhase21LocalSpoolAAD(record)
	if err != nil {
		clear(record.Nonce)
		return nil, err
	}
	record.Ciphertext = aead.Seal(nil, record.Nonce, payloadBytes, aad)
	clear(aad)
	encoded, err := json.Marshal(record)
	clear(record.Ciphertext)
	clear(record.Nonce)
	if err != nil || len(encoded) > formalGLMPhase21LocalSpoolMaxBytes {
		clear(encoded)
		return nil, fmt.Errorf("formal-glm: local spool record too large")
	}
	return encoded, nil
}

func formalGLMPhase21DecodeLocalSpool(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	encoded []byte,
) (formalGLMPhase21LocalSpoolPayload, error) {
	var zero formalGLMPhase21LocalSpoolPayload
	if len(encoded) < 64 || len(encoded) > formalGLMPhase21LocalSpoolMaxBytes ||
		store == nil ||
		formalGLMPhase21RequireProductiveOneDraw(contract.SamplerMode) != nil ||
		formalGLMPhase21ValidateSamplerV2Contract(contract, store.pins) != nil {
		return zero, fmt.Errorf("formal-glm: invalid local spool record size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record formalGLMPhase21LocalSpoolRecord
	if err := decoder.Decode(&record); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("formal-glm: trailing local spool record")
	}
	canonical, err := json.Marshal(record)
	contractSHA, contractErr := formalGLMPhase21SamplerV2ContractSHA256(contract)
	authority, authorityErr := formalFinalizerHandoffPeer(
		store.binding, record.Role)
	if err != nil || contractErr != nil ||
		authorityErr != nil || !bytes.Equal(canonical, encoded) ||
		record.Version != formalGLMPhase21LocalSpoolVersion ||
		record.Purpose != formalGLMPhase21LocalSpoolPurpose ||
		record.ProductionReady || record.ArtifactID != contract.ArtifactID ||
		record.ArtifactID != store.binding.ArtifactID ||
		record.FinalPairRootSHA256 != store.binding.FinalPairRootSHA256 ||
		record.PlanSHA256 != store.binding.PlanSHA256 ||
		record.PinsetSHA256 != store.binding.PinsetSHA256 ||
		record.SamplerContractSHA256 != contractSHA ||
		record.PeerName != authority.PeerName || record.PeerID != authority.PeerID ||
		!formalGLMIsSHA256(record.SourceReceiptSHA256) ||
		!formalGLMIsSHA256(record.CanonicalPayloadSHA256) {
		return zero, fmt.Errorf("formal-glm: local spool binding mismatch")
	}
	key, err := formalGLMPhase21LocalSpoolKey(store, record.Role)
	if err != nil {
		return zero, err
	}
	defer clear(key[:])
	aead, err := formalGLMPhase20HandoffAEAD(key)
	if err != nil || len(record.Nonce) != 12 ||
		len(record.Ciphertext) < aead.Overhead() {
		return zero, fmt.Errorf("formal-glm: invalid local spool AEAD")
	}
	aad, err := formalGLMPhase21LocalSpoolAAD(record)
	if err != nil {
		return zero, err
	}
	payloadBytes, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	clear(aad)
	if err != nil || formalGLMPhase21LocalSpoolPayloadSHA256(payloadBytes) !=
		record.CanonicalPayloadSHA256 {
		clear(payloadBytes)
		return zero, fmt.Errorf("formal-glm: local spool authentication failed")
	}
	defer clear(payloadBytes)
	if formalFinalizerHandoffCanonicalObject(
		payloadBytes, formalGLMPhase21LocalSpoolMaxBytes) != nil {
		return zero, fmt.Errorf("formal-glm: invalid canonical local spool payload")
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	payloadDecoder.DisallowUnknownFields()
	var payload formalGLMPhase21LocalSpoolPayload
	if err := payloadDecoder.Decode(&payload); err != nil ||
		formalGLMPhase21ValidateLocalSpoolPayload(
			store, contract, payload) != nil {
		formalGLMPhase21ClearLocalSpoolPayload(&payload)
		return zero, fmt.Errorf("formal-glm: invalid local spool payload")
	}
	if err := payloadDecoder.Decode(&struct{}{}); err != io.EOF {
		formalGLMPhase21ClearLocalSpoolPayload(&payload)
		return zero, fmt.Errorf("formal-glm: trailing local spool payload")
	}
	receiptSHA, err := formalGLMPhase21LocalSpoolReceiptSHA256(
		payload.OneDraw.Receipt)
	if err != nil || receiptSHA != record.SourceReceiptSHA256 {
		formalGLMPhase21ClearLocalSpoolPayload(&payload)
		return zero, fmt.Errorf("formal-glm: local spool receipt changed")
	}
	return payload, nil
}

func formalGLMPhase21PersistLocalOneDrawSpool(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	output formalGLMPhase21OneDrawLocalOutput,
) (bool, error) {
	return formalGLMPhase21PersistLocalOneDrawSpoolWithResolution(
		source, store, contract, output, nil)
}

func formalGLMPhase21PersistLocalOneDrawSpoolWithResolution(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	output formalGLMPhase21OneDrawLocalOutput,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (bool, error) {
	if store == nil {
		return false, fmt.Errorf("formal-glm: invalid local spool store")
	}
	if err := store.requireLocalRole(output.Role); err != nil {
		return false, err
	}
	if ack, found, err := store.PreflightAck(); err != nil {
		return false, err
	} else if found {
		return true, &formalFinalizerHandoffTerminalAckError{Proof: ack}
	}
	payload, err := formalGLMPhase21BuildLocalSpoolPayloadWithResolution(
		source, store, contract, output, resolution)
	if err != nil {
		return false, err
	}
	defer formalGLMPhase21ClearLocalSpoolPayload(&payload)
	if err := formalGLMPhase21CommitLocalSpoolOwner(
		store, contract, payload); err != nil {
		return false, err
	}
	encoded, err := formalGLMPhase21EncodeLocalSpool(
		store, contract, payload)
	if err != nil {
		return false, err
	}
	defer clear(encoded)
	relative, err := formalGLMPhase21LocalSpoolRelativePath(
		store, payload.Role, true)
	if err != nil {
		return false, err
	}
	existingBytes, replayed, err := store.createAndRead(relative, encoded)
	if err != nil {
		return false, err
	}
	defer clear(existingBytes)
	existing, err := formalGLMPhase21DecodeLocalSpool(
		store, contract, existingBytes)
	if err != nil {
		return false, err
	}
	defer formalGLMPhase21ClearLocalSpoolPayload(&existing)
	if !reflect.DeepEqual(existing, payload) {
		return false, fmt.Errorf("formal-glm: conflicting local output spool")
	}
	return replayed, nil
}

func formalGLMPhase21LoadLocalOneDrawSpool(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
) (formalGLMPhase21OneDrawLocalOutput, error) {
	return formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
		source, store, contract, ticket, capsule, request,
		backendSignatures, workerSignatures, nil)
}

func formalGLMPhase21LoadLocalOneDrawSpoolWithResolution(
	source *formalGLMPhase20HandoffStore,
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	ticket formalFinalizerHandoffTicket,
	capsule formalGLMPhase16CapsuleBinding,
	request formalGLMPhase16ProductiveRequest,
	backendSignatures, workerSignatures []jointDPBiomedicalGaussianSignature,
	resolution *formalGLMArtifactRegistryResolutionV1,
) (formalGLMPhase21OneDrawLocalOutput, error) {
	var zero formalGLMPhase21OneDrawLocalOutput
	if source == nil || store == nil || source.peer == "" {
		return zero, fmt.Errorf("formal-glm: invalid local spool loader")
	}
	role := ""
	for _, authority := range store.binding.Authorities {
		if authority.PeerName == source.peer {
			role = authority.Role
		}
	}
	if role == "" {
		return zero, fmt.Errorf("formal-glm: local spool authority is absent")
	}
	relative, err := formalGLMPhase21LocalSpoolRelativePath(store, role, false)
	if err != nil {
		return zero, err
	}
	encoded, err := store.read(relative)
	if err != nil {
		return zero, err
	}
	payload, err := formalGLMPhase21DecodeLocalSpool(
		store, contract, encoded)
	if err != nil {
		return zero, err
	}
	defer formalGLMPhase21ClearLocalSpoolPayload(&payload)
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		return zero, err
	}
	transit := formalGLMPhase21OneDrawTransitPayload{
		Version:             formalFinalizerHandoffGLMOneDrawPayloadVersion,
		Purpose:             store.binding.Purpose,
		ArtifactID:          payload.ArtifactID,
		PlanSHA256:          payload.PlanSHA256,
		FinalPairRootSHA256: payload.FinalPairRootSHA256,
		TicketSHA256:        ticketSHA,
		SenderPeerName:      payload.PeerName,
		SenderPeerID:        payload.PeerID,
		SenderRole:          payload.Role,
		OneDraw:             payload.OneDraw,
		ProductionReady:     false,
	}
	defer formalGLMPhase21ClearOneDrawTransit(&transit)
	output, err := formalGLMPhase21ImportOneDrawTransitWithResolution(
		source, capsule, request, backendSignatures, workerSignatures,
		store.binding, ticket, transit, &contract, resolution)
	if err != nil || output.Peer != source.peer || output.Role != role {
		output.clear()
		return zero, fmt.Errorf("formal-glm: local spool reimport failed")
	}
	return output, nil
}

func formalGLMPhase21CleanupLocalOneDrawSpoolAfterAck(
	store *formalFinalizerHandoffStore,
	contract formalGLMPhase21SamplerV2Contract,
	proof formalFinalizerHandoffCommitProof,
) (int, error) {
	if store == nil {
		return 0, fmt.Errorf("formal-glm: invalid local spool cleanup")
	}
	ack, found, err := store.PreflightAck()
	ackJSON, _ := json.Marshal(ack)
	proofJSON, _ := json.Marshal(proof)
	if err != nil || !found || !bytes.Equal(ackJSON, proofJSON) {
		return 0, fmt.Errorf("formal-glm: local spool cleanup lacks ACK")
	}
	ownerRelative, err := formalGLMPhase21LocalSpoolOwnerRelativePath(store, false)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if _, statErr := store.root.Lstat(ownerRelative); os.IsNotExist(statErr) {
		for _, role := range []string{"garbler", "evaluator"} {
			spoolRelative, pathErr := formalGLMPhase21LocalSpoolRelativePath(
				store, role, false)
			if pathErr != nil {
				if os.IsNotExist(pathErr) {
					continue
				}
				return 0, pathErr
			}
			if _, spoolErr := store.root.Lstat(spoolRelative); spoolErr == nil {
				return 0, fmt.Errorf("formal-glm: local spool has no owner guard")
			} else if !os.IsNotExist(spoolErr) {
				return 0, spoolErr
			}
		}
		return 0, nil
	} else if statErr != nil {
		return 0, statErr
	}
	ownerBytes, err := store.read(ownerRelative)
	if err != nil {
		return 0, err
	}
	owner, err := formalGLMPhase21DecodeLocalSpoolOwner(
		store, contract, ownerBytes)
	clear(ownerBytes)
	if err != nil {
		return 0, err
	}
	spoolRelative, err := formalGLMPhase21LocalSpoolRelativePath(
		store, owner.Role, false)
	if err != nil {
		return 0, err
	}
	oppositeRole := "garbler"
	if owner.Role == "garbler" {
		oppositeRole = "evaluator"
	}
	oppositeRelative, err := formalGLMPhase21LocalSpoolRelativePath(
		store, oppositeRole, false)
	if err != nil {
		return 0, err
	}
	if _, statErr := store.root.Lstat(oppositeRelative); statErr == nil {
		return 0, fmt.Errorf("formal-glm: local store contains both authority spools")
	} else if !os.IsNotExist(statErr) {
		return 0, statErr
	}
	removedSpool := 0
	if _, statErr := store.root.Lstat(spoolRelative); statErr == nil {
		encoded, readErr := store.read(spoolRelative)
		if readErr != nil {
			return 0, readErr
		}
		payload, decodeErr := formalGLMPhase21DecodeLocalSpool(
			store, contract, encoded)
		clear(encoded)
		if decodeErr != nil {
			return 0, decodeErr
		}
		role := payload.Role
		formalGLMPhase21ClearLocalSpoolPayload(&payload)
		if role != owner.Role {
			return 0, fmt.Errorf("formal-glm: local spool cleanup role mismatch")
		}
		store.mu.Lock()
		removeErr := store.root.Remove(spoolRelative)
		if removeErr == nil {
			removeErr = formalGLMPhase21RootSyncDir(store.root, spoolRelative)
		}
		store.mu.Unlock()
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return 0, removeErr
		}
		if removeErr == nil {
			removedSpool = 1
		}
	} else if !os.IsNotExist(statErr) {
		return 0, statErr
	}
	store.mu.Lock()
	removeErr := store.root.Remove(ownerRelative)
	if removeErr == nil {
		removeErr = formalGLMPhase21RootSyncDir(store.root, ownerRelative)
	}
	store.mu.Unlock()
	if removeErr != nil && !os.IsNotExist(removeErr) {
		return 0, removeErr
	}
	return removedSpool, nil
}
