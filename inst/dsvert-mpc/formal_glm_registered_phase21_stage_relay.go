package main

// The Phase21 sampler owns its exact-GC spool.  This relay only moves the
// already-encrypted spool records between the two designated authorities; it
// neither opens a second spool nor sees a local output share.  Each consumed
// range is acknowledged with the recipient's pinned signature before the
// sender can reclaim it.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	formalGLMRegisteredPhase21StageRelayVersionV1    = "dsvert-formal-glm-registered-phase21-stage-relay-v1"
	formalGLMRegisteredPhase21StageRelayPurposeV1    = "formal_glm_registered_phase21_stage_relay_v1"
	formalGLMRegisteredPhase21StageRelayDomainV1     = "dsVert/formal-glm/registered-phase21/stage-relay/v1"
	formalGLMRegisteredPhase21StageRelayMaxPayloadV1 = 1 << 20
)

type formalGLMRegisteredPhase21StageRelayConfigV1 struct {
	ArtifactID string
	LocalPeer  string
	Peer       string
	SpoolDir   string
	Signing    ed25519.PrivateKey
	Pins       map[string]ed25519.PublicKey
}

type formalGLMRegisteredPhase21StageRelayChunkV1 struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	ArtifactID      string `json:"artifact_id"`
	SenderPeer      string `json:"sender_peer"`
	RecipientPeer   string `json:"recipient_peer"`
	Start           int64  `json:"start"`
	End             int64  `json:"end"`
	PayloadSHA256   string `json:"payload_sha256"`
	Payload         []byte `json:"payload"`
	ProductionReady bool   `json:"production_ready"`
}

type formalGLMRegisteredPhase21StageRelayAckV1 struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	ArtifactID      string `json:"artifact_id"`
	SenderPeer      string `json:"sender_peer"`
	RecipientPeer   string `json:"recipient_peer"`
	Start           int64  `json:"start"`
	End             int64  `json:"end"`
	PayloadSHA256   string `json:"payload_sha256"`
	ProductionReady bool   `json:"production_ready"`
	Signature       []byte `json:"signature"`
}

// Fields are private so this is never a command DTO.  The public boundary
// carries only a Chunk or an Ack, both independently bound to the artifact
// and the two pinned peers.
type formalGLMRegisteredPhase21StageRelayV1 struct {
	mu sync.Mutex

	artifactID string
	localPeer  string
	peer       string
	spoolDir   string
	signing    ed25519.PrivateKey
	pins       map[string]ed25519.PublicKey
	closed     bool
}

func formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func formalGLMRegisteredPhase21StageRelayMessageV1(
	ack formalGLMRegisteredPhase21StageRelayAckV1,
) ([]byte, error) {
	ack.Signature = nil
	encoded, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}
	return append([]byte(formalGLMRegisteredPhase21StageRelayDomainV1+"/ack|"), encoded...), nil
}

func formalGLMRegisteredPhase21StageRelayValidPeerV1(peer string) bool {
	return formalGLMRegistryLabelV1(peer, 128)
}

func formalGLMRegisteredPhase21StageRelayPrivateDirectoryV1(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o700 && formalFinalizerHandoffPrivateOwnedDirectory(info)
}

func formalGLMRegisteredPhase21StageRelayPrivateFileV1(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 && exactGCPrivateOwnedRegular(info)
}

func newFormalGLMRegisteredPhase21StageRelayV1(
	config formalGLMRegisteredPhase21StageRelayConfigV1,
) (*formalGLMRegisteredPhase21StageRelayV1, error) {
	if !formalGLMIsSHA256(config.ArtifactID) ||
		!formalGLMRegisteredPhase21StageRelayValidPeerV1(config.LocalPeer) ||
		!formalGLMRegisteredPhase21StageRelayValidPeerV1(config.Peer) ||
		config.LocalPeer == config.Peer || !filepath.IsAbs(config.SpoolDir) ||
		filepath.Clean(config.SpoolDir) != config.SpoolDir ||
		len(config.Signing) != ed25519.PrivateKeySize ||
		len(config.Pins) != 2 || len(config.Pins[config.LocalPeer]) != ed25519.PublicKeySize ||
		len(config.Pins[config.Peer]) != ed25519.PublicKeySize ||
		!bytes.Equal(config.Signing.Public().(ed25519.PublicKey), config.Pins[config.LocalPeer]) ||
		!formalGLMRegisteredPhase21StageRelayPrivateDirectoryV1(config.SpoolDir) {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid local spool")
	}
	for _, name := range []string{"inbound.segments", "outbound.segments"} {
		if !formalGLMRegisteredPhase21StageRelayPrivateDirectoryV1(filepath.Join(config.SpoolDir, name)) {
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid spool directory")
		}
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack", "exchange.hb"} {
		if !formalGLMRegisteredPhase21StageRelayPrivateFileV1(filepath.Join(config.SpoolDir, name)) {
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid spool state")
		}
	}
	for _, name := range []string{"inbound.ack", "outbound.head", "outbound.ack"} {
		if _, err := exactGCReadOffset(filepath.Join(config.SpoolDir, name)); err != nil {
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid spool offset")
		}
	}
	pins := make(map[string]ed25519.PublicKey, len(config.Pins))
	for peer, pin := range config.Pins {
		pins[peer] = append(ed25519.PublicKey(nil), pin...)
	}
	return &formalGLMRegisteredPhase21StageRelayV1{
		artifactID: config.ArtifactID, localPeer: config.LocalPeer, peer: config.Peer,
		spoolDir: config.SpoolDir, signing: append(ed25519.PrivateKey(nil), config.Signing...),
		pins: pins,
	}, nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) clearLockedV1() {
	clear(relay.signing)
	relay.signing = nil
	for peer, pin := range relay.pins {
		clear(pin)
		delete(relay.pins, peer)
	}
	relay.pins = nil
	relay.artifactID, relay.localPeer, relay.peer, relay.spoolDir = "", "", "", ""
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) Close() {
	if relay == nil {
		return
	}
	relay.mu.Lock()
	if !relay.closed {
		relay.closed = true
		relay.clearLockedV1()
	}
	relay.mu.Unlock()
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) readyLockedV1() error {
	if relay == nil || relay.closed || len(relay.signing) != ed25519.PrivateKeySize ||
		!formalGLMRegisteredPhase21StageRelayPrivateDirectoryV1(relay.spoolDir) {
		return fmt.Errorf("formal-glm registered Phase21 stage relay: unavailable")
	}
	return nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) touchLockedV1() error {
	path := filepath.Join(relay.spoolDir, "exchange.hb")
	if !formalGLMRegisteredPhase21StageRelayPrivateFileV1(path) {
		return fmt.Errorf("formal-glm registered Phase21 stage relay: unsafe heartbeat")
	}
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil ||
		!formalGLMRegisteredPhase21StageRelayPrivateFileV1(path) {
		return fmt.Errorf("formal-glm registered Phase21 stage relay: heartbeat unavailable")
	}
	return nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) validateAckLockedV1(
	ack formalGLMRegisteredPhase21StageRelayAckV1,
) error {
	if ack.Version != formalGLMRegisteredPhase21StageRelayVersionV1 ||
		ack.Purpose != formalGLMRegisteredPhase21StageRelayPurposeV1 ||
		ack.ArtifactID != relay.artifactID || ack.SenderPeer != relay.peer ||
		ack.RecipientPeer != relay.localPeer || ack.Start < 0 || ack.End <= ack.Start ||
		ack.End > exactGCMaxAbsoluteOffset || !formalGLMIsSHA256(ack.PayloadSHA256) ||
		ack.ProductionReady || len(ack.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("formal-glm registered Phase21 stage relay: invalid acknowledgement")
	}
	message, err := formalGLMRegisteredPhase21StageRelayMessageV1(ack)
	if err != nil {
		return err
	}
	defer clear(message)
	if !ed25519.Verify(relay.pins[relay.peer], message, ack.Signature) {
		return fmt.Errorf("formal-glm registered Phase21 stage relay: invalid acknowledgement")
	}
	return nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) signAckLockedV1(
	chunk formalGLMRegisteredPhase21StageRelayChunkV1,
) (formalGLMRegisteredPhase21StageRelayAckV1, error) {
	ack := formalGLMRegisteredPhase21StageRelayAckV1{
		Version:    formalGLMRegisteredPhase21StageRelayVersionV1,
		Purpose:    formalGLMRegisteredPhase21StageRelayPurposeV1,
		ArtifactID: relay.artifactID, SenderPeer: relay.localPeer, RecipientPeer: relay.peer,
		Start: chunk.Start, End: chunk.End, PayloadSHA256: chunk.PayloadSHA256,
		ProductionReady: false,
	}
	message, err := formalGLMRegisteredPhase21StageRelayMessageV1(ack)
	if err != nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{}, err
	}
	ack.Signature = ed25519.Sign(relay.signing, message)
	clear(message)
	return ack, nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) readOutboundRangeLockedV1(
	start, end int64,
) ([]byte, error) {
	if start < 0 || end <= start || end-start > formalGLMRegisteredPhase21StageRelayMaxPayloadV1 {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid outbound range")
	}
	segments, err := exactGCListSegments(filepath.Join(relay.spoolDir, "outbound.segments"))
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, end-start)
	cursor := start
	for cursor < end {
		var selected *exactGCSegment
		for index := range segments {
			if segments[index].start <= cursor && segments[index].end > cursor {
				selected = &segments[index]
				break
			}
		}
		if selected == nil {
			clear(data)
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: outbound gap")
		}
		file, openErr := exactGCOpenVerifiedSegment(*selected)
		if openErr != nil {
			clear(data)
			return nil, openErr
		}
		limit := selected.end
		if limit > end {
			limit = end
		}
		part := make([]byte, limit-cursor)
		read, readErr := file.ReadAt(part, cursor-selected.start)
		closeErr := file.Close()
		if read != len(part) || readErr != nil && readErr != io.EOF || closeErr != nil {
			clear(part)
			clear(data)
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: outbound read failed")
		}
		data = append(data, part...)
		clear(part)
		cursor = limit
	}
	return data, nil
}

func (relay *formalGLMRegisteredPhase21StageRelayV1) cleanupOutboundLockedV1(through int64) error {
	segments, err := exactGCListSegments(filepath.Join(relay.spoolDir, "outbound.segments"))
	if err != nil {
		return err
	}
	changed := false
	for _, segment := range segments {
		if segment.end <= through {
			if err := os.Remove(segment.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			changed = true
		}
	}
	if changed {
		return exactGCSyncDir(filepath.Join(relay.spoolDir, "outbound.segments"))
	}
	return nil
}

// PollV1 first accepts an optional signed receipt for the prior chunk, then
// returns the next bounded encrypted range. A nil result means that the local
// sampler has not published another range yet.
func (relay *formalGLMRegisteredPhase21StageRelayV1) PollV1(
	acknowledgement *formalGLMRegisteredPhase21StageRelayAckV1,
) (*formalGLMRegisteredPhase21StageRelayChunkV1, error) {
	if relay == nil {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: unavailable")
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if err := relay.readyLockedV1(); err != nil {
		return nil, err
	}
	ackPath := filepath.Join(relay.spoolDir, "outbound.ack")
	if acknowledgement != nil {
		if err := relay.validateAckLockedV1(*acknowledgement); err != nil {
			return nil, err
		}
		current, err := exactGCReadOffset(ackPath)
		if err != nil || acknowledgement.Start != current {
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: acknowledgement out of order")
		}
		payload, err := relay.readOutboundRangeLockedV1(acknowledgement.Start, acknowledgement.End)
		if err != nil || formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(payload) != acknowledgement.PayloadSHA256 {
			clear(payload)
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: acknowledgement mismatched")
		}
		clear(payload)
		if err := exactGCWriteOffset(ackPath, acknowledgement.End); err != nil ||
			relay.cleanupOutboundLockedV1(acknowledgement.End) != nil {
			return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: acknowledgement commit failed")
		}
	}
	start, err := exactGCReadOffset(ackPath)
	head, headErr := exactGCReadOffset(filepath.Join(relay.spoolDir, "outbound.head"))
	if err != nil || headErr != nil || head < start {
		return nil, fmt.Errorf("formal-glm registered Phase21 stage relay: invalid outbound cursor")
	}
	if head == start {
		if err := relay.touchLockedV1(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	end := start + formalGLMRegisteredPhase21StageRelayMaxPayloadV1
	if end > head {
		end = head
	}
	payload, err := relay.readOutboundRangeLockedV1(start, end)
	if err != nil {
		return nil, err
	}
	if err := relay.touchLockedV1(); err != nil {
		clear(payload)
		return nil, err
	}
	return &formalGLMRegisteredPhase21StageRelayChunkV1{
		Version:    formalGLMRegisteredPhase21StageRelayVersionV1,
		Purpose:    formalGLMRegisteredPhase21StageRelayPurposeV1,
		ArtifactID: relay.artifactID, SenderPeer: relay.localPeer, RecipientPeer: relay.peer,
		Start: start, End: end,
		PayloadSHA256: formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(payload),
		Payload:       payload, ProductionReady: false,
	}, nil
}

// RelayV1 accepts the peer's next contiguous encrypted range and returns a
// signed receipt. Replays that the sampler has already consumed are harmless;
// gaps and overlaps fail closed.
func (relay *formalGLMRegisteredPhase21StageRelayV1) RelayV1(
	chunk formalGLMRegisteredPhase21StageRelayChunkV1,
) (formalGLMRegisteredPhase21StageRelayAckV1, error) {
	if relay == nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{},
			fmt.Errorf("formal-glm registered Phase21 stage relay: unavailable")
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if err := relay.readyLockedV1(); err != nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{}, err
	}
	if chunk.Version != formalGLMRegisteredPhase21StageRelayVersionV1 ||
		chunk.Purpose != formalGLMRegisteredPhase21StageRelayPurposeV1 ||
		chunk.ArtifactID != relay.artifactID || chunk.SenderPeer != relay.peer ||
		chunk.RecipientPeer != relay.localPeer || chunk.Start < 0 || chunk.End <= chunk.Start ||
		chunk.End-chunk.Start != int64(len(chunk.Payload)) ||
		len(chunk.Payload) > formalGLMRegisteredPhase21StageRelayMaxPayloadV1 ||
		chunk.PayloadSHA256 != formalGLMRegisteredPhase21StageRelayPayloadSHA256V1(chunk.Payload) ||
		chunk.ProductionReady {
		return formalGLMRegisteredPhase21StageRelayAckV1{},
			fmt.Errorf("formal-glm registered Phase21 stage relay: invalid inbound chunk")
	}
	inboundAck, err := exactGCReadOffset(filepath.Join(relay.spoolDir, "inbound.ack"))
	if err != nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{}, err
	}
	if chunk.End > inboundAck {
		if chunk.Start != inboundAck {
			return formalGLMRegisteredPhase21StageRelayAckV1{},
				fmt.Errorf("formal-glm registered Phase21 stage relay: inbound chunk out of order")
		}
		if _, err := exactGCPublishSegment(
			filepath.Join(relay.spoolDir, "inbound.segments"), chunk.Start, chunk.Payload); err != nil {
			return formalGLMRegisteredPhase21StageRelayAckV1{}, err
		}
	}
	if err := relay.touchLockedV1(); err != nil {
		return formalGLMRegisteredPhase21StageRelayAckV1{}, err
	}
	return relay.signAckLockedV1(chunk)
}
