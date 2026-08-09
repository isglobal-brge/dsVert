package linearaccel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrBadSignature = errors.New("invalid authenticated share envelope")
	ErrReplay       = errors.New("replayed share envelope")
	ErrTranscript   = errors.New("share envelope does not match the expected transcript")
	ErrMaskReuse    = errors.New("output mask reuse detected")
)

type shareEnvelope struct {
	Session        [32]byte
	BoundaryDigest [32]byte
	CiphertextHash [32]byte
	Stage          string
	Sender         string
	Lane           uint32
	Output         uint32
	Sequence       uint64
	Payload        []byte
	Signature      []byte
}

func (e shareEnvelope) signingBytes() []byte {
	var buf bytes.Buffer
	writeBytes(&buf, []byte("dsvert-lattigo-linear-share-envelope-v1"))
	buf.Write(e.Session[:])
	buf.Write(e.BoundaryDigest[:])
	buf.Write(e.CiphertextHash[:])
	writeBytes(&buf, []byte(e.Stage))
	writeBytes(&buf, []byte(e.Sender))
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], e.Lane)
	buf.Write(scalar[:4])
	binary.BigEndian.PutUint32(scalar[:4], e.Output)
	buf.Write(scalar[:4])
	binary.BigEndian.PutUint64(scalar[:], e.Sequence)
	buf.Write(scalar[:])
	writeBytes(&buf, e.Payload)
	return buf.Bytes()
}

func (e shareEnvelope) binarySize() int {
	return len(e.signingBytes()) + 8 + len(e.Signature)
}

type envelopeExpectation struct {
	Session        [32]byte
	BoundaryDigest [32]byte
	CiphertextHash [32]byte
	Stage          string
	Sender         string
	Lane           uint32
	Output         uint32
	Sequence       uint64
}

type authenticatedRelay struct {
	mu       sync.Mutex
	peers    map[string]ed25519.PublicKey
	accepted map[[32]byte]struct{}
}

func newAuthenticatedRelay(peers map[string]ed25519.PublicKey) *authenticatedRelay {
	copyPeers := make(map[string]ed25519.PublicKey, len(peers))
	for id, key := range peers {
		copyPeers[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &authenticatedRelay{peers: copyPeers, accepted: make(map[[32]byte]struct{})}
}

func (r *authenticatedRelay) accept(e shareEnvelope, want envelopeExpectation) ([]byte, error) {
	key, ok := r.peers[e.Sender]
	if !ok || !ed25519.Verify(key, e.signingBytes(), e.Signature) {
		return nil, ErrBadSignature
	}
	if e.Session != want.Session ||
		e.BoundaryDigest != want.BoundaryDigest ||
		e.CiphertextHash != want.CiphertextHash ||
		e.Stage != want.Stage ||
		e.Sender != want.Sender ||
		e.Lane != want.Lane ||
		e.Output != want.Output ||
		e.Sequence != want.Sequence {
		return nil, ErrTranscript
	}

	messageID := sha256.Sum256(e.signingBytes())
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.accepted[messageID]; duplicate {
		return nil, ErrReplay
	}
	r.accepted[messageID] = struct{}{}
	return append([]byte(nil), e.Payload...), nil
}

func signEnvelope(privateKey ed25519.PrivateKey, e *shareEnvelope) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key length %d", len(privateKey))
	}
	e.Signature = ed25519.Sign(privateKey, e.signingBytes())
	return nil
}
