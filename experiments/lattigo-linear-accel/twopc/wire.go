package twopc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const ciphertextBundleDomain = "dsvert-lattigo-additive-2pc-ciphertext-bundle-v1"

type envelope struct {
	Session        [32]byte
	WorkloadDigest [32]byte
	Stage          string
	Sender         string
	Receiver       string
	Lane           uint32
	Index          uint32
	Sequence       uint64
	Payload        []byte
	Signature      []byte
}

func (e envelope) signingBytes() []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("dsvert-lattigo-additive-2pc-envelope-v1"))
	buf.Write(e.Session[:])
	buf.Write(e.WorkloadDigest[:])
	writeField(&buf, []byte(e.Stage))
	writeField(&buf, []byte(e.Sender))
	writeField(&buf, []byte(e.Receiver))
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], e.Lane)
	buf.Write(scalar[:4])
	binary.BigEndian.PutUint32(scalar[:4], e.Index)
	buf.Write(scalar[:4])
	binary.BigEndian.PutUint64(scalar[:], e.Sequence)
	buf.Write(scalar[:])
	writeField(&buf, e.Payload)
	return buf.Bytes()
}

func (e envelope) wireBytes() uint64 {
	return uint64(len(e.signingBytes()) + 8 + len(e.Signature))
}

func (e *envelope) sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key length %d", len(privateKey))
	}
	e.Signature = ed25519.Sign(privateKey, e.signingBytes())
	return nil
}

type expectation struct {
	Session        [32]byte
	WorkloadDigest [32]byte
	Stage          string
	Sender         string
	Receiver       string
	Lane           uint32
	Index          uint32
	Sequence       uint64
}

type router struct {
	mu       sync.Mutex
	pinned   map[string]ed25519.PublicKey
	accepted map[[32]byte]struct{}
}

func newRouter(pinned map[string]ed25519.PublicKey) *router {
	keys := make(map[string]ed25519.PublicKey, len(pinned))
	for id, key := range pinned {
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &router{pinned: keys, accepted: make(map[[32]byte]struct{})}
}

func (r *router) accept(message envelope, want expectation) ([]byte, error) {
	key, known := r.pinned[message.Sender]
	if !known || !ed25519.Verify(key, message.signingBytes(), message.Signature) {
		return nil, ErrAuthentication
	}
	if message.Session != want.Session ||
		message.WorkloadDigest != want.WorkloadDigest ||
		message.Stage != want.Stage ||
		message.Sender != want.Sender ||
		message.Receiver != want.Receiver ||
		message.Lane != want.Lane ||
		message.Index != want.Index ||
		message.Sequence != want.Sequence {
		return nil, ErrTranscript
	}

	messageID := sha256.Sum256(message.signingBytes())
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, duplicate := r.accepted[messageID]; duplicate {
		return nil, ErrReplay
	}
	r.accepted[messageID] = struct{}{}
	return append([]byte(nil), message.Payload...), nil
}

func writeField(writer io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func encodeCiphertextBundle(payloads [][]byte) ([]byte, error) {
	if len(payloads) < 1 || uint64(len(payloads)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("invalid ciphertext bundle count %d", len(payloads))
	}
	var encoded bytes.Buffer
	writeField(&encoded, []byte(ciphertextBundleDomain))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(payloads)))
	encoded.Write(count[:])
	for index, payload := range payloads {
		if len(payload) == 0 {
			return nil, fmt.Errorf("ciphertext bundle item %d is empty", index)
		}
		writeField(&encoded, payload)
	}
	return encoded.Bytes(), nil
}

func decodeCiphertextBundle(encoded []byte, expectedCount, maximumBytes int) ([][]byte, error) {
	if expectedCount < 1 || maximumBytes < 1 || len(encoded) == 0 ||
		len(encoded) > maximumBytes {
		return nil, fmt.Errorf("ciphertext bundle size %d is outside the accepted range", len(encoded))
	}
	reader := bytes.NewReader(encoded)
	readField := func(maximum int) ([]byte, error) {
		var size [8]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint64(size[:])
		if length == 0 || length > uint64(maximum) || length > uint64(reader.Len()) {
			return nil, fmt.Errorf("invalid ciphertext bundle field length %d", length)
		}
		value := make([]byte, int(length))
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		return value, nil
	}
	domain, err := readField(len(ciphertextBundleDomain))
	if err != nil || string(domain) != ciphertextBundleDomain {
		return nil, errors.New("invalid ciphertext bundle domain")
	}
	var countBytes [4]byte
	if _, err := io.ReadFull(reader, countBytes[:]); err != nil {
		return nil, errors.New("truncated ciphertext bundle count")
	}
	count := int(binary.BigEndian.Uint32(countBytes[:]))
	if count != expectedCount {
		return nil, fmt.Errorf("ciphertext bundle count %d, want %d", count, expectedCount)
	}
	payloads := make([][]byte, count)
	for index := range payloads {
		payloads[index], err = readField(maximumBytes)
		if err != nil {
			return nil, fmt.Errorf("decode ciphertext bundle item %d: %w", index, err)
		}
	}
	if reader.Len() != 0 {
		return nil, errors.New("ciphertext bundle has trailing bytes")
	}
	return payloads, nil
}
