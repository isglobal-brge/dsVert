// k2_exact_gc_transport.go -- context-bound encrypted records for exact GC.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

type exactGCRole byte

const (
	exactGCRoleGarbler exactGCRole = iota
	exactGCRoleEvaluator

	exactGCRecordVersion  = 1
	exactGCRecordHeader   = 20
	exactGCRecordMaxPlain = 1 << 20
)

var exactGCRecordMagic = [4]byte{'D', 'G', 'C', '1'}

type exactGCSecureRecordRW struct {
	rw      io.ReadWriter
	send    cipher.AEAD
	recv    cipher.AEAD
	sendTag [4]byte
	recvTag [4]byte
	context [32]byte
	sendDir byte
	recvDir byte
	sendSeq uint64
	recvSeq uint64
	readBuf []byte
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func newExactGCSecureRecordRW(rw io.ReadWriter, session exactGCSession,
	role exactGCRole) (*exactGCSecureRecordRW, error) {

	if rw == nil {
		return nil, fmt.Errorf("exact-gc: nil record channel")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	if role != exactGCRoleGarbler && role != exactGCRoleEvaluator {
		return nil, fmt.Errorf("exact-gc: invalid local role")
	}
	context := exactGCContextDigest(session)
	g2eKey, g2eTag, err := exactGCDeriveRecordKey(session, context, "garbler-to-evaluator")
	if err != nil {
		return nil, err
	}
	e2gKey, e2gTag, err := exactGCDeriveRecordKey(session, context, "evaluator-to-garbler")
	if err != nil {
		return nil, err
	}
	g2e, err := exactGCNewAEAD(g2eKey)
	if err != nil {
		return nil, err
	}
	e2g, err := exactGCNewAEAD(e2gKey)
	if err != nil {
		return nil, err
	}
	result := &exactGCSecureRecordRW{rw: rw, context: context}
	if role == exactGCRoleGarbler {
		result.send, result.recv = g2e, e2g
		result.sendTag, result.recvTag = g2eTag, e2gTag
		result.sendDir, result.recvDir = 0, 1
	} else {
		result.send, result.recv = e2g, g2e
		result.sendTag, result.recvTag = e2gTag, g2eTag
		result.sendDir, result.recvDir = 1, 0
	}
	return result, nil
}

func exactGCDeriveRecordKey(session exactGCSession, context [32]byte,
	direction string) ([]byte, [4]byte, error) {

	info := []byte("dsvert-exact-gc-record-v1\x00" + direction)
	reader := hkdf.New(sha256.New, session.MasterKey[:], context[:], info)
	material := make([]byte, 36)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, [4]byte{}, fmt.Errorf("exact-gc: derive record key: %w", err)
	}
	var tag [4]byte
	copy(tag[:], material[32:])
	return material[:32], tag, nil
}

func exactGCNewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("exact-gc: create record cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("exact-gc: create record AEAD: %w", err)
	}
	return aead, nil
}

func (r *exactGCSecureRecordRW) Write(p []byte) (int, error) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	written := 0
	for len(p) > 0 {
		count := len(p)
		if count > exactGCRecordMaxPlain {
			count = exactGCRecordMaxPlain
		}
		header := r.header(r.sendDir, r.sendSeq, count)
		nonce := exactGCRecordNonce(r.sendTag, r.sendSeq)
		ad := exactGCRecordAD(r.context, header)
		ciphertext := r.send.Seal(nil, nonce[:], p[:count], ad)
		// Publish one authenticated record with one underlying Write. In the
		// segmented spool transport, separate header/ciphertext writes would let
		// the relay observe and forward a transient half-record, needlessly
		// doubling DSI cycles. This atomic framing changes neither ciphertext nor
		// protocol timing and never buffers beyond the public record-size policy.
		record := make([]byte, 0, len(header)+len(ciphertext))
		record = append(record, header...)
		record = append(record, ciphertext...)
		if err := exactGCWriteFull(r.rw, record); err != nil {
			return written, err
		}
		r.sendSeq++
		written += count
		p = p[count:]
	}
	return written, nil
}

func (r *exactGCSecureRecordRW) Read(p []byte) (int, error) {
	r.readMu.Lock()
	defer r.readMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	if len(r.readBuf) == 0 {
		header := make([]byte, exactGCRecordHeader)
		if _, err := io.ReadFull(r.rw, header); err != nil {
			return 0, err
		}
		seq, size, err := r.validateHeader(header)
		if err != nil {
			return 0, err
		}
		ciphertext := make([]byte, size+r.recv.Overhead())
		if _, err := io.ReadFull(r.rw, ciphertext); err != nil {
			return 0, err
		}
		nonce := exactGCRecordNonce(r.recvTag, seq)
		ad := exactGCRecordAD(r.context, header)
		plaintext, err := r.recv.Open(nil, nonce[:], ciphertext, ad)
		if err != nil {
			return 0, fmt.Errorf("exact-gc: record authentication failed")
		}
		r.recvSeq++
		r.readBuf = plaintext
	}
	n := copy(p, r.readBuf)
	r.readBuf = r.readBuf[n:]
	return n, nil
}

func (r *exactGCSecureRecordRW) header(direction byte, seq uint64,
	size int) []byte {
	header := make([]byte, exactGCRecordHeader)
	copy(header[0:4], exactGCRecordMagic[:])
	header[4] = exactGCRecordVersion
	header[5] = direction
	binary.BigEndian.PutUint64(header[8:16], seq)
	binary.BigEndian.PutUint32(header[16:20], uint32(size))
	return header
}

func (r *exactGCSecureRecordRW) validateHeader(header []byte) (uint64, int, error) {
	if len(header) != exactGCRecordHeader ||
		string(header[0:4]) != string(exactGCRecordMagic[:]) ||
		header[4] != exactGCRecordVersion || header[5] != r.recvDir ||
		header[6] != 0 || header[7] != 0 {
		return 0, 0, fmt.Errorf("exact-gc: invalid record header")
	}
	seq := binary.BigEndian.Uint64(header[8:16])
	if seq != r.recvSeq {
		return 0, 0, fmt.Errorf("exact-gc: replayed or out-of-order record")
	}
	size := int(binary.BigEndian.Uint32(header[16:20]))
	if size < 1 || size > exactGCRecordMaxPlain {
		return 0, 0, fmt.Errorf("exact-gc: invalid record size")
	}
	return seq, size, nil
}

func exactGCRecordNonce(tag [4]byte, seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], tag[:])
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func exactGCRecordAD(context [32]byte, header []byte) []byte {
	result := make([]byte, 0, len(context)+len(header))
	result = append(result, context[:]...)
	result = append(result, header...)
	return result
}

func exactGCWriteFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
