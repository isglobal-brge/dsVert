package twopc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
)

// Session authenticates and routes ciphertexts but has no API that reads or
// combines either peer's input or output shares.
type Session struct {
	mu           sync.Mutex
	spec         *linearaccel.CRTSpec
	workload     PublicWorkload
	pinned       map[string]ed25519.PublicKey
	router       *router
	lastMessages []envelope
}

func NewSession(spec *linearaccel.CRTSpec, rows, columns, custodianCount int, bounds linearaccel.PublicBounds, pinned []Identity) (*Session, error) {
	if spec == nil {
		return nil, errors.New("CRT spec cannot be nil")
	}
	if rows < 1 || columns < 1 {
		return nil, errors.New("workload dimensions must be positive")
	}
	if custodianCount < 2 {
		return nil, errors.New("at least two upstream custodians are required")
	}
	if len(pinned) != 2 {
		return nil, fmt.Errorf("exactly two compute-peer identities must be pinned, got %d", len(pinned))
	}
	pinnedKeys := make(map[string]ed25519.PublicKey, 2)
	for _, identity := range pinned {
		if identity.ID == "" || len(identity.VerifyKey) != ed25519.PublicKeySize {
			return nil, errors.New("pinned peer identity is invalid")
		}
		if _, duplicate := pinnedKeys[identity.ID]; duplicate {
			return nil, fmt.Errorf("duplicate pinned peer %q", identity.ID)
		}
		pinnedKeys[identity.ID] = append(ed25519.PublicKey(nil), identity.VerifyKey...)
	}
	pinnedIDs := make([]string, 0, 2)
	for id := range pinnedKeys {
		pinnedIDs = append(pinnedIDs, id)
	}
	sort.Strings(pinnedIDs)
	magnitudeBound, err := deriveMagnitudeBound(rows, columns, bounds)
	if err != nil {
		return nil, err
	}
	boundary, err := spec.NewGCBoundary(magnitudeBound)
	if err != nil {
		return nil, err
	}
	workload := PublicWorkload{
		Rows:           rows,
		Columns:        columns,
		CustodianCount: custodianCount,
		Bounds: linearaccel.PublicBounds{
			X:        new(big.Int).Set(bounds.X),
			Beta:     new(big.Int).Set(bounds.Beta),
			Residual: new(big.Int).Set(bounds.Residual),
		},
		Boundary: boundary,
	}
	workload.Digest = digestWorkload(spec, workload, pinnedIDs, pinnedKeys)
	return &Session{
		spec:     spec,
		workload: workload,
		pinned:   pinnedKeys,
		router:   newRouter(pinnedKeys),
	}, nil
}

func (s *Session) Workload() PublicWorkload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneWorkload(s.workload)
}

func (s *Session) Run(first, second *Peer) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validatePeers(first, second); err != nil {
		return Result{}, err
	}
	var session [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		return Result{}, fmt.Errorf("generate 2PC session ID: %w", err)
	}
	workload := cloneWorkload(s.workload)
	if err := first.beginSession(session, workload); err != nil {
		return Result{}, err
	}
	if err := second.beginSession(session, workload); err != nil {
		return Result{}, err
	}

	var memoryBefore, memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	started := time.Now()
	metrics := Metrics{}
	s.lastMessages = s.lastMessages[:0]
	var sequence uint64
	for lane := range s.spec.Moduli() {
		for _, layer := range []string{LayerXBeta, LayerXtR} {
			if err := s.crossTerm(session, first, second, lane, layer, &sequence, &metrics); err != nil {
				return Result{}, err
			}
			if err := s.crossTerm(session, second, first, lane, layer, &sequence, &metrics); err != nil {
				return Result{}, err
			}
		}
	}
	if err := first.finishSession(session); err != nil {
		return Result{}, err
	}
	if err := second.finishSession(session); err != nil {
		return Result{}, err
	}
	metrics.Wall = time.Since(started)
	runtime.ReadMemStats(&memoryAfter)
	metrics.HeapAllocDeltaBytes = signedDelta(memoryAfter.HeapAlloc, memoryBefore.HeapAlloc)
	metrics.TotalAllocDeltaBytes = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
	metrics.ProcessSysDeltaBytes = signedDelta(memoryAfter.Sys, memoryBefore.Sys)
	return Result{Session: session, Workload: workload, Metrics: metrics}, nil
}

// evaluator contributes X_evaluator; keyHolder contributes beta/r and owns the
// HE key. The key holder keeps the decrypted masked term locally.
func (s *Session) crossTerm(session [32]byte, evaluator, keyHolder *Peer, lane int, layer string, sequence *uint64, metrics *Metrics) error {
	inputCount := s.workload.Columns
	if layer == LayerXtR {
		inputCount = 1
	}
	encryptedInputs := make([][]byte, inputCount)
	for index := 0; index < inputCount; index++ {
		message, err := keyHolder.encryptedInput(session, s.workload.Digest, evaluator.id, lane, layer, index, *sequence)
		if err != nil {
			return err
		}
		want := expectation{
			Session:        session,
			WorkloadDigest: s.workload.Digest,
			Stage:          "cross-input/" + layer,
			Sender:         keyHolder.id,
			Receiver:       evaluator.id,
			Lane:           uint32(lane),
			Index:          uint32(index),
			Sequence:       *sequence,
		}
		payload, err := s.router.accept(message, want)
		if err != nil {
			return fmt.Errorf("route encrypted %s input: %w", layer, err)
		}
		encryptedInputs[index] = payload
		s.lastMessages = append(s.lastMessages, message)
		metrics.EncryptedInputPayloadBytes += uint64(len(message.Payload))
		metrics.EncryptedInputWireBytes += message.wireBytes()
		metrics.MessageCount++
		(*sequence)++
	}

	maskedOutput, err := evaluator.evaluateAndMask(session, s.workload.Digest, keyHolder.id, lane, layer, encryptedInputs, *sequence)
	if err != nil {
		return err
	}
	want := expectation{
		Session:        session,
		WorkloadDigest: s.workload.Digest,
		Stage:          "masked-cross/" + layer,
		Sender:         evaluator.id,
		Receiver:       keyHolder.id,
		Lane:           uint32(lane),
		Index:          0,
		Sequence:       *sequence,
	}
	payload, err := s.router.accept(maskedOutput, want)
	if err != nil {
		return fmt.Errorf("route masked %s output: %w", layer, err)
	}
	if err := keyHolder.acceptMaskedOutput(session, s.workload.Digest, lane, layer, payload); err != nil {
		return err
	}
	s.lastMessages = append(s.lastMessages, maskedOutput)
	metrics.MaskedOutputPayloadBytes += uint64(len(maskedOutput.Payload))
	metrics.MaskedOutputWireBytes += maskedOutput.wireBytes()
	metrics.MessageCount++
	(*sequence)++
	return nil
}

func (s *Session) validatePeers(first, second *Peer) error {
	if first == nil || second == nil || first == second || first.id == second.id {
		return errors.New("session requires two distinct compute peers")
	}
	provided := []*Peer{first, second}
	for _, peer := range provided {
		pinned, exists := s.pinned[peer.id]
		if !exists || !bytes.Equal(pinned, peer.verifyKey) {
			return fmt.Errorf("compute peer %q does not match its pinned identity", peer.id)
		}
		if peer.rows != s.workload.Rows || peer.columns != s.workload.Columns || peer.logN != s.spec.LogN() || len(peer.moduli) != len(s.spec.Moduli()) {
			return fmt.Errorf("compute peer %q does not match the workload", peer.id)
		}
		for lane, modulus := range s.spec.Moduli() {
			if peer.moduli[lane] != modulus {
				return fmt.Errorf("compute peer %q CRT lane %d does not match", peer.id, lane)
			}
		}
	}
	return nil
}

func digestWorkload(spec *linearaccel.CRTSpec, workload PublicWorkload, pinnedIDs []string, pinned map[string]ed25519.PublicKey) [32]byte {
	h := sha256.New()
	writeField(h, []byte("dsvert-lattigo-additive-2pc-workload-v1"))
	var scalar [8]byte
	for _, value := range []uint64{
		uint64(spec.Width()), uint64(spec.LogN()), uint64(workload.Rows),
		uint64(workload.Columns), uint64(workload.CustodianCount), uint64(len(workload.Boundary.Moduli)),
	} {
		binary.BigEndian.PutUint64(scalar[:], value)
		h.Write(scalar[:])
	}
	h.Write(workload.Boundary.Digest[:])
	writeField(h, workload.Bounds.X.Bytes())
	writeField(h, workload.Bounds.Beta.Bytes())
	writeField(h, workload.Bounds.Residual.Bytes())
	for _, id := range pinnedIDs {
		writeField(h, []byte(id))
		writeField(h, pinned[id])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
