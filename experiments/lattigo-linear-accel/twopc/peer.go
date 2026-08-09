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
	"sync"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

type peerLane struct {
	params             bgv.Parameters
	encoder            *bgv.Encoder
	encryptor          *rlwe.Encryptor
	decryptor          *rlwe.Decryptor
	evaluator          *bgv.Evaluator
	maxCiphertextBytes int
}

type peerSession struct {
	workloadDigest [32]byte
	boundary       linearaccel.GCBoundary
	xBeta          [][]uint64
	xTr            [][]uint64
	complete       bool
}

// Peer owns exactly one already-aggregated CRT sharing of X, beta, and r.
// Its input shares and HE decryption keys have no accessor.
type Peer struct {
	mu          sync.Mutex
	id          string
	verifyKey   ed25519.PublicKey
	signingKey  ed25519.PrivateKey
	moduli      []uint64
	logN        int
	input       InputShares
	rows        int
	columns     int
	lanes       []peerLane
	sessions    map[[32]byte]*peerSession
	operations  map[string]struct{}
	maskDigests map[[32]byte]struct{}
}

func NewPeer(id string, spec *linearaccel.CRTSpec, shares InputShares) (*Peer, error) {
	if id == "" {
		return nil, errors.New("peer ID cannot be empty")
	}
	if spec == nil {
		return nil, errors.New("CRT spec cannot be nil")
	}
	rows, columns, err := validateInputShares(spec, shares)
	if err != nil {
		return nil, err
	}
	verifyKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate peer identity: %w", err)
	}
	peer := &Peer{
		id:          id,
		verifyKey:   verifyKey,
		signingKey:  signingKey,
		moduli:      spec.Moduli(),
		logN:        spec.LogN(),
		input:       cloneInputShares(shares),
		rows:        rows,
		columns:     columns,
		lanes:       make([]peerLane, len(spec.Moduli())),
		sessions:    make(map[[32]byte]*peerSession),
		operations:  make(map[string]struct{}),
		maskDigests: make(map[[32]byte]struct{}),
	}
	for lane, modulus := range peer.moduli {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             spec.LogN(),
			LogQ:             []int{50, 40},
			PlaintextModulus: modulus,
		})
		if err != nil {
			return nil, fmt.Errorf("create peer %s BGV lane %d: %w", id, lane, err)
		}
		if rows > params.MaxSlots() || columns > params.MaxSlots() {
			return nil, fmt.Errorf("peer input dimensions exceed %d BGV slots", params.MaxSlots())
		}
		secretKey, publicKey := rlwe.NewKeyGenerator(params).GenKeyPairNew()
		peer.lanes[lane] = peerLane{
			params:             params,
			encoder:            bgv.NewEncoder(params),
			encryptor:          rlwe.NewEncryptor(params, publicKey),
			decryptor:          rlwe.NewDecryptor(params, secretKey),
			evaluator:          bgv.NewEvaluator(params, nil),
			maxCiphertextBytes: bgv.NewCiphertext(params, 1, params.MaxLevel()).BinarySize() + 1024,
		}
	}
	return peer, nil
}

func (p *Peer) Identity() Identity {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Identity{ID: p.id, VerifyKey: append(ed25519.PublicKey(nil), p.verifyKey...)}
}

func (p *Peer) beginSession(session [32]byte, workload PublicWorkload) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rows != workload.Rows || p.columns != workload.Columns {
		return fmt.Errorf("peer %s input dimensions do not match workload", p.id)
	}
	if _, exists := p.sessions[session]; exists {
		return fmt.Errorf("peer %s already initialized session %x", p.id, session)
	}
	state := &peerSession{
		workloadDigest: workload.Digest,
		boundary:       cloneBoundary(workload.Boundary),
		xBeta:          make([][]uint64, len(p.moduli)),
		xTr:            make([][]uint64, len(p.moduli)),
	}
	for lane, modulus := range p.moduli {
		state.xBeta[lane] = make([]uint64, p.rows)
		for row := 0; row < p.rows; row++ {
			for column := 0; column < p.columns; column++ {
				term := mulMod(p.input.X[lane][row][column], p.input.Beta[lane][column], modulus)
				state.xBeta[lane][row] = addMod(state.xBeta[lane][row], term, modulus)
			}
		}
		state.xTr[lane] = make([]uint64, p.columns)
		for column := 0; column < p.columns; column++ {
			for row := 0; row < p.rows; row++ {
				term := mulMod(p.input.X[lane][row][column], p.input.Residual[lane][row], modulus)
				state.xTr[lane][column] = addMod(state.xTr[lane][column], term, modulus)
			}
		}
	}
	p.sessions[session] = state
	return nil
}

func (p *Peer) encryptedInput(session [32]byte, workloadDigest [32]byte, receiver string, lane int, layer string, index int, sequence uint64) (envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.activeSession(session, workloadDigest); err != nil {
		return envelope{}, err
	}
	var scalar uint64
	var outputLength int
	switch layer {
	case LayerXBeta:
		if index < 0 || index >= p.columns {
			return envelope{}, fmt.Errorf("beta index %d is out of range", index)
		}
		scalar, outputLength = p.input.Beta[lane][index], p.rows
	case LayerXtR:
		if index != 0 {
			return envelope{}, fmt.Errorf("packed residual index %d is out of range", index)
		}
		outputLength = p.rows
	default:
		return envelope{}, fmt.Errorf("unknown layer %q", layer)
	}
	values := make([]uint64, outputLength)
	if layer == LayerXtR {
		copy(values, p.input.Residual[lane])
	} else {
		for i := range values {
			values[i] = scalar
		}
	}
	plaintext := bgv.NewPlaintext(p.lanes[lane].params, p.lanes[lane].params.MaxLevel())
	if err := p.lanes[lane].encoder.Encode(values, plaintext); err != nil {
		return envelope{}, fmt.Errorf("encode %s peer input: %w", layer, err)
	}
	ciphertext, err := p.lanes[lane].encryptor.EncryptNew(plaintext)
	if err != nil {
		return envelope{}, fmt.Errorf("encrypt %s peer input: %w", layer, err)
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return envelope{}, fmt.Errorf("marshal %s peer input: %w", layer, err)
	}
	message := envelope{
		Session:        session,
		WorkloadDigest: workloadDigest,
		Stage:          "cross-input/" + layer,
		Sender:         p.id,
		Receiver:       receiver,
		Lane:           uint32(lane),
		Index:          uint32(index),
		Sequence:       sequence,
		Payload:        payload,
	}
	if err := message.sign(p.signingKey); err != nil {
		return envelope{}, err
	}
	return message, nil
}

func (p *Peer) evaluateAndMask(session [32]byte, workloadDigest [32]byte, keyHolder string, lane int, layer string, encryptedScalars [][]byte, sequence uint64) (envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.activeSession(session, workloadDigest); err != nil {
		return envelope{}, err
	}
	expectedInputs := p.columns
	outputLength := p.rows
	if layer == LayerXtR {
		expectedInputs = 1
	} else if layer != LayerXBeta {
		return envelope{}, fmt.Errorf("unknown layer %q", layer)
	}
	if len(encryptedScalars) != expectedInputs {
		return envelope{}, fmt.Errorf("got %d encrypted inputs for %s, want %d", len(encryptedScalars), layer, expectedInputs)
	}

	if layer == LayerXtR {
		return p.evaluateAndMaskPackedXtR(
			session, workloadDigest, keyHolder, lane, encryptedScalars[0], sequence)
	}

	var result *rlwe.Ciphertext
	for index, payload := range encryptedScalars {
		ciphertext, err := p.decodeCiphertext(lane, payload)
		if err != nil {
			return envelope{}, fmt.Errorf("decode encrypted cross input %d: %w", index, err)
		}
		multiplier := make([]uint64, outputLength)
		if layer == LayerXBeta {
			for row := 0; row < p.rows; row++ {
				multiplier[row] = p.input.X[lane][row][index]
			}
		} else {
			copy(multiplier, p.input.X[lane][index])
		}
		term, err := p.lanes[lane].evaluator.MulNew(ciphertext, multiplier)
		if err != nil {
			return envelope{}, fmt.Errorf("evaluate encrypted cross input %d: %w", index, err)
		}
		if result == nil {
			result = term
		} else if err := p.lanes[lane].evaluator.Add(result, term, result); err != nil {
			return envelope{}, fmt.Errorf("sum encrypted cross input %d: %w", index, err)
		}
	}

	mask, err := sampleUniformVector(p.moduli[lane], outputLength)
	if err != nil {
		return envelope{}, err
	}
	operation := fmt.Sprintf("%x/%s/lane-%d/evaluator-%s/keyholder-%s", session, layer, lane, p.id, keyHolder)
	if err := p.registerMask(operation, lane, mask); err != nil {
		return envelope{}, err
	}
	if err := p.addContribution(session, layer, lane, mask); err != nil {
		return envelope{}, err
	}
	if err := p.lanes[lane].evaluator.Sub(result, mask, result); err != nil {
		return envelope{}, fmt.Errorf("mask encrypted cross output: %w", err)
	}
	payload, err := result.MarshalBinary()
	if err != nil {
		return envelope{}, fmt.Errorf("marshal masked cross output: %w", err)
	}
	message := envelope{
		Session:        session,
		WorkloadDigest: workloadDigest,
		Stage:          "masked-cross/" + layer,
		Sender:         p.id,
		Receiver:       keyHolder,
		Lane:           uint32(lane),
		Index:          0,
		Sequence:       sequence,
		Payload:        payload,
	}
	if err := message.sign(p.signingKey); err != nil {
		return envelope{}, err
	}
	return message, nil
}

// Caller holds p.mu. The decrypting peer receives one independently and
// uniformly masked row vector per output column. It may sum each vector, but
// cannot inspect an unmasked row contribution. The evaluator retains only the
// corresponding sums of masks as its additive X^T*r output contribution.
func (p *Peer) evaluateAndMaskPackedXtR(session [32]byte,
	workloadDigest [32]byte, keyHolder string, lane int,
	encryptedResidual []byte, sequence uint64,
) (envelope, error) {
	ciphertext, err := p.decodeCiphertext(lane, encryptedResidual)
	if err != nil {
		return envelope{}, fmt.Errorf("decode packed residual input: %w", err)
	}
	payloads := make([][]byte, p.columns)
	maskSums := make([]uint64, p.columns)
	for column := 0; column < p.columns; column++ {
		multiplier := make([]uint64, p.rows)
		for row := 0; row < p.rows; row++ {
			multiplier[row] = p.input.X[lane][row][column]
		}
		term, err := p.lanes[lane].evaluator.MulNew(ciphertext, multiplier)
		if err != nil {
			return envelope{}, fmt.Errorf("evaluate packed X^T*r column %d: %w", column, err)
		}
		mask, err := sampleUniformVector(p.moduli[lane], p.rows)
		if err != nil {
			return envelope{}, err
		}
		operation := fmt.Sprintf(
			"%x/%s/lane-%d/evaluator-%s/keyholder-%s/column-%d",
			session, LayerXtR, lane, p.id, keyHolder, column)
		if err := p.registerMask(operation, lane, mask); err != nil {
			return envelope{}, err
		}
		for _, value := range mask {
			maskSums[column] = addMod(maskSums[column], value, p.moduli[lane])
		}
		if err := p.lanes[lane].evaluator.Sub(term, mask, term); err != nil {
			return envelope{}, fmt.Errorf("mask packed X^T*r column %d: %w", column, err)
		}
		payloads[column], err = term.MarshalBinary()
		if err != nil {
			return envelope{}, fmt.Errorf("marshal packed X^T*r column %d: %w", column, err)
		}
	}
	if err := p.addContribution(session, LayerXtR, lane, maskSums); err != nil {
		return envelope{}, err
	}
	payload, err := encodeCiphertextBundle(payloads)
	if err != nil {
		return envelope{}, err
	}
	message := envelope{
		Session: session, WorkloadDigest: workloadDigest,
		Stage:  "masked-cross/" + LayerXtR,
		Sender: p.id, Receiver: keyHolder, Lane: uint32(lane),
		Index: 0, Sequence: sequence, Payload: payload,
	}
	if err := message.sign(p.signingKey); err != nil {
		return envelope{}, err
	}
	return message, nil
}

func (p *Peer) acceptMaskedOutput(session [32]byte, workloadDigest [32]byte, lane int, layer string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.activeSession(session, workloadDigest); err != nil {
		return err
	}
	outputLength := p.rows
	if layer == LayerXtR {
		maximumBundleBytes := p.columns*(p.lanes[lane].maxCiphertextBytes+8) +
			len(ciphertextBundleDomain) + 16
		payloads, err := decodeCiphertextBundle(
			payload, p.columns, maximumBundleBytes)
		if err != nil {
			return fmt.Errorf("decode masked packed X^T*r output: %w", err)
		}
		contribution := make([]uint64, p.columns)
		for column, encoded := range payloads {
			ciphertext, err := p.decodeCiphertext(lane, encoded)
			if err != nil {
				return fmt.Errorf("decode masked X^T*r column %d: %w", column, err)
			}
			plaintext := p.lanes[lane].decryptor.DecryptNew(ciphertext)
			decoded := make([]uint64, p.rows)
			if err := p.lanes[lane].encoder.Decode(plaintext, decoded); err != nil {
				return fmt.Errorf("decode masked X^T*r plaintext column %d: %w", column, err)
			}
			for _, value := range decoded {
				contribution[column] = addMod(
					contribution[column], value, p.moduli[lane])
			}
		}
		return p.addContribution(session, layer, lane, contribution)
	} else if layer != LayerXBeta {
		return fmt.Errorf("unknown layer %q", layer)
	}
	ciphertext, err := p.decodeCiphertext(lane, payload)
	if err != nil {
		return fmt.Errorf("decode masked cross output: %w", err)
	}
	plaintext := p.lanes[lane].decryptor.DecryptNew(ciphertext)
	decoded := make([]uint64, outputLength)
	if err := p.lanes[lane].encoder.Decode(plaintext, decoded); err != nil {
		return fmt.Errorf("decode masked plaintext output: %w", err)
	}
	return p.addContribution(session, layer, lane, decoded)
}

func (p *Peer) decodeCiphertext(lane int, payload []byte) (*rlwe.Ciphertext, error) {
	if lane < 0 || lane >= len(p.lanes) {
		return nil, fmt.Errorf("CRT lane %d is out of range", lane)
	}
	if len(payload) == 0 || len(payload) > p.lanes[lane].maxCiphertextBytes {
		return nil, fmt.Errorf("ciphertext payload size %d is outside the accepted range", len(payload))
	}
	ciphertext := new(rlwe.Ciphertext)
	if err := ciphertext.UnmarshalBinary(payload); err != nil {
		return nil, err
	}
	if ciphertext.Degree() != 1 ||
		ciphertext.Level() != p.lanes[lane].params.MaxLevel() ||
		ciphertext.Value[0].N() != p.lanes[lane].params.N() ||
		ciphertext.BinarySize() != len(payload) {
		return nil, errors.New("ciphertext shape does not match the pinned BGV lane")
	}
	return ciphertext, nil
}

func (p *Peer) activeSession(session [32]byte, workloadDigest [32]byte) (*peerSession, error) {
	state, exists := p.sessions[session]
	if !exists || state.workloadDigest != workloadDigest || state.complete {
		return nil, fmt.Errorf("peer %s has no matching active session", p.id)
	}
	return state, nil
}

// Caller holds p.mu.
func (p *Peer) addContribution(session [32]byte, layer string, lane int, values []uint64) error {
	state, exists := p.sessions[session]
	if !exists || state.complete {
		return fmt.Errorf("peer %s has no mutable session output", p.id)
	}
	var output []uint64
	switch layer {
	case LayerXBeta:
		output = state.xBeta[lane]
	case LayerXtR:
		output = state.xTr[lane]
	default:
		return fmt.Errorf("unknown layer %q", layer)
	}
	if len(values) != len(output) {
		return errors.New("cross contribution has an unexpected length")
	}
	for i, value := range values {
		if value >= p.moduli[lane] {
			return fmt.Errorf("cross contribution is not canonical modulo %d", p.moduli[lane])
		}
		output[i] = addMod(output[i], value, p.moduli[lane])
	}
	return nil
}

func (p *Peer) registerMask(operation string, lane int, mask []uint64) error {
	if _, duplicate := p.operations[operation]; duplicate {
		return fmt.Errorf("%w: operation %q", ErrMaskReuse, operation)
	}
	var encoded bytes.Buffer
	writeField(&encoded, []byte("dsvert-lattigo-additive-2pc-mask-v1"))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(lane))
	encoded.Write(scalar[:])
	for _, value := range mask {
		binary.BigEndian.PutUint64(scalar[:], value)
		encoded.Write(scalar[:])
	}
	digest := sha256.Sum256(encoded.Bytes())
	if _, duplicate := p.maskDigests[digest]; duplicate {
		return fmt.Errorf("%w: repeated local mask digest", ErrMaskReuse)
	}
	p.operations[operation] = struct{}{}
	p.maskDigests[digest] = struct{}{}
	return nil
}

func (p *Peer) finishSession(session [32]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, exists := p.sessions[session]
	if !exists || state.complete {
		return fmt.Errorf("peer %s cannot complete session", p.id)
	}
	state.complete = true
	return nil
}

// Output exports only this peer's additive result for the subsequent GC/MPC
// boundary. It never exposes the peer's input shares or decryption key.
func (p *Peer) Output(result Result, layer string) (PartyOutput, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state, exists := p.sessions[result.Session]
	if !exists || !state.complete || state.workloadDigest != result.Workload.Digest {
		return PartyOutput{}, fmt.Errorf("peer %s has no completed matching session", p.id)
	}
	var source [][]uint64
	switch layer {
	case LayerXBeta:
		source = state.xBeta
	case LayerXtR:
		source = state.xTr
	default:
		return PartyOutput{}, fmt.Errorf("unknown layer %q", layer)
	}
	shares := make([][]uint64, len(source))
	for lane := range source {
		shares[lane] = append([]uint64(nil), source[lane]...)
	}
	return PartyOutput{
		PartyID:         p.id,
		Session:         result.Session,
		Layer:           layer,
		Boundary:        cloneBoundary(state.boundary),
		SharesByModulus: shares,
	}, nil
}

func sampleUniformVector(modulus uint64, count int) ([]uint64, error) {
	values := make([]uint64, count)
	upper := new(big.Int).SetUint64(modulus)
	for i := range values {
		value, err := rand.Int(rand.Reader, upper)
		if err != nil {
			return nil, fmt.Errorf("sample uniform cross-term mask: %w", err)
		}
		values[i] = value.Uint64()
	}
	return values, nil
}
