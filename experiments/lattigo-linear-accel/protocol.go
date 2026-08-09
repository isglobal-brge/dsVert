package linearaccel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	experimentLogN = 12
	layerXBeta     = "x_beta"
	layerXtR       = "xt_r"
)

// PublicBounds are server-authoritative absolute contribution bounds. The
// simulation checks its fixture against them; a real deployment would need
// local validation or range proofs at each custodian.
type PublicBounds struct {
	X        *big.Int
	Beta     *big.Int
	Residual *big.Int
}

// LinearInput is a test fixture for the two exact integer linear layers. X is
// row-major. Values are never converted through float64 or int64.
type LinearInput struct {
	X        [][]*big.Int
	Beta     []*big.Int
	Residual []*big.Int
	Bounds   PublicBounds
}

// RunMetrics records byte counts and process-memory deltas for the spike. CPU
// time and allocations are reported more reliably by Go benchmarks.
type RunMetrics struct {
	Wall                   time.Duration
	InputCiphertextBytes   uint64
	OutputCiphertextBytes  uint64
	PublicShareBytes       uint64
	SignedEnvelopeBytes    uint64
	SetupPublicBytes       uint64
	HeapAllocDeltaBytes    int64
	TotalAllocDeltaBytes   uint64
	ProcessSysDeltaBytes   int64
	PlaintextCRTSlots      int
	CollectiveComputeRoles int
}

type RunResult struct {
	Session  [32]byte
	Boundary GCBoundary
	Rows     int
	Columns  int
	Metrics  RunMetrics
}

// GCPartyInput is one role's additive CRT share vector. It is intentionally
// still in independent residues: only a future exact GC may combine roles,
// reconstruct CRT, and apply the signed rule in Boundary.
type GCPartyInput struct {
	PartyID         string
	Session         [32]byte
	Layer           string
	Boundary        GCBoundary
	SharesByModulus [][]uint64
}

type outputKey struct {
	session [32]byte
	layer   string
	lane    int
}

type computeRole struct {
	id         string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	secretKeys []*rlwe.SecretKey
	e2s        []*mpbgv.EncToShareProtocol
	encoders   []*bgv.Encoder
	encryptors []*rlwe.Encryptor
	outputs    map[outputKey][]uint64
	operations map[string]struct{}
	maskHashes map[[32]byte]struct{}
}

func (r *computeRole) registerMask(operation string, encodedMask []byte) error {
	if _, exists := r.operations[operation]; exists {
		return fmt.Errorf("%w: operation %q was already generated", ErrMaskReuse, operation)
	}
	hash := sha256.Sum256(encodedMask)
	if _, exists := r.maskHashes[hash]; exists {
		return fmt.Errorf("%w: repeated local mask digest", ErrMaskReuse)
	}
	r.operations[operation] = struct{}{}
	r.maskHashes[hash] = struct{}{}
	return nil
}

type bgvLane struct {
	modulus   uint64
	params    bgv.Parameters
	evaluator *bgv.Evaluator
}

// Experiment is a logically separated N-out-of-N BGV simulation. Secret-key
// shares and output masks remain inside computeRole objects. The harness runs
// in one process, so it is not an OS-isolation claim.
type Experiment struct {
	mu               sync.Mutex
	spec             *CRTSpec
	roles            []*computeRole
	lanes            []bgvLane
	relay            *authenticatedRelay
	setupPublicBytes uint64
	lastEnvelopes    []shareEnvelope
	sessions         map[[32]byte]GCBoundary
}

// NewExperiment builds fresh, independent collective keys for every CRT lane.
// The parameter set is experimental and has not received a production security
// review; it is deliberately isolated from dsVert's package and binaries.
func NewExperiment(width SignedWidth, roleCount int) (*Experiment, error) {
	if roleCount < 2 {
		return nil, fmt.Errorf("at least two collective compute roles are required")
	}
	spec, err := NewCRTSpec(width, experimentLogN)
	if err != nil {
		return nil, err
	}

	experiment := &Experiment{
		spec:     spec,
		roles:    make([]*computeRole, roleCount),
		lanes:    make([]bgvLane, len(spec.moduli)),
		sessions: make(map[[32]byte]GCBoundary),
	}
	peerKeys := make(map[string]ed25519.PublicKey, roleCount)
	for i := range experiment.roles {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate role identity: %w", err)
		}
		role := &computeRole{
			id:         fmt.Sprintf("compute-%d", i+1),
			publicKey:  publicKey,
			privateKey: privateKey,
			secretKeys: make([]*rlwe.SecretKey, len(spec.moduli)),
			e2s:        make([]*mpbgv.EncToShareProtocol, len(spec.moduli)),
			encoders:   make([]*bgv.Encoder, len(spec.moduli)),
			encryptors: make([]*rlwe.Encryptor, len(spec.moduli)),
			outputs:    make(map[outputKey][]uint64),
			operations: make(map[string]struct{}),
			maskHashes: make(map[[32]byte]struct{}),
		}
		experiment.roles[i] = role
		peerKeys[role.id] = publicKey
	}
	experiment.relay = newAuthenticatedRelay(peerKeys)

	for laneIndex, modulus := range spec.moduli {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             experimentLogN,
			LogQ:             []int{50, 40},
			PlaintextModulus: modulus,
		})
		if err != nil {
			return nil, fmt.Errorf("create BGV lane %d: %w", laneIndex, err)
		}
		keyGenerator := rlwe.NewKeyGenerator(params)
		for _, role := range experiment.roles {
			role.secretKeys[laneIndex] = keyGenerator.GenSecretKeyNew()
		}

		ckg := multiparty.NewPublicKeyGenProtocol(params)
		seed := sha256.Sum256([]byte(fmt.Sprintf("dsvert-lattigo-linear-crs-v1/lane/%d/modulus/%d", laneIndex, modulus)))
		crs, err := sampling.NewKeyedPRNG(seed[:])
		if err != nil {
			return nil, fmt.Errorf("create lane CRS: %w", err)
		}
		crp := ckg.SampleCRP(crs)
		combined := ckg.AllocateShare()
		for _, role := range experiment.roles {
			share := ckg.AllocateShare()
			ckg.GenShare(role.secretKeys[laneIndex], crp, &share)
			encoded, err := share.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("measure collective-key share: %w", err)
			}
			experiment.setupPublicBytes += uint64(len(encoded))
			ckg.AggregateShares(combined, share, &combined)
		}
		collectivePublicKey := rlwe.NewPublicKey(params)
		ckg.GenPublicKey(combined, crp, collectivePublicKey)
		encodedPK, err := collectivePublicKey.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("measure collective public key: %w", err)
		}
		experiment.setupPublicBytes += uint64(len(encodedPK))

		for _, role := range experiment.roles {
			protocol, err := mpbgv.NewEncToShareProtocol(params, params.Xe())
			if err != nil {
				return nil, fmt.Errorf("create EncToShare role %s lane %d: %w", role.id, laneIndex, err)
			}
			role.e2s[laneIndex] = &protocol
			role.encoders[laneIndex] = bgv.NewEncoder(params)
			role.encryptors[laneIndex] = rlwe.NewEncryptor(params, collectivePublicKey)
		}
		experiment.lanes[laneIndex] = bgvLane{
			modulus:   modulus,
			params:    params,
			evaluator: bgv.NewEvaluator(params, nil),
		}
	}
	return experiment, nil
}

func (e *Experiment) PartyIDs() []string {
	ids := make([]string, len(e.roles))
	for i, role := range e.roles {
		ids[i] = role.id
	}
	return ids
}

func (e *Experiment) Spec() *CRTSpec { return e.spec }

// Run evaluates X*beta and X^T*r independently in every CRT lane, then invokes
// EncToShare before any output decoding. It returns metadata only.
func (e *Experiment) Run(input LinearInput) (RunResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rows, columns, magnitudeBound, err := validateLinearInput(input, e.spec, e.lanes[0].params.MaxSlots())
	if err != nil {
		return RunResult{}, err
	}
	boundary, err := e.spec.NewGCBoundary(magnitudeBound)
	if err != nil {
		return RunResult{}, err
	}
	var session [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		return RunResult{}, fmt.Errorf("generate session identifier: %w", err)
	}

	var memoryBefore, memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	started := time.Now()
	metrics := RunMetrics{
		SetupPublicBytes:       e.setupPublicBytes,
		PlaintextCRTSlots:      len(e.spec.moduli),
		CollectiveComputeRoles: len(e.roles),
	}
	e.lastEnvelopes = e.lastEnvelopes[:0]

	for laneIndex := range e.lanes {
		xBeta, inputBytes, err := e.evaluateXBeta(laneIndex, input, rows, columns)
		if err != nil {
			return RunResult{}, fmt.Errorf("evaluate X*beta in CRT lane %d: %w", laneIndex, err)
		}
		metrics.InputCiphertextBytes += inputBytes
		xTr, inputBytes, err := e.evaluateXtR(laneIndex, input, rows, columns)
		if err != nil {
			return RunResult{}, fmt.Errorf("evaluate X^T*r in CRT lane %d: %w", laneIndex, err)
		}
		metrics.InputCiphertextBytes += inputBytes

		for outputIndex, output := range []struct {
			layer  string
			value  *rlwe.Ciphertext
			length int
		}{
			{layer: layerXBeta, value: xBeta, length: rows},
			{layer: layerXtR, value: xTr, length: columns},
		} {
			encoded, err := output.value.MarshalBinary()
			if err != nil {
				return RunResult{}, fmt.Errorf("marshal evaluated ciphertext: %w", err)
			}
			metrics.OutputCiphertextBytes += uint64(len(encoded))
			if err := e.outputToShares(session, boundary, laneIndex, outputIndex, output.layer, output.value, output.length, &metrics); err != nil {
				return RunResult{}, err
			}
		}
	}

	metrics.Wall = time.Since(started)
	runtime.ReadMemStats(&memoryAfter)
	metrics.HeapAllocDeltaBytes = signedDelta(memoryAfter.HeapAlloc, memoryBefore.HeapAlloc)
	metrics.TotalAllocDeltaBytes = memoryAfter.TotalAlloc - memoryBefore.TotalAlloc
	metrics.ProcessSysDeltaBytes = signedDelta(memoryAfter.Sys, memoryBefore.Sys)
	e.sessions[session] = cloneBoundary(boundary)
	return RunResult{Session: session, Boundary: cloneBoundary(boundary), Rows: rows, Columns: columns, Metrics: metrics}, nil
}

func (e *Experiment) evaluateXBeta(laneIndex int, input LinearInput, rows, columns int) (*rlwe.Ciphertext, uint64, error) {
	lane := &e.lanes[laneIndex]
	var result *rlwe.Ciphertext
	var inputBytes uint64
	for column := 0; column < columns; column++ {
		owner := e.roles[column%len(e.roles)]
		betaResidue := signedResidue(input.Beta[column], lane.modulus)
		betaVector := make([]uint64, rows)
		for i := range betaVector {
			betaVector[i] = betaResidue
		}
		ciphertext, err := encryptVector(owner, laneIndex, lane.params, betaVector)
		if err != nil {
			return nil, 0, err
		}
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return nil, 0, err
		}
		inputBytes += uint64(len(encoded))
		xColumn := make([]uint64, rows)
		for row := 0; row < rows; row++ {
			xColumn[row] = signedResidue(input.X[row][column], lane.modulus)
		}
		term, err := lane.evaluator.MulNew(ciphertext, xColumn)
		if err != nil {
			return nil, 0, err
		}
		if result == nil {
			result = term
		} else if err := lane.evaluator.Add(result, term, result); err != nil {
			return nil, 0, err
		}
	}
	return result, inputBytes, nil
}

func (e *Experiment) evaluateXtR(laneIndex int, input LinearInput, rows, columns int) (*rlwe.Ciphertext, uint64, error) {
	lane := &e.lanes[laneIndex]
	var result *rlwe.Ciphertext
	var inputBytes uint64
	for row := 0; row < rows; row++ {
		owner := e.roles[row%len(e.roles)]
		residualResidue := signedResidue(input.Residual[row], lane.modulus)
		residualVector := make([]uint64, columns)
		for i := range residualVector {
			residualVector[i] = residualResidue
		}
		ciphertext, err := encryptVector(owner, laneIndex, lane.params, residualVector)
		if err != nil {
			return nil, 0, err
		}
		encoded, err := ciphertext.MarshalBinary()
		if err != nil {
			return nil, 0, err
		}
		inputBytes += uint64(len(encoded))
		xRow := make([]uint64, columns)
		for column := 0; column < columns; column++ {
			xRow[column] = signedResidue(input.X[row][column], lane.modulus)
		}
		term, err := lane.evaluator.MulNew(ciphertext, xRow)
		if err != nil {
			return nil, 0, err
		}
		if result == nil {
			result = term
		} else if err := lane.evaluator.Add(result, term, result); err != nil {
			return nil, 0, err
		}
	}
	return result, inputBytes, nil
}

func encryptVector(role *computeRole, laneIndex int, params bgv.Parameters, values []uint64) (*rlwe.Ciphertext, error) {
	plaintext := bgv.NewPlaintext(params, params.MaxLevel())
	if err := role.encoders[laneIndex].Encode(values, plaintext); err != nil {
		return nil, fmt.Errorf("encode role %s input: %w", role.id, err)
	}
	ciphertext, err := role.encryptors[laneIndex].EncryptNew(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt role %s input: %w", role.id, err)
	}
	return ciphertext, nil
}

func (e *Experiment) outputToShares(session [32]byte, boundary GCBoundary, laneIndex, outputIndex int, layer string, ciphertext *rlwe.Ciphertext, valueCount int, metrics *RunMetrics) error {
	encodedCiphertext, err := ciphertext.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal output ciphertext: %w", err)
	}
	ciphertextHash := sha256.Sum256(encodedCiphertext)
	secretShares := make([]multiparty.AdditiveShare, len(e.roles))
	receivedShares := make([]multiparty.KeySwitchShare, len(e.roles))

	for partyIndex, role := range e.roles {
		secretShares[partyIndex] = mpbgv.NewAdditiveShare(e.lanes[laneIndex].params)
		publicShare := role.e2s[laneIndex].AllocateShare(ciphertext.Level())
		role.e2s[laneIndex].GenShare(role.secretKeys[laneIndex], ciphertext, &secretShares[partyIndex], &publicShare)
		encodedMask, err := secretShares[partyIndex].Value.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal private output mask: %w", err)
		}
		operation := fmt.Sprintf("%x/%s/%d/%s", session, layer, laneIndex, role.id)
		if err := role.registerMask(operation, encodedMask); err != nil {
			return err
		}
		payload, err := publicShare.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal public EncToShare share: %w", err)
		}
		envelope := shareEnvelope{
			Session:        session,
			BoundaryDigest: boundary.Digest,
			CiphertextHash: ciphertextHash,
			Stage:          "enc-to-share/" + layer,
			Sender:         role.id,
			Lane:           uint32(laneIndex),
			Output:         uint32(outputIndex),
			Sequence:       uint64(laneIndex*2 + outputIndex),
			Payload:        payload,
		}
		if err := signEnvelope(role.privateKey, &envelope); err != nil {
			return err
		}
		want := envelopeExpectation{
			Session:        session,
			BoundaryDigest: boundary.Digest,
			CiphertextHash: ciphertextHash,
			Stage:          envelope.Stage,
			Sender:         role.id,
			Lane:           envelope.Lane,
			Output:         envelope.Output,
			Sequence:       envelope.Sequence,
		}
		accepted, err := e.relay.accept(envelope, want)
		if err != nil {
			return fmt.Errorf("relay rejected %s: %w", role.id, err)
		}
		received := role.e2s[laneIndex].AllocateShare(ciphertext.Level())
		if err := received.UnmarshalBinary(accepted); err != nil {
			return fmt.Errorf("decode public EncToShare share: %w", err)
		}
		if received.Level() != ciphertext.Level() || received.BinarySize() != len(accepted) {
			return errors.New("decoded EncToShare share has an unexpected shape")
		}
		receivedShares[partyIndex] = received
		e.lastEnvelopes = append(e.lastEnvelopes, envelope)
		metrics.PublicShareBytes += uint64(len(payload))
		metrics.SignedEnvelopeBytes += uint64(envelope.binarySize())
	}

	aggregate := e.roles[0].e2s[laneIndex].AllocateShare(ciphertext.Level())
	for _, share := range receivedShares {
		if err := e.roles[0].e2s[laneIndex].AggregateShares(aggregate, share, &aggregate); err != nil {
			return fmt.Errorf("aggregate EncToShare shares: %w", err)
		}
	}
	// Only role 0 computes its own masked additive output. Every other role keeps
	// its independent uniform mask; no role receives all decoded shares.
	e.roles[0].e2s[laneIndex].GetShare(&secretShares[0], aggregate, ciphertext, &secretShares[0])
	for partyIndex, role := range e.roles {
		decoded := make([]uint64, valueCount)
		if err := role.encoders[laneIndex].DecodeRingT(secretShares[partyIndex].Value, ciphertext.Scale, decoded); err != nil {
			return fmt.Errorf("decode local additive share for %s: %w", role.id, err)
		}
		role.outputs[outputKey{session: session, layer: layer, lane: laneIndex}] = decoded
	}
	return nil
}

// GCInput returns exactly one role's locally held shares. There is no method on
// Experiment that combines or decrypts them.
func (e *Experiment) GCInput(result RunResult, partyID, layer string) (GCPartyInput, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	boundary, ok := e.sessions[result.Session]
	if !ok || boundary.Digest != result.Boundary.Digest {
		return GCPartyInput{}, errors.New("unknown or mismatched experiment session")
	}
	if layer != layerXBeta && layer != layerXtR {
		return GCPartyInput{}, fmt.Errorf("unknown linear layer %q", layer)
	}
	var role *computeRole
	for _, candidate := range e.roles {
		if candidate.id == partyID {
			role = candidate
			break
		}
	}
	if role == nil {
		return GCPartyInput{}, fmt.Errorf("unknown compute role %q", partyID)
	}
	shares := make([][]uint64, len(e.lanes))
	for laneIndex := range e.lanes {
		value, exists := role.outputs[outputKey{session: result.Session, layer: layer, lane: laneIndex}]
		if !exists {
			return GCPartyInput{}, errors.New("role output is incomplete")
		}
		shares[laneIndex] = append([]uint64(nil), value...)
	}
	return GCPartyInput{
		PartyID:         role.id,
		Session:         result.Session,
		Layer:           layer,
		Boundary:        cloneBoundary(boundary),
		SharesByModulus: shares,
	}, nil
}

func validateLinearInput(input LinearInput, spec *CRTSpec, maxSlots int) (rows, columns int, magnitudeBound *big.Int, err error) {
	rows = len(input.X)
	if rows == 0 {
		return 0, 0, nil, errors.New("X must have at least one row")
	}
	columns = len(input.X[0])
	if columns == 0 {
		return 0, 0, nil, errors.New("X must have at least one column")
	}
	if rows > maxSlots || columns > maxSlots {
		return 0, 0, nil, fmt.Errorf("matrix dimensions exceed %d SIMD slots", maxSlots)
	}
	if len(input.Beta) != columns || len(input.Residual) != rows {
		return 0, 0, nil, errors.New("X, beta, and residual dimensions do not agree")
	}
	for row := range input.X {
		if len(input.X[row]) != columns {
			return 0, 0, nil, errors.New("X is not rectangular")
		}
	}
	for name, bound := range map[string]*big.Int{"X": input.Bounds.X, "beta": input.Bounds.Beta, "residual": input.Bounds.Residual} {
		if bound == nil || bound.Sign() < 0 {
			return 0, 0, nil, fmt.Errorf("%s bound must be a non-negative integer", name)
		}
	}
	for row := range input.X {
		for column := range input.X[row] {
			if err := checkAbsBound(input.X[row][column], input.Bounds.X, fmt.Sprintf("X[%d,%d]", row, column)); err != nil {
				return 0, 0, nil, err
			}
		}
	}
	for i, value := range input.Beta {
		if err := checkAbsBound(value, input.Bounds.Beta, fmt.Sprintf("beta[%d]", i)); err != nil {
			return 0, 0, nil, err
		}
	}
	for i, value := range input.Residual {
		if err := checkAbsBound(value, input.Bounds.Residual, fmt.Sprintf("residual[%d]", i)); err != nil {
			return 0, 0, nil, err
		}
	}
	xBetaBound := new(big.Int).Mul(new(big.Int).Set(input.Bounds.X), input.Bounds.Beta)
	xBetaBound.Mul(xBetaBound, big.NewInt(int64(columns)))
	xTrBound := new(big.Int).Mul(new(big.Int).Set(input.Bounds.X), input.Bounds.Residual)
	xTrBound.Mul(xTrBound, big.NewInt(int64(rows)))
	magnitudeBound = xBetaBound
	if xTrBound.Cmp(magnitudeBound) > 0 {
		magnitudeBound = xTrBound
	}
	if err := spec.ValidateMagnitudeBound(magnitudeBound); err != nil {
		return 0, 0, nil, err
	}
	return rows, columns, new(big.Int).Set(magnitudeBound), nil
}

func checkAbsBound(value, bound *big.Int, label string) error {
	if value == nil {
		return fmt.Errorf("%s is nil", label)
	}
	if new(big.Int).Abs(new(big.Int).Set(value)).Cmp(bound) > 0 {
		return fmt.Errorf("%w: |%s|=%s > %s", ErrBoundExceeded, label, new(big.Int).Abs(new(big.Int).Set(value)), bound)
	}
	return nil
}

func signedResidue(value *big.Int, modulus uint64) uint64 {
	return new(big.Int).Mod(new(big.Int).Set(value), new(big.Int).SetUint64(modulus)).Uint64()
}

func cloneBoundary(boundary GCBoundary) GCBoundary {
	boundary.Moduli = append([]uint64(nil), boundary.Moduli...)
	boundary.Product = append([]byte(nil), boundary.Product...)
	boundary.MagnitudeBound = append([]byte(nil), boundary.MagnitudeBound...)
	return boundary
}

func signedDelta(after, before uint64) int64 {
	if after >= before {
		delta := after - before
		if delta > uint64(^uint64(0)>>1) {
			return int64(^uint64(0) >> 1)
		}
		return int64(delta)
	}
	delta := before - after
	if delta > uint64(^uint64(0)>>1) {
		return -int64(^uint64(0) >> 1)
	}
	return -int64(delta)
}
