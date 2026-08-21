// k2_exact_gc_core.go -- exact two-party garbled-circuit primitives.
//
// This file deliberately contains no command handler.  It is the reviewable
// core for a future peer-to-peer integration.  The relay must only carry the
// encrypted record stream from k2_exact_gc_transport.go; it is never an OT
// dealer and never receives an input or output share.
//
// Security scope: Yao garbling with KOS-checked IKNP OT is used under the
// pinned, semi-honest, non-colluding two-peer model.  The output is decoded by
// the evaluator only and is one-time-padded by a fresh garbler share.  This is
// not a malicious-secure two-party computation claim.

package main

import (
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

type exactGCOperation string
type exactGCMulBackend string

const (
	exactGCCompareSigned        exactGCOperation  = "compare-signed"
	exactGCTruncateFloor        exactGCOperation  = "truncate-floor"
	exactGCTruncateNearestEven  exactGCOperation  = "truncate-nearest-ties-to-even"
	exactGCMulTruncateChecked   exactGCOperation  = "mul-truncate-checked"
	exactGCHybridMulFinalize    exactGCOperation  = "hybrid-mul-finalize"
	exactGCCountGuard           exactGCOperation  = "count-guard"
	exactGCClampCount           exactGCOperation  = "clamp-count"
	exactGCJointDPLaplace       exactGCOperation  = "joint-dp-laplace-v2"
	exactGCAlignmentMaskRing128 exactGCOperation  = "alignment-mask-ring128"
	exactGCCRTToRingChecked     exactGCOperation  = "crt-to-ring-checked-v1"
	exactGCMulBackendDirect     exactGCMulBackend = "direct-wide"
	exactGCMulBackendHybrid     exactGCMulBackend = "ring127-ot"

	exactGCMinRingBits           = 2
	exactGCMaxRingBits           = 4096
	exactGCMaxDecimalBoundDigits = 1200
	exactGCMaxVectorLen          = 4096
	exactGCMaxCircuitTypeBits    = 512 * 1024
	exactGCMaxDirectMulLen       = 64
	exactGCMaxHybridVectorLen    = 256
	// A direct checked multiplier has quadratic cost in its container width.
	// Preserve the old Ring512 x 64 upper work envelope while reducing chunks
	// automatically for wider containers. This is an explicit per-circuit
	// resource limit, never a request-count or history-dependent quota.
	exactGCMaxDirectMulBitWork = 512 * 512 * exactGCMaxDirectMulLen
)

// exactGCCircuitSpec is public protocol context, not private input. Threshold
// is signed for compare-signed and non-negative for count-guard.
type exactGCCircuitSpec struct {
	Operation  exactGCOperation
	RingBits   int
	FracBits   int
	Threshold  *big.Int
	BoundX     *big.Int
	BoundY     *big.Int
	MulBackend exactGCMulBackend
	VectorLen  int
}

// exactGCSession binds one circuit execution to the authenticated pinned peer
// identities and to a caller-defined purpose string. MasterKey must come from
// an authenticated peer-to-peer key agreement; it is not supplied by the
// analyst or relay.
type exactGCSession struct {
	SessionID   [32]byte
	MasterKey   [32]byte
	GarblerID   string
	EvaluatorID string
	Purpose     string
	Spec        exactGCCircuitSpec
}

const exactGCCircuitCacheEntries = 4

var exactGCCircuitCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
	order   []string
}{entries: make(map[string]*circuit.Circuit)}

func newExactGCSessionID() ([32]byte, error) {
	var id [32]byte
	_, err := io.ReadFull(crand.Reader, id[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("exact-gc: generate session id: %w", err)
	}
	return id, nil
}

func (s exactGCSession) validate() error {
	if bytes.Equal(s.SessionID[:], make([]byte, len(s.SessionID))) {
		return fmt.Errorf("exact-gc: session id must be 32 non-zero random bytes")
	}
	if bytes.Equal(s.MasterKey[:], make([]byte, len(s.MasterKey))) {
		return fmt.Errorf("exact-gc: master key must be non-zero")
	}
	if err := exactGCValidateLabel("garbler identity", s.GarblerID, 256); err != nil {
		return err
	}
	if err := exactGCValidateLabel("evaluator identity", s.EvaluatorID, 256); err != nil {
		return err
	}
	if s.GarblerID == s.EvaluatorID {
		return fmt.Errorf("exact-gc: garbler and evaluator identities must differ")
	}
	if err := exactGCValidateLabel("purpose", s.Purpose, 512); err != nil {
		return err
	}
	return s.Spec.validate()
}

func exactGCValidateLabel(name, value string, max int) error {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return fmt.Errorf("exact-gc: invalid %s", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("exact-gc: invalid %s", name)
		}
	}
	return nil
}

func (s exactGCCircuitSpec) validate() error {
	if s.RingBits < exactGCMinRingBits || s.RingBits > exactGCMaxRingBits {
		return fmt.Errorf("exact-gc: ring bits must be in [%d,%d]",
			exactGCMinRingBits, exactGCMaxRingBits)
	}
	if s.VectorLen < 1 || s.VectorLen > exactGCMaxVectorLen {
		return fmt.Errorf("exact-gc: vector length must be in [1,%d]", exactGCMaxVectorLen)
	}
	if exactGCCircuitInputBits(s) > exactGCMaxCircuitTypeBits {
		return fmt.Errorf("exact-gc: circuit shape exceeds %d typed input bits",
			exactGCMaxCircuitTypeBits)
	}
	switch s.Operation {
	case exactGCCompareSigned:
		if s.FracBits != 0 {
			return fmt.Errorf("exact-gc: comparison does not accept fractional bits")
		}
		if s.Threshold == nil || !exactGCFitsSigned(s.Threshold, s.RingBits) {
			return fmt.Errorf("exact-gc: signed threshold is outside Ring%d", s.RingBits)
		}
	case exactGCTruncateFloor, exactGCTruncateNearestEven:
		if s.Threshold != nil {
			return fmt.Errorf("exact-gc: truncation does not accept a threshold")
		}
		if s.FracBits < 0 || s.FracBits >= s.RingBits {
			return fmt.Errorf("exact-gc: fractional bits must be in [0,%d]", s.RingBits-1)
		}
	case exactGCMulTruncateChecked:
		if s.Threshold != nil {
			return fmt.Errorf("exact-gc: checked multiplication does not accept a threshold")
		}
		if s.FracBits < 0 || s.FracBits >= s.RingBits {
			return fmt.Errorf("exact-gc: checked multiplication fractional bits must be in [0,%d]",
				s.RingBits-1)
		}
		if s.MulBackend != exactGCMulBackendDirect &&
			s.MulBackend != exactGCMulBackendHybrid {
			return fmt.Errorf("exact-gc: checked multiplication backend is invalid")
		}
		maxVectorLen := exactGCMaxDirectMulChunk(s.RingBits)
		if s.MulBackend == exactGCMulBackendHybrid {
			if s.RingBits != 127 || s.FracBits < 1 {
				return fmt.Errorf("exact-gc: OT multiplication requires Ring127 with fractional scale")
			}
			maxVectorLen = exactGCMaxHybridVectorLen
		}
		if maxVectorLen < 1 {
			return fmt.Errorf("exact-gc: checked multiplication ring exceeds the circuit resource policy")
		}
		if s.VectorLen > maxVectorLen {
			return fmt.Errorf("exact-gc: checked multiplication shape exceeds backend policy")
		}
		maxMagnitude := exactGCMaxSigned(s.RingBits)
		if s.BoundX == nil || s.BoundY == nil || s.BoundX.Sign() <= 0 ||
			s.BoundY.Sign() <= 0 || s.BoundX.Cmp(maxMagnitude) > 0 ||
			s.BoundY.Cmp(maxMagnitude) > 0 {
			return fmt.Errorf("exact-gc: checked multiplication bounds are outside Ring%d",
				s.RingBits)
		}
		productBound := new(big.Int).Mul(s.BoundX, s.BoundY)
		if s.MulBackend == exactGCMulBackendHybrid &&
			productBound.Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
			return fmt.Errorf("exact-gc: checked multiplication policy does not prove raw-product headroom")
		}
		// The direct backend computes the raw product in a 2*w circuit type.
		// Its public bounds therefore need only prove that the exactly floored
		// quotient fits the signed output ring. This is the safe fallback when
		// a Ring127 raw product would wrap, without reinterpreting either share.
		if s.MulBackend == exactGCMulBackendDirect {
			denominator := new(big.Int).Lsh(big.NewInt(1), uint(s.FracBits))
			quotientBound := new(big.Int).Add(
				new(big.Int).Set(productBound), new(big.Int).Sub(denominator, big.NewInt(1)))
			quotientBound.Quo(quotientBound, denominator)
			if quotientBound.Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
				return fmt.Errorf("exact-gc: checked multiplication policy does not prove truncated-output headroom")
			}
		}
	case exactGCHybridMulFinalize:
		if s.Threshold != nil || s.RingBits != 127 || s.FracBits < 1 ||
			s.VectorLen > exactGCMaxHybridVectorLen {
			return fmt.Errorf("exact-gc: invalid hybrid multiplication finalizer shape")
		}
		maxMagnitude := new(big.Int).Lsh(big.NewInt(1), uint(s.RingBits-1))
		if s.BoundX == nil || s.BoundY == nil || s.BoundX.Sign() <= 0 ||
			s.BoundY.Sign() <= 0 || s.BoundX.Cmp(maxMagnitude) > 0 ||
			s.BoundY.Cmp(maxMagnitude) > 0 ||
			new(big.Int).Mul(s.BoundX, s.BoundY).Cmp(
				exactGCMaxSigned(s.RingBits)) > 0 {
			return fmt.Errorf("exact-gc: invalid hybrid multiplication bounds")
		}
	case exactGCCountGuard:
		if s.FracBits != 0 {
			return fmt.Errorf("exact-gc: count guard does not accept fractional bits")
		}
		if s.Threshold == nil || s.Threshold.Sign() <= 0 ||
			s.Threshold.Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
			return fmt.Errorf("exact-gc: count threshold must be in [1,2^%d-1]", s.RingBits-1)
		}
	case exactGCClampCount:
		if s.FracBits != 0 || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.Threshold == nil ||
			s.Threshold.Sign() <= 0 ||
			s.Threshold.Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
			return fmt.Errorf("exact-gc: count clamp requires one positive signed upper bound")
		}
	case exactGCJointDPLaplace:
		// The full public sampler contract is validated by the specialised
		// joint-DP runner.  Keep the generic session shape deliberately narrow
		// so this operation cannot be routed through exactGCCompileCircuit.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || (s.RingBits != 63 && s.RingBits != 127) ||
			s.FracBits < 0 || s.FracBits >= s.RingBits ||
			s.VectorLen > jointDPMaxCoordinates {
			return fmt.Errorf("exact-gc: invalid joint-DP Laplace session shape")
		}
	case exactGCAlignmentMaskRing128:
		// Threshold carries the public number of source custodians. Each peer
		// supplies VectorLen additive Ring128 value shares followed by two
		// XOR-shared 128-bit limbs for every custodian's private SHA-256
		// alignment digest. The digest equality predicate is evaluated only in
		// the circuit and is never emitted as a per-source result.
		if s.RingBits != 128 || s.FracBits != 0 || s.Threshold == nil ||
			s.Threshold.Cmp(big.NewInt(2)) < 0 ||
			s.Threshold.Cmp(big.NewInt(64)) > 0 ||
			s.BoundX != nil || s.BoundY != nil || s.MulBackend != "" {
			return fmt.Errorf("exact-gc: invalid alignment-mask Ring128 session shape")
		}
	case jointDPVectorOperation:
		// Bounds, global sensitivity, dyadic probabilities and exact delta
		// accounting live in the specialised vector policy.  The generic
		// session admits only its fixed Ring128, integer, bounded chunk shape.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.RingBits != 128 || s.FracBits != 0 ||
			s.VectorLen > jointDPVectorMaxCoordinates {
			return fmt.Errorf("exact-gc: invalid joint-DP vector session shape")
		}
	case jointDPGaussianOneDrawOperation:
		// Full CDF, global L2 accounting, pinset/role binding and resource
		// bounds are validated by the specialised one-draw runner.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.RingBits != 128 || s.FracBits != 0 ||
			s.VectorLen > jointDPGaussianOneDrawMaxCoordinates {
			return fmt.Errorf("exact-gc: invalid one-draw Gaussian session shape")
		}
	case exactGCFormalGLMOneIteration:
		// The complete public policy is checked by the specialised sealed
		// runner. The generic operation cannot compile or open this workload.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.RingBits < 128 ||
			s.FracBits < 8 || s.FracBits >= s.RingBits {
			return fmt.Errorf("exact-gc: invalid formal GLM session shape")
		}
	case exactGCFormalCoxIterations:
		// Only the purpose-bound internal Cox runner can compile this workload.
		// Generic admission is intentionally limited to record-layer/session
		// validation and cannot construct an input or expose an output.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.RingBits < 128 ||
			s.FracBits < 8 || s.FracBits >= s.RingBits {
			return fmt.Errorf("exact-gc: invalid formal Cox session shape")
		}
	case exactGCFormalGLMDPBridge:
		// The dedicated bridge may consume Ring63/127 or a dynamic source
		// ring, but its fresh selective-sharing mask is always Ring128.  Its
		// specialised compiler validates the coefficient box and quantizer.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.FracBits < 0 || s.FracBits >= s.RingBits {
			return fmt.Errorf("exact-gc: invalid formal GLM DP bridge session shape")
		}
	case exactGCCRTToRingChecked:
		// The CRT moduli, product and signed magnitude certificate are bound
		// into Purpose and validated by the specialised runner.  This generic
		// shape cannot be compiled or invoked through the ordinary Ring path.
		if s.Threshold != nil || s.BoundX != nil || s.BoundY != nil ||
			s.MulBackend != "" || s.FracBits != 0 {
			return fmt.Errorf("exact-gc: invalid checked CRT-to-Ring session shape")
		}
	default:
		return fmt.Errorf("exact-gc: unsupported operation %q", s.Operation)
	}
	return nil
}

func exactGCCircuitInputBits(spec exactGCCircuitSpec) int {
	containers := spec.VectorLen
	switch spec.Operation {
	case exactGCCompareSigned:
		containers = 3 * spec.VectorLen
	case exactGCTruncateFloor, exactGCTruncateNearestEven:
		// Garbler: one input share plus one output mask. Evaluator: one
		// input share. The masked result is uniform to the evaluator.
		containers = 3 * spec.VectorLen
	case exactGCClampCount:
		// Garbler: one noised input share plus one fresh output mask.
		// Evaluator: one noised input share.  The pre-clamp reconstruction
		// never leaves the circuit.
		containers = 3 * spec.VectorLen
	case exactGCMulTruncateChecked:
		// The checked operation uses an OT product followed by the hybrid
		// finalizer below. Account for the largest typed subprotocol input.
		containers = 7*spec.VectorLen + 1
	case exactGCHybridMulFinalize:
		// Garbler: raw/x/y shares, output masks, validity mask.
		// Evaluator: raw/x/y shares.
		containers = 7*spec.VectorLen + 1
	case exactGCCountGuard:
		containers = 2*spec.VectorLen + 1
	case exactGCJointDPLaplace:
		// Each peer supplies d ring shares and a 256-bit seed; the garbler
		// additionally supplies d deterministic output masks and one validity
		// mask.  The specialised compiler enforces this exact struct layout.
		return exactGCTypeBits(spec.RingBits)*(3*spec.VectorLen) + 513
	case exactGCAlignmentMaskRing128:
		// Both peers provide n values and 2*K private digest limbs. The
		// garbler additionally provides n additive output masks and one XOR
		// validity mask in a full Ring128 container.
		k := 0
		if spec.Threshold != nil && spec.Threshold.IsInt64() {
			k = int(spec.Threshold.Int64())
		}
		return exactGCTypeBits(spec.RingBits) * (3*spec.VectorLen + 4*k + 1)
	case jointDPVectorOperation:
		// The specialised policy enforces the complete stream-input bound once
		// J and R are known.  Account here for both source shares, the public
		// upper bounds, output masks and validity bit.
		return 4*128*spec.VectorLen + 1
	case jointDPGaussianOneDrawOperation:
		// Both peers: source, 128-bit stream word and sign. Garbler: upper
		// bound, output mask and validity mask.
		return 770*spec.VectorLen + 1
	case exactGCFormalGLMOneIteration:
		// Both source-share vectors plus a conservative output-mask envelope.
		return 3 * exactGCTypeBits(spec.RingBits) * spec.VectorLen
	case exactGCFormalCoxIterations:
		// The specialised runner checks its tighter 2*n+p+1 shape. Keep the
		// generic session gate conservative without adding a generic packer.
		return 3 * exactGCTypeBits(spec.RingBits) * spec.VectorLen
	case exactGCFormalGLMDPBridge:
		// Source shares and Ring128 output masks share the compiler input
		// container.  Account for the wider of the two, never the source ring
		// alone (Ring63 otherwise undercounts and overlaps high mask bits).
		return 3 * formalGLMPhase15DPBridgeInputTypeBits(spec.RingBits) *
			spec.VectorLen
	case exactGCCRTToRingChecked:
		// The specialised CRT policy performs the exact lane-aware resource
		// accounting.  This lower bound only protects generic session parsing.
		return 3*exactGCTypeBits(spec.RingBits)*spec.VectorLen + 1
	}
	return exactGCTypeBits(spec.RingBits) * containers
}

func exactGCFitsSigned(x *big.Int, bits int) bool {
	if x == nil {
		return false
	}
	min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	return x.Cmp(min) >= 0 && x.Cmp(exactGCMaxSigned(bits)) <= 0
}

func exactGCMaxSigned(bits int) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1))
}

func exactGCModulus(bits int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bits))
}

func exactGCMask(bits int) *big.Int {
	return new(big.Int).Sub(exactGCModulus(bits), big.NewInt(1))
}

func exactGCValidateShares(shares []*big.Int, spec exactGCCircuitSpec) error {
	want := exactGCInputShareCount(spec)
	if len(shares) != want {
		return fmt.Errorf("exact-gc: got %d shares, want %d", len(shares), want)
	}
	mod := exactGCModulus(spec.RingBits)
	for i, share := range shares {
		if share == nil || share.Sign() < 0 || share.Cmp(mod) >= 0 {
			return fmt.Errorf("exact-gc: share %d is not canonical Ring%d", i, spec.RingBits)
		}
	}
	return nil
}

func exactGCInputShareCount(spec exactGCCircuitSpec) int {
	if spec.Operation == exactGCMulTruncateChecked {
		return 2 * spec.VectorLen
	}
	if spec.Operation == exactGCHybridMulFinalize {
		return 3 * spec.VectorLen
	}
	if spec.Operation == exactGCAlignmentMaskRing128 {
		return spec.VectorLen + 2*int(spec.Threshold.Int64())
	}
	return spec.VectorLen
}

// exactGCDefaultMulBound is a fixed, runtime-owned magnitude policy for the
// hybrid OT product. It is the largest symmetric integer bound whose square
// fits the signed side of the ring, proving that the raw modular product did
// not wrap before exact truncation. It cannot be supplied by the analyst.
func exactGCDefaultMulBound(ringBits, fracBits int) *big.Int {
	_ = fracBits
	return new(big.Int).Sqrt(exactGCMaxSigned(ringBits))
}

// exactGCRunGarbler executes the garbler half and returns only its fresh output
// shares. It never receives the evaluator's decoded output shares.
func exactGCRunGarbler(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	if rw == nil {
		return nil, fmt.Errorf("exact-gc: nil peer channel")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if session.Spec.Operation == exactGCMulTruncateChecked &&
		session.Spec.MulBackend == exactGCMulBackendHybrid {
		return exactGCRunHybridMulGarbler(rw, session, shares)
	}
	outShares, err := exactGCRandomOutputShares(session.Spec)
	if err != nil {
		return nil, err
	}
	return exactGCRunGarblerWithOutputShares(rw, session, shares, outShares)
}

// exactGCDeterministicOutputShares derives the clamp's additive output mask
// from a query-bound custodian secret.  It deliberately excludes the
// transport session and retry attempt, so a crash/restart cannot leave the two
// peers with incompatible durable post-clamp shares.  The seed is never sent
// to the evaluator or relay.
func exactGCDeterministicOutputShares(session exactGCSession,
	seed [32]byte) ([]*big.Int, error) {
	if session.Spec.Operation != exactGCClampCount {
		return nil, fmt.Errorf("exact-gc: deterministic output mask is Count-only")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	threshold := ""
	if session.Spec.Threshold != nil {
		threshold = session.Spec.Threshold.String()
	}
	byteLen := (session.Spec.RingBits + 7) / 8
	result := make([]*big.Int, session.Spec.VectorLen)
	for coordinate := range result {
		encoded := make([]byte, byteLen)
		for offset, counter := 0, 0; offset < len(encoded); counter++ {
			mac := hmac.New(sha256.New, seed[:])
			fmt.Fprintf(mac,
				"dsvert-exact-gc/count-output-mask/v1|%s|%s|%s|%d|%d|%s|%d|%d",
				session.GarblerID, session.Purpose, session.Spec.Operation,
				session.Spec.RingBits, session.Spec.FracBits, threshold,
				coordinate, counter)
			block := mac.Sum(nil)
			offset += copy(encoded[offset:], block)
			clear(block)
		}
		if remainder := session.Spec.RingBits % 8; remainder != 0 {
			encoded[0] &= byte((1 << remainder) - 1)
		}
		result[coordinate] = new(big.Int).SetBytes(encoded)
		clear(encoded)
	}
	return result, nil
}

func exactGCRunGarblerWithDeterministicOutputSeed(rw io.ReadWriter,
	session exactGCSession, shares []*big.Int, seed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("exact-gc: nil peer channel")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	outShares, err := exactGCDeterministicOutputShares(session, seed)
	if err != nil {
		return nil, err
	}
	return exactGCRunGarblerWithOutputShares(rw, session, shares, outShares)
}

func exactGCRunGarblerWithOutputShares(rw io.ReadWriter,
	session exactGCSession, shares, outShares []*big.Int) ([]*big.Int, error) {
	input := exactGCPackGarblerInput(shares, outShares, session.Spec)

	circ, err := exactGCCompileCircuit(session.Spec)
	if err != nil {
		return nil, err
	}
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return outShares, nil
}

// exactGCRunEvaluator executes the evaluator half and returns only the shares
// decoded by the evaluator. Combined with exactGCRunGarbler's return value they
// reconstruct the operation result; neither peer obtains both values.
func exactGCRunEvaluator(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	if rw == nil {
		return nil, fmt.Errorf("exact-gc: nil peer channel")
	}
	if err := session.validate(); err != nil {
		return nil, err
	}
	if err := exactGCValidateShares(shares, session.Spec); err != nil {
		return nil, err
	}
	if session.Spec.Operation == exactGCMulTruncateChecked &&
		session.Spec.MulBackend == exactGCMulBackendHybrid {
		return exactGCRunHybridMulEvaluator(rw, session, shares)
	}
	circ, err := exactGCCompileCircuit(session.Spec)
	if err != nil {
		return nil, err
	}
	input := exactGCPackChunks(shares, exactGCTypeBits(session.Spec.RingBits))

	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	decoded := exactGCUnpackOutputs(result, session.Spec)
	return decoded, nil
}

func exactGCRunHybridMulGarbler(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	raw, err := exactGCHybridOTProductGarbler(rw, session, shares)
	if err != nil {
		return nil, err
	}
	return exactGCHybridFinalizeGarbler(rw, session, shares, raw)
}

func exactGCRunHybridMulEvaluator(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	raw, err := exactGCHybridOTProductEvaluator(rw, session, shares)
	if err != nil {
		return nil, err
	}
	return exactGCHybridFinalizeEvaluator(rw, session, shares, raw)
}

func exactGCHybridOTSession(session exactGCSession) exactGCSession {
	result := session
	result.Purpose += "/hybrid-ot-v1"
	return result
}

func exactGCHybridFinalizeSession(session exactGCSession) exactGCSession {
	result := session
	result.Purpose += "/hybrid-finalize-v1"
	result.Spec = exactGCCircuitSpec{
		Operation:  exactGCHybridMulFinalize,
		RingBits:   session.Spec.RingBits,
		FracBits:   session.Spec.FracBits,
		BoundX:     new(big.Int).Set(session.Spec.BoundX),
		BoundY:     new(big.Int).Set(session.Spec.BoundY),
		MulBackend: exactGCMulBackendHybrid,
		VectorLen:  session.Spec.VectorLen,
	}
	return result
}

func exactGCHybridOTProductGarbler(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	otSession := exactGCHybridOTSession(session)
	secure, err := newExactGCSecureRecordRW(rw, otSession, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	var protocolErr error
	if protocolErr = exactGCHybridBeginGarbler(conn, otSession); protocolErr != nil {
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	n := session.Spec.VectorLen
	x, y := exactGCHybridUint128Inputs(shares, n)
	sendShare, protocolErr := exactGCHybridOTSend(conn, x)
	if protocolErr != nil {
		protocolErr = fmt.Errorf("exact-gc: hybrid forward OT: %w", protocolErr)
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	receiveShare, protocolErr := exactGCHybridOTReceive(conn, y)
	if protocolErr != nil {
		protocolErr = fmt.Errorf("exact-gc: hybrid reverse OT: %w", protocolErr)
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	protocolErr = exactGCHybridFinishGarbler(conn, otSession)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return exactGCHybridCombineProduct(x, y, sendShare, receiveShare), nil
}

func exactGCHybridOTProductEvaluator(rw io.ReadWriter, session exactGCSession,
	shares []*big.Int) ([]*big.Int, error) {

	otSession := exactGCHybridOTSession(session)
	secure, err := newExactGCSecureRecordRW(rw, otSession, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	var protocolErr error
	if protocolErr = exactGCHybridBeginEvaluator(conn, otSession); protocolErr != nil {
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	n := session.Spec.VectorLen
	x, y := exactGCHybridUint128Inputs(shares, n)
	receiveShare, protocolErr := exactGCHybridOTReceive(conn, y)
	if protocolErr != nil {
		protocolErr = fmt.Errorf("exact-gc: hybrid forward OT: %w", protocolErr)
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	sendShare, protocolErr := exactGCHybridOTSend(conn, x)
	if protocolErr != nil {
		protocolErr = fmt.Errorf("exact-gc: hybrid reverse OT: %w", protocolErr)
		return nil, exactGCFinishConn(conn, rw, protocolErr)
	}
	protocolErr = exactGCHybridFinishEvaluator(conn, otSession)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return exactGCHybridCombineProduct(x, y, sendShare, receiveShare), nil
}

// exactGCFinishConn drains p2p's asynchronous writer before a worker may mark
// itself complete, then publishes any public phase buffer owned by the spool.
// Protocol errors remain authoritative; close/flush errors can only make an
// otherwise successful operation fail closed.
func exactGCFinishConn(conn *p2p.Conn, rw io.ReadWriter, protocolErr error) error {
	closeErr := conn.Close()
	var flushErr error
	if flusher, ok := rw.(interface{ Flush() error }); ok {
		flushErr = flusher.Flush()
	}
	if protocolErr != nil {
		return protocolErr
	}
	if closeErr != nil {
		return fmt.Errorf("exact-gc: close peer channel: %w", closeErr)
	}
	if flushErr != nil {
		return fmt.Errorf("exact-gc: flush peer channel: %w", flushErr)
	}
	return nil
}

func exactGCHybridUint128Inputs(shares []*big.Int, n int) ([]Uint128, []Uint128) {
	x := make([]Uint128, n)
	y := make([]Uint128, n)
	for i := 0; i < n; i++ {
		x[i] = U128FromBig(shares[i]).ModPow127()
		y[i] = U128FromBig(shares[n+i]).ModPow127()
	}
	return x, y
}

func exactGCHybridOTSend(conn *p2p.Conn, x []Uint128) ([]Uint128, error) {
	const bits = 127
	wires := make([]ot.Wire, len(x)*bits)
	share := make([]Uint128, len(x))
	for i, value := range x {
		for bit := 0; bit < bits; bit++ {
			mask := cryptoRandUint128().ModPow127()
			withTerm := mask.Add(value.Shl(uint(bit))).ModPow127()
			wires[i*bits+bit] = ot.Wire{
				L0: labelFromUint128(mask),
				L1: labelFromUint128(withTerm),
			}
			share[i] = share[i].Sub(mask).ModPow127()
		}
	}
	transfer := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := transfer.InitSender(conn); err != nil {
		return nil, err
	}
	if err := transfer.Send(wires); err != nil {
		return nil, err
	}
	return share, nil
}

func exactGCHybridOTReceive(conn *p2p.Conn, y []Uint128) ([]Uint128, error) {
	const bits = 127
	choices := make([]bool, len(y)*bits)
	for i, value := range y {
		for bit := 0; bit < bits; bit++ {
			if bit < 64 {
				choices[i*bits+bit] = ((value.Lo >> uint(bit)) & 1) == 1
			} else {
				choices[i*bits+bit] = ((value.Hi >> uint(bit-64)) & 1) == 1
			}
		}
	}
	labels := make([]ot.Label, len(choices))
	transfer := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := transfer.InitReceiver(conn); err != nil {
		return nil, err
	}
	if err := transfer.Receive(choices, labels); err != nil {
		return nil, err
	}
	decoded, err := otLabelsToRingShare(labels, len(y), "ring127")
	if err != nil {
		return nil, err
	}
	return decoded.([]Uint128), nil
}

func exactGCHybridCombineProduct(x, y, sendShare, receiveShare []Uint128) []*big.Int {
	result := make([]*big.Int, len(x))
	for i := range result {
		local := x[i].Mul(y[i]).ModPow127()
		value := local.Add(sendShare[i]).Add(receiveShare[i]).ModPow127()
		result[i] = value.ToBig()
	}
	return result
}

func exactGCHybridBeginGarbler(conn *p2p.Conn, session exactGCSession) error {
	digest := exactGCContextDigest(session)
	if err := conn.SendData(digest[:]); err != nil {
		return fmt.Errorf("exact-gc: send hybrid context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush hybrid context: %w", err)
	}
	ack, err := conn.ReceiveData()
	if err != nil || !bytes.Equal(ack, digest[:]) {
		return fmt.Errorf("exact-gc: hybrid peer context mismatch")
	}
	return nil
}

func exactGCHybridBeginEvaluator(conn *p2p.Conn, session exactGCSession) error {
	digest := exactGCContextDigest(session)
	got, err := conn.ReceiveData()
	if err != nil || !bytes.Equal(got, digest[:]) {
		return fmt.Errorf("exact-gc: hybrid peer context mismatch")
	}
	if err := conn.SendData(digest[:]); err != nil {
		return fmt.Errorf("exact-gc: acknowledge hybrid context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush hybrid context acknowledgement: %w", err)
	}
	return nil
}

func exactGCHybridFinishGarbler(conn *p2p.Conn, session exactGCSession) error {
	done := exactGCDoneDigest(exactGCContextDigest(session))
	if err := conn.SendData(done[:]); err != nil {
		return fmt.Errorf("exact-gc: send hybrid completion: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush hybrid completion: %w", err)
	}
	ack, err := conn.ReceiveData()
	if err != nil || !bytes.Equal(ack, done[:]) {
		return fmt.Errorf("exact-gc: invalid hybrid completion acknowledgement")
	}
	return nil
}

func exactGCHybridFinishEvaluator(conn *p2p.Conn, session exactGCSession) error {
	done := exactGCDoneDigest(exactGCContextDigest(session))
	got, err := conn.ReceiveData()
	if err != nil || !bytes.Equal(got, done[:]) {
		return fmt.Errorf("exact-gc: invalid hybrid completion")
	}
	if err := conn.SendData(done[:]); err != nil {
		return fmt.Errorf("exact-gc: acknowledge hybrid completion: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush hybrid completion acknowledgement: %w", err)
	}
	return nil
}

func exactGCHybridFinalizeGarbler(rw io.ReadWriter, session exactGCSession,
	input, raw []*big.Int) ([]*big.Int, error) {
	finalInput := append(append([]*big.Int{}, raw...), input...)
	finalSession := exactGCHybridFinalizeSession(session)
	output, err := exactGCRunGarbler(rw, finalSession, finalInput)
	if err != nil {
		return nil, err
	}
	return exactGCHybridFinalizeOutput(raw, output, session.Spec)
}

func exactGCHybridFinalizeEvaluator(rw io.ReadWriter, session exactGCSession,
	input, raw []*big.Int) ([]*big.Int, error) {
	finalInput := append(append([]*big.Int{}, raw...), input...)
	finalSession := exactGCHybridFinalizeSession(session)
	output, err := exactGCRunEvaluator(rw, finalSession, finalInput)
	if err != nil {
		return nil, err
	}
	return exactGCHybridFinalizeOutput(raw, output, session.Spec)
}

func exactGCHybridFinalizeOutput(raw, output []*big.Int,
	spec exactGCCircuitSpec) ([]*big.Int, error) {
	n := spec.VectorLen
	if len(raw) != n || len(output) != n+1 {
		return nil, fmt.Errorf("exact-gc: invalid hybrid finalizer output shape")
	}
	result := make([]*big.Int, n+1)
	for i := range result {
		result[i] = new(big.Int).Set(output[i])
	}
	return result, nil
}

func exactGCGarblerProtocol(conn *p2p.Conn, circ *circuit.Circuit,
	input *big.Int, session exactGCSession) error {

	digest := exactGCContextDigest(session)
	if err := conn.SendData(digest[:]); err != nil {
		return fmt.Errorf("exact-gc: send context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush context: %w", err)
	}
	ack, err := conn.ReceiveData()
	if err != nil {
		return fmt.Errorf("exact-gc: receive context acknowledgement: %w", err)
	}
	if !bytes.Equal(ack, digest[:]) {
		return fmt.Errorf("exact-gc: peer context mismatch")
	}

	// This is the public fixed-key AES hash key used by the garbling scheme,
	// exactly as in markkurossi/mpc's Garbler/Evaluator protocol. It is not the
	// secret record-layer MasterKey and does not derive random wire labels.
	var garblingHashKey [32]byte
	if _, err := io.ReadFull(crand.Reader, garblingHashKey[:]); err != nil {
		return fmt.Errorf("exact-gc: generate garbling key: %w", err)
	}
	garbled, err := circ.Garble(crand.Reader, garblingHashKey[:])
	if err != nil {
		return fmt.Errorf("exact-gc: garble circuit: %w", err)
	}
	if err := conn.SendData(garblingHashKey[:]); err != nil {
		return fmt.Errorf("exact-gc: send garbling key: %w", err)
	}
	if err := conn.SendUint32(len(garbled.Gates)); err != nil {
		return fmt.Errorf("exact-gc: send gate count: %w", err)
	}
	var labelData ot.LabelData
	for _, row := range garbled.Gates {
		if err := conn.SendUint32(len(row)); err != nil {
			return fmt.Errorf("exact-gc: send gate row size: %w", err)
		}
		for _, label := range row {
			if err := conn.SendLabel(label, &labelData); err != nil {
				return fmt.Errorf("exact-gc: send garbled gate: %w", err)
			}
		}
	}

	garblerBits := int(circ.Inputs[0].Type.Bits)
	for i := 0; i < garblerBits; i++ {
		label := circuit.LabelForBit(garbled.Wires[i], input.Bit(i) == 1)
		if err := conn.SendLabel(label, &labelData); err != nil {
			return fmt.Errorf("exact-gc: send garbler input: %w", err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush garbled circuit: %w", err)
	}

	oti := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := oti.InitSender(conn); err != nil {
		return fmt.Errorf("exact-gc: initialize OT sender: %w", err)
	}
	offset, err := conn.ReceiveUint32()
	if err != nil {
		return fmt.Errorf("exact-gc: receive OT offset: %w", err)
	}
	count, err := conn.ReceiveUint32()
	if err != nil {
		return fmt.Errorf("exact-gc: receive OT count: %w", err)
	}
	evaluatorBits := int(circ.Inputs[1].Type.Bits)
	if offset != garblerBits || count != evaluatorBits {
		return fmt.Errorf("exact-gc: invalid evaluator OT range")
	}
	if err := oti.Send(garbled.Wires[offset : offset+count]); err != nil {
		return fmt.Errorf("exact-gc: transfer evaluator inputs: %w", err)
	}

	decode := make([]byte, (circ.Outputs.Size()+7)/8)
	firstOutput := circ.NumWires - circ.Outputs.Size()
	for i := 0; i < circ.Outputs.Size(); i++ {
		if garbled.Wires[firstOutput+i].L0.S() {
			decode[i/8] |= 1 << uint(i%8)
		}
	}
	if err := conn.SendData(decode); err != nil {
		return fmt.Errorf("exact-gc: send output decoding mask: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc: flush output decoding mask: %w", err)
	}
	done, err := conn.ReceiveData()
	if err != nil {
		return fmt.Errorf("exact-gc: receive completion: %w", err)
	}
	expectedDone := exactGCDoneDigest(digest)
	if !bytes.Equal(done, expectedDone[:]) {
		return fmt.Errorf("exact-gc: invalid completion acknowledgement")
	}
	return nil
}

func exactGCEvaluatorProtocol(conn *p2p.Conn, circ *circuit.Circuit,
	input *big.Int, session exactGCSession) (*big.Int, error) {

	digest := exactGCContextDigest(session)
	gotContext, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive context: %w", err)
	}
	if !bytes.Equal(gotContext, digest[:]) {
		return nil, fmt.Errorf("exact-gc: peer context mismatch")
	}
	if err := conn.SendData(digest[:]); err != nil {
		return nil, fmt.Errorf("exact-gc: acknowledge context: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush context acknowledgement: %w", err)
	}

	garblingHashKey, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive garbling key: %w", err)
	}
	if len(garblingHashKey) != 32 {
		return nil, fmt.Errorf("exact-gc: invalid garbling key length")
	}
	gateCount, err := conn.ReceiveUint32()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive gate count: %w", err)
	}
	if gateCount != circ.NumGates {
		return nil, fmt.Errorf("exact-gc: invalid gate count")
	}
	garbled := make([][]ot.Label, circ.NumGates)
	var labelData ot.LabelData
	for i, gate := range circ.Gates {
		count, err := conn.ReceiveUint32()
		if err != nil {
			return nil, fmt.Errorf("exact-gc: receive gate row size: %w", err)
		}
		expected := exactGCGarbledRowSize(gate.Op)
		if count != expected {
			return nil, fmt.Errorf("exact-gc: invalid row size for gate %d", i)
		}
		row := make([]ot.Label, count)
		for j := range row {
			if err := conn.ReceiveLabel(&row[j], &labelData); err != nil {
				return nil, fmt.Errorf("exact-gc: receive garbled gate: %w", err)
			}
		}
		garbled[i] = row
	}

	wires := make([]ot.Label, circ.NumWires)
	garblerBits := int(circ.Inputs[0].Type.Bits)
	for i := 0; i < garblerBits; i++ {
		if err := conn.ReceiveLabel(&wires[i], &labelData); err != nil {
			return nil, fmt.Errorf("exact-gc: receive garbler input: %w", err)
		}
	}

	oti := ot.NewCOT(ot.NewCO(crand.Reader), crand.Reader, true, false)
	if err := oti.InitReceiver(conn); err != nil {
		return nil, fmt.Errorf("exact-gc: initialize OT receiver: %w", err)
	}
	evaluatorBits := int(circ.Inputs[1].Type.Bits)
	if err := conn.SendUint32(garblerBits); err != nil {
		return nil, fmt.Errorf("exact-gc: send OT offset: %w", err)
	}
	if err := conn.SendUint32(evaluatorBits); err != nil {
		return nil, fmt.Errorf("exact-gc: send OT count: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush OT request: %w", err)
	}
	choices := make([]bool, evaluatorBits)
	for i := range choices {
		choices[i] = input.Bit(i) == 1
	}
	if err := oti.Receive(choices, wires[garblerBits:garblerBits+evaluatorBits]); err != nil {
		return nil, fmt.Errorf("exact-gc: receive evaluator inputs: %w", err)
	}
	if err := circ.Eval(garblingHashKey, wires, garbled); err != nil {
		return nil, fmt.Errorf("exact-gc: evaluate circuit: %w", err)
	}

	decode, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc: receive output decoding mask: %w", err)
	}
	if len(decode) != (circ.Outputs.Size()+7)/8 {
		return nil, fmt.Errorf("exact-gc: invalid output decoding mask length")
	}
	result := new(big.Int)
	firstOutput := circ.NumWires - circ.Outputs.Size()
	for i := 0; i < circ.Outputs.Size(); i++ {
		lambda := (decode[i/8] >> uint(i%8)) & 1
		bit := uint(0)
		if wires[firstOutput+i].S() != (lambda == 1) {
			bit = 1
		}
		result.SetBit(result, i, bit)
	}
	done := exactGCDoneDigest(digest)
	if err := conn.SendData(done[:]); err != nil {
		return nil, fmt.Errorf("exact-gc: send completion: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc: flush completion: %w", err)
	}
	return result, nil
}

func exactGCGarbledRowSize(op circuit.Operation) int {
	switch op {
	case circuit.XOR, circuit.XNOR:
		return 0
	case circuit.AND:
		return 2
	case circuit.OR:
		return 3
	case circuit.INV:
		return 1
	default:
		return -1
	}
}

func exactGCDoneDigest(context [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("dsvert-exact-gc-done-v1"))
	h.Write(context[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func exactGCRandomOutputShares(spec exactGCCircuitSpec) ([]*big.Int, error) {
	n := spec.VectorLen
	if spec.Operation == exactGCHybridMulFinalize {
		n++
	} else if spec.Operation == exactGCCountGuard {
		n = 1
	} else if spec.Operation == exactGCMulTruncateChecked {
		n++
	} else if spec.Operation == exactGCAlignmentMaskRing128 {
		n++
	}
	result := make([]*big.Int, n)
	for i := range result {
		bits := spec.RingBits
		if spec.Operation != exactGCCompareSigned &&
			spec.Operation != exactGCTruncateFloor &&
			spec.Operation != exactGCTruncateNearestEven &&
			spec.Operation != exactGCClampCount &&
			spec.Operation != exactGCHybridMulFinalize &&
			spec.Operation != exactGCMulTruncateChecked &&
			spec.Operation != exactGCAlignmentMaskRing128 {
			bits = 1
		}
		if spec.Operation == exactGCHybridMulFinalize && i == spec.VectorLen {
			bits = 1
		}
		if spec.Operation == exactGCMulTruncateChecked && i == spec.VectorLen {
			bits = 1
		}
		if spec.Operation == exactGCAlignmentMaskRing128 && i == spec.VectorLen {
			bits = 1
		}
		v, err := crand.Int(crand.Reader, exactGCModulus(bits))
		if err != nil {
			return nil, fmt.Errorf("exact-gc: generate output share: %w", err)
		}
		result[i] = v
	}
	return result, nil
}

func exactGCPackGarblerInput(shares, masks []*big.Int,
	spec exactGCCircuitSpec) *big.Int {
	if spec.Operation == exactGCTruncateFloor ||
		spec.Operation == exactGCTruncateNearestEven ||
		spec.Operation == exactGCClampCount {
		values := append(append([]*big.Int{}, shares...), masks...)
		return exactGCPackChunks(values, exactGCTypeBits(spec.RingBits))
	}
	if spec.Operation == exactGCHybridMulFinalize {
		values := make([]*big.Int, 0, 4*spec.VectorLen+1)
		values = append(values, shares...)
		values = append(values, masks...)
		return exactGCPackChunks(values, exactGCTypeBits(spec.RingBits))
	}

	chunks := make([]*big.Int, 0, len(shares)+len(masks))
	chunks = append(chunks, shares...)
	chunks = append(chunks, masks...)
	return exactGCPackChunks(chunks, exactGCTypeBits(spec.RingBits))
}

func exactGCPackChunks(values []*big.Int, width int) *big.Int {
	result := new(big.Int)
	for i, value := range values {
		part := new(big.Int).Lsh(new(big.Int).Set(value), uint(i*width))
		result.Or(result, part)
	}
	return result
}

func exactGCUnpackOutputs(value *big.Int, spec exactGCCircuitSpec) []*big.Int {
	count := spec.VectorLen
	stride := exactGCTypeBits(spec.RingBits)
	valueBits := spec.RingBits
	if spec.Operation == exactGCCountGuard {
		count, stride, valueBits = 1, 1, 1
	}
	if spec.Operation == exactGCHybridMulFinalize {
		count++
	}
	if spec.Operation == exactGCMulTruncateChecked {
		count++
	}
	if spec.Operation == exactGCAlignmentMaskRing128 {
		count++
	}
	result := make([]*big.Int, count)
	for i := range result {
		result[i] = new(big.Int).Rsh(new(big.Int).Set(value), uint(i*stride))
		bits := valueBits
		if spec.Operation == exactGCHybridMulFinalize && i == spec.VectorLen {
			bits = 1
		}
		if spec.Operation == exactGCMulTruncateChecked && i == spec.VectorLen {
			bits = 1
		}
		if spec.Operation == exactGCAlignmentMaskRing128 && i == spec.VectorLen {
			bits = 1
		}
		result[i].And(result[i], exactGCMask(bits))
	}
	return result
}

func exactGCTypeBits(ringBits int) int {
	result := 64
	for result < ringBits {
		result <<= 1
	}
	return result
}

func exactGCMaxDirectMulChunk(ringBits int) int {
	typeBits := exactGCTypeBits(ringBits)
	if typeBits < 1 || typeBits > exactGCMaxRingBits {
		return 0
	}
	byTypedInput := (exactGCMaxCircuitTypeBits/typeBits - 1) / 7
	byMulWork := exactGCMaxDirectMulBitWork / (typeBits * typeBits)
	result := exactGCMaxDirectMulLen
	if byTypedInput < result {
		result = byTypedInput
	}
	if byMulWork < result {
		result = byMulWork
	}
	if result < 0 {
		return 0
	}
	return result
}

func exactGCCompileCircuit(spec exactGCCircuitSpec) (*circuit.Circuit, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if spec.Operation == exactGCJointDPLaplace {
		return nil, fmt.Errorf("exact-gc: joint-DP circuits require the purpose-bound specialised runner")
	}
	if spec.Operation == jointDPGaussianOneDrawOperation {
		return nil, fmt.Errorf("exact-gc: one-draw Gaussian circuits require the purpose-bound specialised runner")
	}
	if spec.Operation == exactGCFormalGLMOneIteration ||
		spec.Operation == exactGCFormalGLMDPBridge {
		return nil, fmt.Errorf("exact-gc: formal GLM circuits require the purpose-bound specialised runner")
	}
	if spec.Operation == exactGCFormalCoxIterations {
		return nil, fmt.Errorf("exact-gc: formal Cox circuits require the purpose-bound internal runner")
	}
	if spec.Operation == exactGCCRTToRingChecked {
		return nil, fmt.Errorf("exact-gc: checked CRT-to-Ring circuits require the purpose-bound specialised runner")
	}
	if spec.Operation == exactGCMulTruncateChecked &&
		spec.MulBackend == exactGCMulBackendDirect &&
		spec.VectorLen > exactGCMaxDirectMulChunk(spec.RingBits) {
		return nil, fmt.Errorf("exact-gc: direct checked multiplication circuit exceeds policy")
	}
	key := exactGCCircuitCacheKey(spec)
	exactGCCircuitCache.Lock()
	if cached, ok := exactGCCircuitCache.entries[key]; ok {
		exactGCCircuitCache.Unlock()
		return cached, nil
	}
	exactGCCircuitCache.Unlock()
	source := exactGCCircuitSource(spec)
	params := utils.NewParams()
	circ, _, err := compiler.New(params).Compile(source, nil)
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("exact-gc: compile %s circuit: %w", spec.Operation, err))
	}
	wantOutputs := 1
	if spec.Operation == exactGCTruncateFloor ||
		spec.Operation == exactGCTruncateNearestEven ||
		spec.Operation == exactGCClampCount {
		wantOutputs = spec.VectorLen
	} else if spec.Operation == exactGCHybridMulFinalize {
		wantOutputs = spec.VectorLen + 1
	}
	if len(circ.Inputs) != 2 || len(circ.Outputs) != wantOutputs {
		return nil, fmt.Errorf("exact-gc: compiler produced invalid circuit arity")
	}
	exactGCCircuitCache.Lock()
	defer exactGCCircuitCache.Unlock()
	if cached, ok := exactGCCircuitCache.entries[key]; ok {
		return cached, nil
	}
	if len(exactGCCircuitCache.order) == exactGCCircuitCacheEntries {
		oldest := exactGCCircuitCache.order[0]
		delete(exactGCCircuitCache.entries, oldest)
		exactGCCircuitCache.order = exactGCCircuitCache.order[1:]
	}
	exactGCCircuitCache.entries[key] = circ
	exactGCCircuitCache.order = append(exactGCCircuitCache.order, key)
	return circ, nil
}

func exactGCCircuitCacheKey(spec exactGCCircuitSpec) string {
	threshold := ""
	if spec.Threshold != nil {
		threshold = spec.Threshold.String()
	}
	boundX, boundY := "", ""
	if spec.BoundX != nil {
		boundX = spec.BoundX.String()
	}
	if spec.BoundY != nil {
		boundY = spec.BoundY.String()
	}
	return fmt.Sprintf("%s/%d/%d/%s/%s/%s/%s/%d", spec.Operation, spec.RingBits,
		spec.FracBits, threshold, boundX, boundY, spec.MulBackend, spec.VectorLen)
}

func exactGCCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	n := spec.VectorLen

	switch spec.Operation {
	case exactGCCompareSigned:
		thresholdResidue := new(big.Int).Set(spec.Threshold)
		if thresholdResidue.Sign() < 0 {
			thresholdResidue.Add(thresholdResidue, exactGCModulus(spec.RingBits))
		}
		less := fmt.Sprintf("((x[i] & %s(0x%s)) != 0) || x[i] < %s(%s)",
			uintType, sign, uintType, thresholdResidue.String())
		if spec.Threshold.Sign() < 0 {
			less = fmt.Sprintf("((x[i] & %s(0x%s)) != 0) && x[i] < %s(%s)",
				uintType, sign, uintType, thresholdResidue.String())
		}
		return fmt.Sprintf(`package main
func main(g [%d]%s, e [%d]%s) [%d]%s {
	var out [%d]%s
	var x [%d]%s
	for i := 0; i < %d; i++ {
		x[i] = (g[i] + e[i]) & %s(0x%s)
		out[i] = (%s(0) - g[%d+i]) & %s(0x%s)
		if %s { out[i] = (%s(1) - g[%d+i]) & %s(0x%s) }
	}
	return out
}
`, 2*n, uintType, n, uintType, n, uintType, n, uintType, n, uintType, n,
			uintType, mask,
			uintType, n, uintType, mask, less, uintType, n, uintType, mask)

	case exactGCTruncateFloor:
		return exactGCTruncateCircuitSource(spec)

	case exactGCTruncateNearestEven:
		return exactGCTruncateNearestEvenCircuitSource(spec)

	case exactGCMulTruncateChecked:
		return exactGCMulTruncateCircuitSource(spec)

	case exactGCHybridMulFinalize:
		return exactGCHybridMulFinalizeCircuitSource(spec)

	case exactGCCountGuard:
		return fmt.Sprintf(`package main
func main(g [%d]%s, e [%d]%s) bool {
	valid := true
	var x [%d]%s
	var nonnegative [%d]bool
	for i := 0; i < %d; i++ {
		x[i] = (g[i] + e[i]) & %s(0x%s)
		nonnegative[i] = (x[i] & %s(0x%s)) == 0
		valid = valid && (x[i] == 0 || (nonnegative[i] && x[i] >= %s(%s)))
	}
	return valid != ((g[%d] & 1) != 0)
}
`, n+1, uintType, n, uintType, n, uintType, n, n, uintType, mask,
			uintType, sign, uintType, spec.Threshold.String(), n)
	case exactGCClampCount:
		return exactGCClampCountCircuitSource(spec)
	case exactGCAlignmentMaskRing128:
		return exactGCAlignmentMaskCircuitSource(spec)
	default:
		panic("validated exact-gc operation is missing a circuit")
	}
}

// exactGCAlignmentMaskCircuitSource reconstructs each private alignment
// digest only inside the GC, checks non-zero all-K equality, and masks the
// complete value chunk on failure. The circuit has one public, K/n-dependent
// shape for both success and every mismatch location. Its final bit remains
// XOR shared and is opened only by the purpose-specific terminal adapter after
// all chunks have completed.
func exactGCAlignmentMaskCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	n := spec.VectorLen
	k := int(spec.Threshold.Int64())
	inputCount := n + 2*k
	var source strings.Builder
	fmt.Fprintf(&source,
		"package main\nfunc main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		2*n+2*k+1, uintType, inputCount, uintType, n+1, uintType)
	fmt.Fprintf(&source, "\tvar out [%d]%s\n", n+1, uintType)
	source.WriteString("\tvalid := true\n\tnonzero := false\n")
	for custodian := 0; custodian < k; custodian++ {
		for limb := 0; limb < 2; limb++ {
			index := n + 2*custodian + limb
			fmt.Fprintf(&source,
				"\td%d_%d := g[%d] ^ e[%d]\n", custodian, limb, index, index)
			fmt.Fprintf(&source,
				"\tnonzero = nonzero || d%d_%d != %s(0)\n",
				custodian, limb, uintType)
			if custodian > 0 {
				fmt.Fprintf(&source,
					"\tvalid = valid && d%d_%d == d0_%d\n",
					custodian, limb, limb)
			}
		}
	}
	source.WriteString("\tvalid = valid && nonzero\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source,
			"\tv%d := (g[%d] + e[%d]) & %s(0x%s)\n",
			i, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tif !valid { v%d = %s(0) }\n", i, uintType)
		fmt.Fprintf(&source,
			"\tout[%d] = (v%d - g[%d]) & %s(0x%s)\n",
			i, i, inputCount+i, uintType, mask)
	}
	fmt.Fprintf(&source, "\tout[%d] = %s(0)\n", n, uintType)
	fmt.Fprintf(&source,
		"\tif valid != ((g[%d] & %s(1)) != 0) { out[%d] = %s(1) }\n",
		inputCount+n, uintType, n, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String()
}

// exactGCClampCountCircuitSource reconstructs a signed Ring2^k value only
// inside the garbled circuit, clamps it once to the public interval
// [0, Threshold], and returns a freshly masked additive share.  In
// particular, neither party nor the relay receives the pre-clamp value.
func exactGCClampCountCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	n := spec.VectorLen
	var source strings.Builder
	source.WriteString("package main\n")
	source.WriteString("type Garbler struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tOutputMask%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("type Evaluator struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("func main(g Garbler, e Evaluator) (\n")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n")
		}
		fmt.Fprintf(&source, "\t%s", uintType)
	}
	source.WriteString("\n) {\n")
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		fmt.Fprintf(&source,
			"\tvalue%s := (g.Share%d + e.Share%d) & %s(0x%s)\n",
			suffix, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tresult%s := value%s\n", suffix, suffix)
		fmt.Fprintf(&source,
			"\tif (value%s & %s(0x%s)) != 0 { result%s = 0 }\n",
			suffix, uintType, sign, suffix)
		fmt.Fprintf(&source,
			"\tif (value%s & %s(0x%s)) == 0 && value%s > %s(%s) { result%s = %s(%s) }\n",
			suffix, uintType, sign, suffix, uintType, spec.Threshold.String(),
			suffix, uintType, spec.Threshold.String())
		fmt.Fprintf(&source,
			"\toutput%s := (result%s - g.OutputMask%d) & %s(0x%s)\n",
			suffix, suffix, i, uintType, mask)
	}
	source.WriteString("\treturn ")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n\t\t")
		}
		fmt.Fprintf(&source, "output%d", i)
	}
	source.WriteString("\n}\n")
	return source.String()
}

func exactGCTruncateCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	signCorrection := new(big.Int).Lsh(
		big.NewInt(1), uint(spec.RingBits-spec.FracBits)).Text(16)
	n := spec.VectorLen
	var source strings.Builder
	source.WriteString("package main\n")
	source.WriteString("type Garbler struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tOutputMask%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("type Evaluator struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("func main(g Garbler, e Evaluator) (\n")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n")
		}
		fmt.Fprintf(&source, "\t%s", uintType)
	}
	source.WriteString("\n) {\n")
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		fmt.Fprintf(&source,
			"\tvalue%s := (g.Share%d + e.Share%d) & %s(0x%s)\n",
			suffix, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tresult%s := value%s >> %d\n",
			suffix, suffix, spec.FracBits)
		if spec.FracBits > 0 {
			fmt.Fprintf(&source,
				"\tif (value%s & %s(0x%s)) != 0 { result%s = (result%s - %s(0x%s)) & %s(0x%s) }\n",
				suffix, uintType, sign, suffix, suffix, uintType, signCorrection,
				uintType, mask)
		}
		fmt.Fprintf(&source,
			"\toutput%s := (result%s - g.OutputMask%d) & %s(0x%s)\n",
			suffix, suffix, i, uintType, mask)
	}
	source.WriteString("\treturn ")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n\t\t")
		}
		fmt.Fprintf(&source, "output%d", i)
	}
	source.WriteString("\n}\n")
	return source.String()
}

func exactGCTruncateNearestEvenCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	fracMask := new(big.Int)
	half := new(big.Int)
	if spec.FracBits > 0 {
		fracMask.Sub(new(big.Int).Lsh(big.NewInt(1), uint(spec.FracBits)),
			big.NewInt(1))
		half.Lsh(big.NewInt(1), uint(spec.FracBits-1))
	}
	n := spec.VectorLen
	var source strings.Builder
	source.WriteString("package main\n")
	source.WriteString("type Garbler struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tOutputMask%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("type Evaluator struct {\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tShare%d %s\n", i, uintType)
	}
	source.WriteString("}\n")
	source.WriteString("func main(g Garbler, e Evaluator) (\n")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n")
		}
		fmt.Fprintf(&source, "\t%s", uintType)
	}
	source.WriteString("\n) {\n")
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		fmt.Fprintf(&source,
			"\tvalue%s := (g.Share%d + e.Share%d) & %s(0x%s)\n",
			suffix, i, i, uintType, mask)
		fmt.Fprintf(&source,
			"\tnegative%s := (value%s & %s(0x%s)) != 0\n",
			suffix, suffix, uintType, sign)
		fmt.Fprintf(&source, "\tmagnitude%s := value%s\n", suffix, suffix)
		fmt.Fprintf(&source,
			"\tif negative%s { magnitude%s = (%s(0) - value%s) & %s(0x%s) }\n",
			suffix, suffix, uintType, suffix, uintType, mask)
		fmt.Fprintf(&source, "\tresult%s := magnitude%s >> %d\n",
			suffix, suffix, spec.FracBits)
		if spec.FracBits > 0 {
			fmt.Fprintf(&source,
				"\tremainder%s := magnitude%s & %s(0x%s)\n",
				suffix, suffix, uintType, fracMask.Text(16))
			fmt.Fprintf(&source,
				"\tif remainder%s > %s(0x%s) || (remainder%s == %s(0x%s) && (result%s & 1) != 0) { result%s = result%s + 1 }\n",
				suffix, uintType, half.Text(16), suffix, uintType, half.Text(16),
				suffix, suffix, suffix)
		}
		fmt.Fprintf(&source,
			"\tif negative%s { result%s = (%s(0) - result%s) & %s(0x%s) }\n",
			suffix, suffix, uintType, suffix, uintType, mask)
		fmt.Fprintf(&source,
			"\toutput%s := (result%s - g.OutputMask%d) & %s(0x%s)\n",
			suffix, suffix, i, uintType, mask)
	}
	source.WriteString("\treturn ")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n\t\t")
		}
		fmt.Fprintf(&source, "output%d", i)
	}
	source.WriteString("\n}\n")
	return source.String()
}

func exactGCHybridMulFinalizeCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	signCorrection := new(big.Int).Lsh(
		big.NewInt(1), uint(spec.RingBits-spec.FracBits)).Text(16)
	n := spec.VectorLen
	var source strings.Builder
	source.WriteString("package main\n")
	source.WriteString("type Garbler struct {\n")
	for _, share := range []string{"Raw", "X", "Y"} {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&source, "\t%sShare%d %s\n", share, i, uintType)
		}
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tOutputMask%d %s\n", i, uintType)
	}
	fmt.Fprintf(&source, "\tValidityMask %s\n", uintType)
	source.WriteString("}\n")
	source.WriteString("type Evaluator struct {\n")
	for _, share := range []string{"Raw", "X", "Y"} {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&source, "\t%sShare%d %s\n", share, i, uintType)
		}
	}
	source.WriteString("}\n")
	source.WriteString("func main(g Garbler, e Evaluator) (\n")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n")
		}
		fmt.Fprintf(&source, "\t%s", uintType)
	}
	source.WriteString(",\n\tbool\n) {\n")
	source.WriteString("\tallValid := true\n")
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		fmt.Fprintf(&source,
			"\trawValue%s := (g.RawShare%d + e.RawShare%d) & %s(0x%s)\n",
			suffix, i, i, uintType, mask)
		fmt.Fprintf(&source, "\tresult%s := rawValue%s >> %d\n",
			suffix, suffix, spec.FracBits)
		fmt.Fprintf(&source,
			"\tif (rawValue%s & %s(0x%s)) != 0 { result%s = (result%s - %s(0x%s)) & %s(0x%s) }\n",
			suffix, uintType, sign, suffix, suffix, uintType, signCorrection,
			uintType, mask)

		for _, operand := range []string{"X", "Y"} {
			name := strings.ToLower(operand)
			fmt.Fprintf(&source,
				"\t%sValue%s := (g.%sShare%d + e.%sShare%d) & %s(0x%s)\n",
				name, suffix, operand, i, operand, i, uintType, mask)
			fmt.Fprintf(&source,
				"\t%sNegative%s := (%sValue%s & %s(0x%s)) != 0\n",
				name, suffix, name, suffix, uintType, sign)
			fmt.Fprintf(&source, "\t%sMagnitude%s := %sValue%s\n",
				name, suffix, name, suffix)
			fmt.Fprintf(&source,
				"\tif %sNegative%s { %sMagnitude%s = (%s(0) - %sValue%s) & %s(0x%s) }\n",
				name, suffix, name, suffix, uintType, name, suffix, uintType, mask)
		}
		fmt.Fprintf(&source,
			"\tvalid%s := xMagnitude%s <= %s(%s) && yMagnitude%s <= %s(%s)\n",
			suffix, suffix, uintType, spec.BoundX.String(), suffix, uintType,
			spec.BoundY.String())
		fmt.Fprintf(&source, "\tallValid = allValid && valid%s\n", suffix)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tif !allValid { result%d = 0 }\n", i)
		fmt.Fprintf(&source,
			"\toutput%d := (result%d - g.OutputMask%d) & %s(0x%s)\n",
			i, i, i, uintType, mask)
	}
	source.WriteString("\treturn ")
	for i := 0; i < n; i++ {
		if i > 0 {
			source.WriteString(",\n\t\t")
		}
		fmt.Fprintf(&source, "output%d", i)
	}
	source.WriteString(",\n\t\tallValid != ((g.ValidityMask & 1) != 0)\n}\n")
	return source.String()
}

func exactGCMulTruncateCircuitSource(spec exactGCCircuitSpec) string {
	typeBits := exactGCTypeBits(spec.RingBits)
	uintType := fmt.Sprintf("uint%d", typeBits)
	wideType := fmt.Sprintf("uint%d", 2*typeBits)
	mask := exactGCMask(spec.RingBits).Text(16)
	sign := new(big.Int).Lsh(big.NewInt(1), uint(spec.RingBits-1)).Text(16)
	fracMask := new(big.Int)
	if spec.FracBits > 0 {
		fracMask.Sub(new(big.Int).Lsh(big.NewInt(1), uint(spec.FracBits)),
			big.NewInt(1))
	}
	maxSigned := exactGCMaxSigned(spec.RingBits).Text(16)
	n := spec.VectorLen
	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		3*n+1, uintType, 2*n, uintType, n+1, uintType)
	fmt.Fprintf(&source, "\tvar out [%d]%s\n\tallValid := true\n", n+1, uintType)
	for i := 0; i < n; i++ {
		suffix := fmt.Sprintf("%d", i)
		fmt.Fprintf(&source, "\tx%s := (g[%d] + e[%d]) & %s(0x%s)\n",
			suffix, i, i, uintType, mask)
		fmt.Fprintf(&source, "\ty%s := (g[%d] + e[%d]) & %s(0x%s)\n",
			suffix, n+i, n+i, uintType, mask)
		fmt.Fprintf(&source, "\txNegative%s := (x%s & %s(0x%s)) != 0\n",
			suffix, suffix, uintType, sign)
		fmt.Fprintf(&source, "\tyNegative%s := (y%s & %s(0x%s)) != 0\n",
			suffix, suffix, uintType, sign)
		fmt.Fprintf(&source, "\txMagnitude%s := x%s\n\tyMagnitude%s := y%s\n",
			suffix, suffix, suffix, suffix)
		fmt.Fprintf(&source,
			"\tif xNegative%s { xMagnitude%s = (%s(0) - x%s) & %s(0x%s) }\n",
			suffix, suffix, uintType, suffix, uintType, mask)
		fmt.Fprintf(&source,
			"\tif yNegative%s { yMagnitude%s = (%s(0) - y%s) & %s(0x%s) }\n",
			suffix, suffix, uintType, suffix, uintType, mask)
		fmt.Fprintf(&source,
			"\tvalid%s := xMagnitude%s <= %s(%s) && yMagnitude%s <= %s(%s)\n",
			suffix, suffix, uintType, spec.BoundX.String(), suffix, uintType,
			spec.BoundY.String())
		fmt.Fprintf(&source, "\tproduct%s := wideMul(xMagnitude%s, yMagnitude%s)\n",
			suffix, suffix, suffix)
		fmt.Fprintf(&source, "\tquotient%s := product%s >> %d\n",
			suffix, suffix, spec.FracBits)
		fmt.Fprintf(&source, "\tremainder%s := product%s & %s(0x%s)\n",
			suffix, suffix, wideType, fracMask.Text(16))
		fmt.Fprintf(&source, "\tnegative%s := xNegative%s != yNegative%s\n",
			suffix, suffix, suffix)
		fmt.Fprintf(&source,
			"\tif negative%s && remainder%s != 0 {\n", suffix, suffix)
		fmt.Fprintf(&source, "\t\tquotient%s = quotient%s + 1\n\t}\n",
			suffix, suffix)
		fmt.Fprintf(&source, "\tif negative%s {\n", suffix)
		fmt.Fprintf(&source,
			"\t\tvalid%s = valid%s && quotient%s <= %s(0x%s)\n",
			suffix, suffix, suffix, wideType, sign)
		fmt.Fprintf(&source, "\t} else {\n")
		fmt.Fprintf(&source,
			"\t\tvalid%s = valid%s && quotient%s <= %s(0x%s)\n\t}\n",
			suffix, suffix, suffix, wideType, maxSigned)
		fmt.Fprintf(&source, "\tmagnitude%s := %s(quotient%s)\n",
			suffix, uintType, suffix)
		fmt.Fprintf(&source, "\tresult%s := magnitude%s\n", suffix, suffix)
		fmt.Fprintf(&source,
			"\tif negative%s { result%s = (%s(0) - magnitude%s) & %s(0x%s) }\n",
			suffix, suffix, uintType, suffix, uintType, mask)
		fmt.Fprintf(&source, "\tif !valid%s { result%s = 0 }\n", suffix, suffix)
		fmt.Fprintf(&source, "\tallValid = allValid && valid%s\n", suffix)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&source, "\tif !allValid { result%d = 0 }\n", i)
		fmt.Fprintf(&source,
			"\tout[%d] = (result%d - g[%d]) & %s(0x%s)\n",
			i, i, 2*n+i, uintType, mask)
	}
	fmt.Fprintf(&source, "\tout[%d] = %s(0)\n", n, uintType)
	fmt.Fprintf(&source, "\tif allValid != ((g[%d] & 1) != 0) { out[%d] = %s(1) }\n",
		3*n, n, uintType)
	source.WriteString("\treturn out\n}\n")
	return source.String()
}

// Reference functions below are intentionally independent of the circuit
// compiler. They specify exact arithmetic for exhaustive and property tests.

func exactGCReferenceReconstruct(a, b *big.Int, bits int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, exactGCModulus(bits))
}

func exactGCReferenceSigned(residue *big.Int, bits int) *big.Int {
	result := new(big.Int).Set(residue)
	if result.Bit(bits-1) == 1 {
		result.Sub(result, exactGCModulus(bits))
	}
	return result
}

func exactGCReferenceCompare(a, b, threshold *big.Int, bits int) bool {
	x := exactGCReferenceSigned(exactGCReferenceReconstruct(a, b, bits), bits)
	return x.Cmp(threshold) < 0
}

func exactGCReferenceClampCount(a, b, upper *big.Int, bits int) *big.Int {
	x := exactGCReferenceSigned(exactGCReferenceReconstruct(a, b, bits), bits)
	if x.Sign() < 0 {
		return big.NewInt(0)
	}
	if x.Cmp(upper) > 0 {
		return new(big.Int).Set(upper)
	}
	return x
}

func exactGCReferenceTruncateFloor(a, b *big.Int, bits, fracBits int) *big.Int {
	x := exactGCReferenceSigned(exactGCReferenceReconstruct(a, b, bits), bits)
	denom := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(x, denom, rem)
	if x.Sign() < 0 && rem.Sign() != 0 {
		q.Sub(q, big.NewInt(1))
	}
	return q.Mod(q, exactGCModulus(bits))
}

func exactGCReferenceTruncateNearestEven(a, b *big.Int, bits,
	fracBits int) *big.Int {

	x := exactGCReferenceSigned(exactGCReferenceReconstruct(a, b, bits), bits)
	negative := x.Sign() < 0
	magnitude := new(big.Int).Abs(new(big.Int).Set(x))
	denom := new(big.Int).Lsh(big.NewInt(1), uint(fracBits))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(magnitude, denom, remainder)
	twiceRemainder := new(big.Int).Lsh(new(big.Int).Set(remainder), 1)
	comparison := twiceRemainder.Cmp(denom)
	if comparison > 0 || (comparison == 0 && quotient.Bit(0) == 1) {
		quotient.Add(quotient, big.NewInt(1))
	}
	if negative {
		quotient.Neg(quotient)
	}
	return quotient.Mod(quotient, exactGCModulus(bits))
}

func exactGCReferenceMulTruncateChecked(xa, xb, ya, yb *big.Int,
	spec exactGCCircuitSpec) (*big.Int, bool) {

	x := exactGCReferenceSigned(exactGCReferenceReconstruct(xa, xb,
		spec.RingBits), spec.RingBits)
	y := exactGCReferenceSigned(exactGCReferenceReconstruct(ya, yb,
		spec.RingBits), spec.RingBits)
	ax, ay := new(big.Int).Abs(new(big.Int).Set(x)),
		new(big.Int).Abs(new(big.Int).Set(y))
	if ax.Cmp(spec.BoundX) > 0 || ay.Cmp(spec.BoundY) > 0 {
		return big.NewInt(0), false
	}
	product := new(big.Int).Mul(x, y)
	denom := new(big.Int).Lsh(big.NewInt(1), uint(spec.FracBits))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, denom, remainder)
	if product.Sign() < 0 && remainder.Sign() != 0 {
		quotient.Sub(quotient, big.NewInt(1))
	}
	if !exactGCFitsSigned(quotient, spec.RingBits) {
		return big.NewInt(0), false
	}
	return quotient.Mod(quotient, exactGCModulus(spec.RingBits)), true
}

func exactGCReferenceCountGuard(a, b []*big.Int, threshold *big.Int,
	bits int) bool {
	for i := range a {
		x := exactGCReferenceReconstruct(a[i], b[i], bits)
		if x.Bit(bits-1) == 1 {
			return false
		}
		if x.Sign() != 0 && x.Cmp(threshold) < 0 {
			return false
		}
	}
	return true
}

func exactGCContextDigest(session exactGCSession) [32]byte {
	threshold := ""
	if session.Spec.Threshold != nil {
		threshold = session.Spec.Threshold.String()
	}
	canonical := strings.Join([]string{
		"dsvert-exact-gc-context-v2",
		fmt.Sprintf("%x", session.SessionID[:]),
		session.GarblerID,
		session.EvaluatorID,
		session.Purpose,
		string(session.Spec.Operation),
		exactGCRoundingMode(session.Spec),
		fmt.Sprintf("%d", session.Spec.RingBits),
		fmt.Sprintf("%d", session.Spec.FracBits),
		threshold,
		exactGCOptionalIntString(session.Spec.BoundX),
		exactGCOptionalIntString(session.Spec.BoundY),
		string(session.Spec.MulBackend),
		fmt.Sprintf("%d", session.Spec.VectorLen),
	}, "\x00")
	return sha256.Sum256([]byte(canonical))
}

func exactGCRoundingMode(spec exactGCCircuitSpec) string {
	switch spec.Operation {
	case exactGCTruncateFloor, exactGCMulTruncateChecked,
		exactGCHybridMulFinalize:
		return "floor"
	case exactGCTruncateNearestEven:
		return "nearest-ties-to-even"
	case exactGCFormalGLMOneIteration:
		return "formal-glm-fixed-dag-signed-floor-v1"
	case exactGCFormalGLMDPBridge:
		return "formal-glm-signed-floor-quantize-ring128-share-v1"
	case exactGCCRTToRingChecked:
		return "exact-crt-signed-map-and-bound-v1"
	default:
		return ""
	}
}

func exactGCOptionalIntString(value *big.Int) string {
	if value == nil {
		return ""
	}
	return value.String()
}
