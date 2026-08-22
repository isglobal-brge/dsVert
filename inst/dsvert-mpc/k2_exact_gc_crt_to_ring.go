// k2_exact_gc_crt_to_ring.go -- exact private CRT-to-Ring conversion.
//
// Linear HE works over independent odd-prime plaintext lanes whereas the
// nonlinear dsVert kernels use additive shares in Z/2^kZ.  Decoding the CRT
// value at either peer would open the protected aggregate.  This specialised
// circuit therefore performs the entire boundary conversion privately and
// emits only fresh additive Ring shares plus a one-bit shared validity gate.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

const (
	exactGCCRTToRingVersion        = "dsvert-exact-gc-crt-to-ring-v1"
	exactGCCRTToRingMaxModuli      = 16
	exactGCCRTToRingMaxCoordinates = 64
	exactGCCRTMaskedHeaderBytes    = 48
)

var exactGCCRTMaskedMagic = [8]byte{'D', 'V', 'C', 'R', 'T', 'M', '1', 0}

// exactGCCRTToRingSpec is server-authored public numeric policy.  Moduli are
// the HE plaintext primes and MagnitudeBound is the proved bound M satisfying
// P=product(Moduli)>2M.  RingBits is the target Z/2^kZ share width.
type exactGCCRTToRingSpec struct {
	RingBits           int
	Moduli             []uint64
	MagnitudeBound     *big.Int
	CustodianCount     int
	TotalCoordinates   int
	ChunkStart         int
	VectorLen          int
	ReleaseBinding     [32]byte
	SourceSnapshotHMAC [32]byte
	PinsetHash         [32]byte
	ArithmeticCertHash [32]byte
}

func (s exactGCCRTToRingSpec) product() *big.Int {
	product := big.NewInt(1)
	for _, modulus := range s.Moduli {
		product.Mul(product, new(big.Int).SetUint64(modulus))
	}
	return product
}

func (s exactGCCRTToRingSpec) typeBits() int {
	bits := s.RingBits
	// The circuit adds two values in [0,P), so reserve the carry bit as
	// well as the complete CRT product.
	if productBits := s.product().BitLen() + 1; productBits > bits {
		bits = productBits
	}
	return exactGCTypeBits(bits)
}

func (s exactGCCRTToRingSpec) validate() error {
	if s.RingBits != 63 && s.RingBits != 127 && s.RingBits != 257 {
		return fmt.Errorf("exact-gc-crt: target ring must be Ring63, Ring127 or Ring257")
	}
	if s.VectorLen < 1 || s.VectorLen > exactGCCRTToRingMaxCoordinates {
		return fmt.Errorf("exact-gc-crt: vector length must be in [1,%d]",
			exactGCCRTToRingMaxCoordinates)
	}
	if s.CustodianCount < 2 {
		return fmt.Errorf("exact-gc-crt: at least two upstream custodians are required")
	}
	if s.TotalCoordinates < 1 || s.ChunkStart < 0 ||
		s.ChunkStart > s.TotalCoordinates ||
		s.VectorLen > s.TotalCoordinates-s.ChunkStart {
		return fmt.Errorf("exact-gc-crt: invalid global coordinate interval")
	}
	if s.ReleaseBinding == ([32]byte{}) || s.SourceSnapshotHMAC == ([32]byte{}) ||
		s.PinsetHash == ([32]byte{}) || s.ArithmeticCertHash == ([32]byte{}) {
		return fmt.Errorf("exact-gc-crt: release, opaque snapshot, pinset and arithmetic-certificate bindings must be non-zero")
	}
	if len(s.Moduli) < 2 || len(s.Moduli) > exactGCCRTToRingMaxModuli {
		return fmt.Errorf("exact-gc-crt: CRT lane count must be in [2,%d]",
			exactGCCRTToRingMaxModuli)
	}
	for i, modulus := range s.Moduli {
		// The HE prototype uses 29-bit plaintext primes.  A 31-bit ceiling
		// preserves a no-overflow proof for the sum of two canonical shares.
		if modulus < 3 || modulus >= 1<<31 || modulus&1 == 0 ||
			!new(big.Int).SetUint64(modulus).ProbablyPrime(64) {
			return fmt.Errorf("exact-gc-crt: modulus %d is not an accepted odd prime", i)
		}
		for j := 0; j < i; j++ {
			gcd := new(big.Int).GCD(nil, nil,
				new(big.Int).SetUint64(modulus),
				new(big.Int).SetUint64(s.Moduli[j]))
			if gcd.Cmp(big.NewInt(1)) != 0 {
				return fmt.Errorf("exact-gc-crt: moduli %d and %d are not coprime", j, i)
			}
		}
	}
	if s.MagnitudeBound == nil || s.MagnitudeBound.Sign() < 0 ||
		s.MagnitudeBound.Cmp(exactGCMaxSigned(s.RingBits)) > 0 {
		return fmt.Errorf("exact-gc-crt: magnitude bound is outside signed Ring%d",
			s.RingBits)
	}
	product := s.product()
	if product.Cmp(new(big.Int).Lsh(new(big.Int).Set(s.MagnitudeBound), 1)) <= 0 {
		return fmt.Errorf("exact-gc-crt: CRT product must satisfy P > 2M")
	}
	typeBits := s.typeBits()
	// Garbler: one uniform CRT pad, one Ring output mask and a validity
	// mask. Evaluator: one perfectly masked CRT opening. Raw CRT shares are
	// exchanged only through the authenticated pad phase below.
	inputBits := typeBits * (3*s.VectorLen + 1)
	if inputBits > exactGCMaxCircuitTypeBits {
		return fmt.Errorf("exact-gc-crt: circuit shape exceeds %d typed input bits",
			exactGCMaxCircuitTypeBits)
	}
	if _, err := s.coefficients(); err != nil {
		return err
	}
	return nil
}

// coefficients returns C_i=(P/q_i)*(P/q_i)^-1 mod q_i (mod P).  Thus
// sum(r_i*C_i) mod P is the unique CRT reconstruction in [0,P).
func (s exactGCCRTToRingSpec) coefficients() ([]*big.Int, error) {
	product := s.product()
	coefficients := make([]*big.Int, len(s.Moduli))
	for i, modulus := range s.Moduli {
		q := new(big.Int).SetUint64(modulus)
		partial := new(big.Int).Quo(new(big.Int).Set(product), q)
		inverse := new(big.Int).ModInverse(new(big.Int).Mod(partial, q), q)
		if inverse == nil {
			return nil, fmt.Errorf("exact-gc-crt: modulus %d has no CRT inverse", i)
		}
		coefficient := new(big.Int).Mul(partial, inverse)
		coefficient.Mod(coefficient, product)
		coefficients[i] = coefficient
	}
	return coefficients, nil
}

func (s exactGCCRTToRingSpec) digest() [32]byte {
	release := s.releaseDigest()
	h := sha256.New()
	exactGCCRTWriteField(h, []byte("dsvert-exact-gc-crt-chunk-contract-v1"))
	h.Write(release[:])
	var scalar [8]byte
	for _, value := range []uint64{uint64(s.ChunkStart), uint64(s.VectorLen)} {
		binary.BigEndian.PutUint64(scalar[:], value)
		h.Write(scalar[:])
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// releaseDigest is invariant under transparent re-chunking.  It is used for
// deterministic output masks so coordinate i receives the same share on a
// retry, restart or different safe chunk partition.
func (s exactGCCRTToRingSpec) releaseDigest() [32]byte {
	h := sha256.New()
	exactGCCRTWriteField(h, []byte(exactGCCRTToRingVersion))
	var scalar [8]byte
	for _, value := range []uint64{
		uint64(s.RingBits), uint64(s.CustodianCount),
		uint64(s.TotalCoordinates), uint64(len(s.Moduli)),
	} {
		binary.BigEndian.PutUint64(scalar[:], value)
		h.Write(scalar[:])
	}
	for _, modulus := range s.Moduli {
		binary.BigEndian.PutUint64(scalar[:], modulus)
		h.Write(scalar[:])
	}
	exactGCCRTWriteField(h, s.product().Bytes())
	if s.MagnitudeBound != nil {
		exactGCCRTWriteField(h, s.MagnitudeBound.Bytes())
	} else {
		exactGCCRTWriteField(h, nil)
	}
	h.Write(s.ReleaseBinding[:])
	h.Write(s.SourceSnapshotHMAC[:])
	h.Write(s.PinsetHash[:])
	h.Write(s.ArithmeticCertHash[:])
	exactGCCRTWriteField(h, []byte(
		"sum-shares-mod-qi;crt-[0,P);if-x>P/2-subtract-P;assert-abs<=M;tuple-neutralize;fresh-Z2k-shares"))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// circuitDigest excludes release identity and chunk position because neither
// changes the compiled Boolean function.  This permits safe circuit reuse
// without weakening the separately authenticated session context.
func (s exactGCCRTToRingSpec) circuitDigest() [32]byte {
	h := sha256.New()
	exactGCCRTWriteField(h, []byte("dsvert-exact-gc-crt-circuit-v1"))
	var scalar [8]byte
	for _, value := range []uint64{
		uint64(s.RingBits), uint64(s.VectorLen), uint64(len(s.Moduli)),
	} {
		binary.BigEndian.PutUint64(scalar[:], value)
		h.Write(scalar[:])
	}
	for _, modulus := range s.Moduli {
		binary.BigEndian.PutUint64(scalar[:], modulus)
		h.Write(scalar[:])
	}
	exactGCCRTWriteField(h, s.MagnitudeBound.Bytes())
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func exactGCCRTWriteField(w io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}

func (s exactGCCRTToRingSpec) purpose() string {
	digest := s.digest()
	return "exact-crt-to-ring-v1/" + hex.EncodeToString(digest[:])
}

func exactGCCRTToRingSession(base exactGCSession,
	spec exactGCCRTToRingSpec) exactGCSession {
	base.Purpose = spec.purpose()
	base.Spec = exactGCCircuitSpec{
		Operation: exactGCCRTToRingChecked,
		RingBits:  spec.RingBits,
		VectorLen: spec.VectorLen,
	}
	return base
}

func exactGCCRTValidateSession(session exactGCSession,
	spec exactGCCRTToRingSpec) error {
	if err := spec.validate(); err != nil {
		return err
	}
	if err := session.validate(); err != nil {
		return err
	}
	if session.Spec.Operation != exactGCCRTToRingChecked ||
		session.Spec.RingBits != spec.RingBits || session.Spec.FracBits != 0 ||
		session.Spec.VectorLen != spec.VectorLen || session.Purpose != spec.purpose() {
		return fmt.Errorf("exact-gc-crt: session is not bound to the CRT boundary")
	}
	return nil
}

func exactGCCRTValidateLocalShares(shares [][]uint64,
	spec exactGCCRTToRingSpec) error {
	if len(shares) != spec.VectorLen {
		return fmt.Errorf("exact-gc-crt: got %d coordinates, want %d",
			len(shares), spec.VectorLen)
	}
	for coordinate, lanes := range shares {
		if len(lanes) != len(spec.Moduli) {
			return fmt.Errorf("exact-gc-crt: coordinate %d has %d lanes, want %d",
				coordinate, len(lanes), len(spec.Moduli))
		}
		for lane, value := range lanes {
			if value >= spec.Moduli[lane] {
				return fmt.Errorf("exact-gc-crt: local residue (%d,%d) is not canonical",
					coordinate, lane)
			}
		}
	}
	return nil
}

// CRT circuit source is derived entirely from the public arithmetic and
// release binding specification. Cache only those immutable compiled circuits;
// never cache shares, masks, sessions, or noise material.
const exactGCCRTToRingCacheEntries = 4

var exactGCCRTToRingCache = struct {
	sync.Mutex
	entries map[string]*circuit.Circuit
	order   []string
}{entries: make(map[string]*circuit.Circuit)}

func exactGCCRTToRingCacheTouchLocked(key string) {
	for index, value := range exactGCCRTToRingCache.order {
		if value == key {
			exactGCCRTToRingCache.order = append(
				exactGCCRTToRingCache.order[:index],
				exactGCCRTToRingCache.order[index+1:]...)
			break
		}
	}
	exactGCCRTToRingCache.order = append(exactGCCRTToRingCache.order, key)
}

func exactGCCRTCompile(spec exactGCCRTToRingSpec) (*circuit.Circuit, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	digest := spec.circuitDigest()
	key := hex.EncodeToString(digest[:])
	exactGCCRTToRingCache.Lock()
	if cached := exactGCCRTToRingCache.entries[key]; cached != nil {
		exactGCCRTToRingCacheTouchLocked(key)
		exactGCCRTToRingCache.Unlock()
		return cached, nil
	}
	exactGCCRTToRingCache.Unlock()

	var compiled *circuit.Circuit
	err := jointDPWithMPCLRuntime(func() error {
		var compileErr error
		compiled, _, compileErr = compiler.New(utils.NewParams()).Compile(
			exactGCCRTCircuitSource(spec), nil)
		return compileErr
	})
	if err != nil {
		return nil, exactGCFailure(exactGCFailureNumericBackendUnavailable,
			fmt.Errorf("exact-gc-crt: compile circuit: %w", err))
	}
	if len(compiled.Inputs) != 2 || len(compiled.Outputs) != 1 ||
		compiled.Outputs.Size() != (spec.VectorLen+1)*spec.typeBits() {
		return nil, fmt.Errorf("exact-gc-crt: compiler produced an invalid circuit shape")
	}
	exactGCCRTToRingCache.Lock()
	defer exactGCCRTToRingCache.Unlock()
	if cached := exactGCCRTToRingCache.entries[key]; cached != nil {
		exactGCCRTToRingCacheTouchLocked(key)
		return cached, nil
	}
	if len(exactGCCRTToRingCache.order) >= exactGCCRTToRingCacheEntries {
		oldest := exactGCCRTToRingCache.order[0]
		delete(exactGCCRTToRingCache.entries, oldest)
		exactGCCRTToRingCache.order = exactGCCRTToRingCache.order[1:]
	}
	exactGCCRTToRingCache.entries[key] = compiled
	exactGCCRTToRingCache.order = append(exactGCCRTToRingCache.order, key)
	return compiled, nil
}

func exactGCCRTCircuitSource(spec exactGCCRTToRingSpec) string {
	typeBits := spec.typeBits()
	uintType := fmt.Sprintf("uint%d", typeBits)
	n := spec.VectorLen
	garblerInputs := 2*n + 1
	evaluatorInputs := n
	product := spec.product()
	halfProduct := new(big.Int).Rsh(new(big.Int).Set(product), 1)
	ringMask := exactGCMask(spec.RingBits)

	var source strings.Builder
	fmt.Fprintf(&source, "package main\nfunc main(g [%d]%s, e [%d]%s) [%d]%s {\n",
		garblerInputs, uintType, evaluatorInputs, uintType, n+1, uintType)
	fmt.Fprintf(&source, "\tvar out [%d]%s\n\tallValid := true\n", n+1, uintType)
	for coordinate := 0; coordinate < n; coordinate++ {
		fmt.Fprintf(&source,
			"\tu%d := g[%d] + e[%d]\n\tif u%d >= %s(0x%s) { u%d = u%d - %s(0x%s) }\n",
			coordinate, coordinate, coordinate, coordinate, uintType, product.Text(16),
			coordinate, coordinate, uintType, product.Text(16))
		fmt.Fprintf(&source,
			"\tnegative%d := u%d > %s(0x%s)\n\tmagnitude%d := u%d\n",
			coordinate, coordinate, uintType, halfProduct.Text(16), coordinate, coordinate)
		fmt.Fprintf(&source,
			"\tvalue%d := %s(u%d) & %s(0x%s)\n",
			coordinate, uintType, coordinate, uintType, ringMask.Text(16))
		fmt.Fprintf(&source,
			"\tif negative%d {\n\t\tmagnitude%d = %s(0x%s) - u%d\n\t\tvalue%d = (%s(0) - %s(magnitude%d)) & %s(0x%s)\n\t}\n",
			coordinate, coordinate, uintType, product.Text(16), coordinate, coordinate,
			uintType, uintType, coordinate, uintType, ringMask.Text(16))
		fmt.Fprintf(&source,
			"\tvalid%d := magnitude%d <= %s(0x%s)\n\tallValid = allValid && valid%d\n",
			coordinate, coordinate, uintType, spec.MagnitudeBound.Text(16), coordinate)
	}
	maskBase := n
	for coordinate := 0; coordinate < n; coordinate++ {
		fmt.Fprintf(&source,
			"\tif !allValid { value%d = 0 }\n\tout[%d] = (value%d - g[%d]) & %s(0x%s)\n",
			coordinate, coordinate, coordinate, maskBase+coordinate, uintType,
			ringMask.Text(16))
	}
	fmt.Fprintf(&source,
		"\tout[%d] = g[%d] & 1\n\tif allValid { out[%d] = out[%d] ^ 1 }\n\treturn out\n}\n",
		n, garblerInputs-1, n, n)
	return source.String()
}

func exactGCCRTDeterministicMasks(seed [32]byte,
	spec exactGCCRTToRingSpec) ([]*big.Int, bool, error) {
	if seed == ([32]byte{}) {
		return nil, false, fmt.Errorf("exact-gc-crt: output-mask seed must be non-zero")
	}
	digest := spec.releaseDigest()
	byteLen := (spec.RingBits + 7) / 8
	masks := make([]*big.Int, spec.VectorLen)
	for coordinate := range masks {
		encoded := make([]byte, byteLen)
		for offset, counter := 0, uint64(0); offset < len(encoded); counter++ {
			mac := hmac.New(sha256.New, seed[:])
			mac.Write([]byte("dsvert-exact-gc-crt-output-mask-v1"))
			mac.Write(digest[:])
			var scalar [16]byte
			binary.BigEndian.PutUint64(scalar[:8], uint64(spec.ChunkStart+coordinate))
			binary.BigEndian.PutUint64(scalar[8:], counter)
			mac.Write(scalar[:])
			block := mac.Sum(nil)
			offset += copy(encoded[offset:], block)
			clear(block)
		}
		if remainder := spec.RingBits % 8; remainder != 0 {
			encoded[0] &= byte((1 << remainder) - 1)
		}
		masks[coordinate] = new(big.Int).SetBytes(encoded)
		clear(encoded)
	}
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("dsvert-exact-gc-crt-validity-mask-v1"))
	chunkDigest := spec.digest()
	mac.Write(chunkDigest[:])
	validity := mac.Sum(nil)[0]&1 == 1
	return masks, validity, nil
}

// exactGCCRTDeterministicPads samples a computationally uniform value in
// [0,P) for every global coordinate using rejection sampling from the
// custodian-only root.  Reuse is restricted to the identical logical release;
// source snapshot and release bindings make cross-query pad reuse impossible.
func exactGCCRTDeterministicPads(seed [32]byte,
	spec exactGCCRTToRingSpec) ([]*big.Int, error) {
	if seed == ([32]byte{}) {
		return nil, fmt.Errorf("exact-gc-crt: CRT pad seed must be non-zero")
	}
	product := spec.product()
	bitLen := product.BitLen()
	byteLen := (bitLen + 7) / 8
	release := spec.releaseDigest()
	pads := make([]*big.Int, spec.VectorLen)
	for coordinate := range pads {
		globalCoordinate := uint64(spec.ChunkStart + coordinate)
		for attempt := uint64(0); ; attempt++ {
			encoded := make([]byte, byteLen)
			for offset, blockIndex := 0, uint64(0); offset < len(encoded); blockIndex++ {
				mac := hmac.New(sha256.New, seed[:])
				mac.Write([]byte("dsvert-exact-gc-crt-uniform-pad-v1"))
				mac.Write(release[:])
				var scalar [24]byte
				binary.BigEndian.PutUint64(scalar[:8], globalCoordinate)
				binary.BigEndian.PutUint64(scalar[8:16], attempt)
				binary.BigEndian.PutUint64(scalar[16:], blockIndex)
				mac.Write(scalar[:])
				block := mac.Sum(nil)
				offset += copy(encoded[offset:], block)
				clear(block)
			}
			if remainder := bitLen % 8; remainder != 0 {
				encoded[0] &= byte((1 << remainder) - 1)
			}
			candidate := new(big.Int).SetBytes(encoded)
			clear(encoded)
			if candidate.Cmp(product) < 0 {
				pads[coordinate] = candidate
				break
			}
		}
	}
	return pads, nil
}

func exactGCCRTMaskLocalResidues(shares [][]uint64, pads []*big.Int,
	spec exactGCCRTToRingSpec) [][]uint64 {
	masked := make([][]uint64, spec.VectorLen)
	for coordinate := 0; coordinate < spec.VectorLen; coordinate++ {
		masked[coordinate] = make([]uint64, len(spec.Moduli))
		for lane, modulus := range spec.Moduli {
			padResidue := new(big.Int).Mod(pads[coordinate],
				new(big.Int).SetUint64(modulus)).Uint64()
			masked[coordinate][lane] =
				(shares[coordinate][lane] + modulus - padResidue) % modulus
		}
	}
	return masked
}

func exactGCCRTEncodeMaskedBundle(masked [][]uint64,
	spec exactGCCRTToRingSpec) []byte {
	size := exactGCCRTMaskedHeaderBytes + 8*spec.VectorLen*len(spec.Moduli)
	result := make([]byte, size)
	copy(result[:8], exactGCCRTMaskedMagic[:])
	result[8] = 1
	binary.BigEndian.PutUint16(result[10:12], uint16(len(spec.Moduli)))
	binary.BigEndian.PutUint32(result[12:16], uint32(spec.VectorLen))
	digest := spec.digest()
	copy(result[16:48], digest[:])
	offset := exactGCCRTMaskedHeaderBytes
	for _, coordinate := range masked {
		for _, residue := range coordinate {
			binary.BigEndian.PutUint64(result[offset:offset+8], residue)
			offset += 8
		}
	}
	return result
}

func exactGCCRTDecodeMaskedBundle(encoded []byte,
	spec exactGCCRTToRingSpec) ([][]uint64, error) {
	want := exactGCCRTMaskedHeaderBytes + 8*spec.VectorLen*len(spec.Moduli)
	digest := spec.digest()
	if len(encoded) != want || len(encoded) < exactGCCRTMaskedHeaderBytes ||
		string(encoded[:8]) != string(exactGCCRTMaskedMagic[:]) ||
		encoded[8] != 1 || encoded[9] != 0 ||
		int(binary.BigEndian.Uint16(encoded[10:12])) != len(spec.Moduli) ||
		int(binary.BigEndian.Uint32(encoded[12:16])) != spec.VectorLen ||
		!hmac.Equal(encoded[16:48], digest[:]) {
		return nil, fmt.Errorf("exact-gc-crt: invalid authenticated masked-residue bundle")
	}
	result := make([][]uint64, spec.VectorLen)
	offset := exactGCCRTMaskedHeaderBytes
	for coordinate := range result {
		result[coordinate] = make([]uint64, len(spec.Moduli))
		for lane, modulus := range spec.Moduli {
			value := binary.BigEndian.Uint64(encoded[offset : offset+8])
			offset += 8
			if value >= modulus {
				return nil, fmt.Errorf("exact-gc-crt: masked residue (%d,%d) is not canonical",
					coordinate, lane)
			}
			result[coordinate][lane] = value
		}
	}
	return result, nil
}

func exactGCCRTCombineMaskedOpening(masked, evaluator [][]uint64,
	spec exactGCCRTToRingSpec) ([]*big.Int, error) {
	coefficients, err := spec.coefficients()
	if err != nil {
		return nil, err
	}
	product := spec.product()
	openings := make([]*big.Int, spec.VectorLen)
	for coordinate := range openings {
		value := new(big.Int)
		for lane, modulus := range spec.Moduli {
			residue := (masked[coordinate][lane] + evaluator[coordinate][lane]) % modulus
			value.Add(value, new(big.Int).Mul(
				new(big.Int).SetUint64(residue), coefficients[lane]))
		}
		openings[coordinate] = value.Mod(value, product)
	}
	return openings, nil
}

func exactGCCRTPackCircuitInput(privateValues, masks []*big.Int,
	validityMask bool, spec exactGCCRTToRingSpec, garbler bool) *big.Int {
	values := make([]*big.Int, 0, spec.VectorLen+len(masks)+1)
	values = append(values, privateValues...)
	if garbler {
		values = append(values, masks...)
		values = append(values, new(big.Int).SetUint64(boolToUint64(validityMask)))
	}
	return exactGCPackChunks(values, spec.typeBits())
}

func exactGCCRTUnpackOutputs(value *big.Int,
	spec exactGCCRTToRingSpec) []*big.Int {
	result := make([]*big.Int, spec.VectorLen+1)
	for i := range result {
		result[i] = new(big.Int).Rsh(new(big.Int).Set(value), uint(i*spec.typeBits()))
		bits := spec.RingBits
		if i == spec.VectorLen {
			bits = 1
		}
		result[i].And(result[i], exactGCMask(bits))
	}
	return result
}

func exactGCCRTMaskedBundleAck(encoded []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("dsvert-exact-gc-crt-masked-bundle-ack-v1"))
	h.Write(encoded)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func exactGCCRTSendMaskedBundle(conn *p2p.Conn, encoded []byte) error {
	if err := conn.SendData(encoded); err != nil {
		return fmt.Errorf("exact-gc-crt: send masked-residue bundle: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exact-gc-crt: flush masked-residue bundle: %w", err)
	}
	want := exactGCCRTMaskedBundleAck(encoded)
	got, err := conn.ReceiveData()
	if err != nil || !hmac.Equal(got, want[:]) {
		return fmt.Errorf("exact-gc-crt: invalid masked-residue acknowledgement")
	}
	return nil
}

func exactGCCRTReceiveMaskedBundle(conn *p2p.Conn,
	spec exactGCCRTToRingSpec) ([][]uint64, error) {
	encoded, err := conn.ReceiveData()
	if err != nil {
		return nil, fmt.Errorf("exact-gc-crt: receive masked-residue bundle: %w", err)
	}
	masked, err := exactGCCRTDecodeMaskedBundle(encoded, spec)
	if err != nil {
		return nil, err
	}
	ack := exactGCCRTMaskedBundleAck(encoded)
	if err := conn.SendData(ack[:]); err != nil {
		return nil, fmt.Errorf("exact-gc-crt: acknowledge masked-residue bundle: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("exact-gc-crt: flush masked-residue acknowledgement: %w", err)
	}
	return masked, nil
}

func exactGCCRTRunGarbler(rw io.ReadWriter, session exactGCSession,
	spec exactGCCRTToRingSpec, shares [][]uint64,
	outputMaskSeed [32]byte) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("exact-gc-crt: nil peer channel")
	}
	if err := exactGCCRTValidateSession(session, spec); err != nil {
		return nil, err
	}
	if err := exactGCCRTValidateLocalShares(shares, spec); err != nil {
		return nil, err
	}
	pads, err := exactGCCRTDeterministicPads(outputMaskSeed, spec)
	if err != nil {
		return nil, err
	}
	masks, validityMask, err := exactGCCRTDeterministicMasks(outputMaskSeed, spec)
	if err != nil {
		return nil, err
	}
	circ, err := exactGCCRTCompile(spec)
	if err != nil {
		return nil, err
	}
	masked := exactGCCRTMaskLocalResidues(shares, pads, spec)
	encodedMasked := exactGCCRTEncodeMaskedBundle(masked, spec)
	input := exactGCCRTPackCircuitInput(pads, masks, validityMask, spec, true)
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleGarbler)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	if err := exactGCCRTSendMaskedBundle(conn, encodedMasked); err != nil {
		return nil, exactGCFinishConn(conn, rw, err)
	}
	protocolErr := exactGCGarblerProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return append(masks,
		new(big.Int).SetUint64(boolToUint64(validityMask))), nil
}

func exactGCCRTRunEvaluator(rw io.ReadWriter, session exactGCSession,
	spec exactGCCRTToRingSpec, shares [][]uint64) ([]*big.Int, error) {
	if rw == nil {
		return nil, fmt.Errorf("exact-gc-crt: nil peer channel")
	}
	if err := exactGCCRTValidateSession(session, spec); err != nil {
		return nil, err
	}
	if err := exactGCCRTValidateLocalShares(shares, spec); err != nil {
		return nil, err
	}
	circ, err := exactGCCRTCompile(spec)
	if err != nil {
		return nil, err
	}
	secure, err := newExactGCSecureRecordRW(rw, session, exactGCRoleEvaluator)
	if err != nil {
		return nil, err
	}
	conn := p2p.NewConn(secure)
	masked, err := exactGCCRTReceiveMaskedBundle(conn, spec)
	if err != nil {
		return nil, exactGCFinishConn(conn, rw, err)
	}
	openings, err := exactGCCRTCombineMaskedOpening(masked, shares, spec)
	if err != nil {
		return nil, exactGCFinishConn(conn, rw, err)
	}
	input := exactGCCRTPackCircuitInput(openings, nil, false, spec, false)
	result, protocolErr := exactGCEvaluatorProtocol(conn, circ, input, session)
	if err := exactGCFinishConn(conn, rw, protocolErr); err != nil {
		return nil, err
	}
	return exactGCCRTUnpackOutputs(result, spec), nil
}

// exactGCCRTReference is an independent big.Int oracle used by exhaustive,
// property and integration tests.  A failed coordinate invalidates and
// neutralises the complete tuple, matching the private circuit contract.
func exactGCCRTReference(first, second [][]uint64,
	spec exactGCCRTToRingSpec) ([]*big.Int, bool, error) {
	if err := spec.validate(); err != nil {
		return nil, false, err
	}
	if err := exactGCCRTValidateLocalShares(first, spec); err != nil {
		return nil, false, err
	}
	if err := exactGCCRTValidateLocalShares(second, spec); err != nil {
		return nil, false, err
	}
	coefficients, err := spec.coefficients()
	if err != nil {
		return nil, false, err
	}
	product := spec.product()
	halfProduct := new(big.Int).Rsh(new(big.Int).Set(product), 1)
	values := make([]*big.Int, spec.VectorLen)
	allValid := true
	for coordinate := 0; coordinate < spec.VectorLen; coordinate++ {
		reconstructed := new(big.Int)
		for lane, modulus := range spec.Moduli {
			residue := (first[coordinate][lane] + second[coordinate][lane]) % modulus
			reconstructed.Add(reconstructed,
				new(big.Int).Mul(new(big.Int).SetUint64(residue), coefficients[lane]))
		}
		reconstructed.Mod(reconstructed, product)
		signed := new(big.Int).Set(reconstructed)
		if reconstructed.Cmp(halfProduct) > 0 {
			signed.Sub(signed, product)
		}
		if new(big.Int).Abs(new(big.Int).Set(signed)).Cmp(spec.MagnitudeBound) > 0 {
			allValid = false
		}
		values[coordinate] = signed.Mod(signed, exactGCModulus(spec.RingBits))
	}
	if !allValid {
		for i := range values {
			values[i] = big.NewInt(0)
		}
	}
	return values, allValid, nil
}
