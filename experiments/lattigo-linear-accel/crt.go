package linearaccel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// SignedWidth names the signed integer ranges investigated by this experiment.
// A width k has the symmetric certified range |x| <= 2^(k-1)-1.
type SignedWidth int

const (
	Signed63  SignedWidth = 63
	Signed127 SignedWidth = 127
	Signed257 SignedWidth = 257
)

var (
	ErrBoundExceeded = errors.New("value exceeds the certified public bound")
	ErrCRTTooSmall   = errors.New("CRT product does not satisfy P > 2M")
)

// CRTSpec is an immutable description of independent BGV plaintext lanes.
// Each modulus is an NTT-friendly prime; their product is the logical signed
// plaintext domain. Lattigo itself evaluates every lane independently.
type CRTSpec struct {
	width      SignedWidth
	logN       int
	moduli     []uint64
	product    *big.Int
	capacity   *big.Int
	productBit int
}

// NewCRTSpec selects deterministic 29-bit NTT-friendly plaintext primes. The
// product is deliberately larger than twice the full symmetric range.
func NewCRTSpec(width SignedWidth, logN int) (*CRTSpec, error) {
	if width != Signed63 && width != Signed127 && width != Signed257 {
		return nil, fmt.Errorf("unsupported signed width %d", width)
	}
	if logN < 4 || logN > 16 {
		return nil, fmt.Errorf("logN must be in [4,16], got %d", logN)
	}

	capacity := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), uint(width-1)),
		big.NewInt(1),
	)
	doubleCapacity := new(big.Int).Lsh(new(big.Int).Set(capacity), 1)
	product := big.NewInt(1)
	moduli := make([]uint64, 0, int(width)/29+2)
	generator := ring.NewNTTFriendlyPrimesGenerator(29, uint64(1<<(logN+1)))
	for product.Cmp(doubleCapacity) <= 0 {
		prime, err := generator.NextAlternatingPrime()
		if err != nil {
			return nil, fmt.Errorf("select CRT plaintext prime: %w", err)
		}
		moduli = append(moduli, prime)
		product.Mul(product, new(big.Int).SetUint64(prime))
	}

	return &CRTSpec{
		width:      width,
		logN:       logN,
		moduli:     moduli,
		product:    new(big.Int).Set(product),
		capacity:   capacity,
		productBit: product.BitLen(),
	}, nil
}

func (s *CRTSpec) Width() SignedWidth { return s.width }
func (s *CRTSpec) LogN() int          { return s.logN }
func (s *CRTSpec) ProductBits() int   { return s.productBit }

func (s *CRTSpec) Moduli() []uint64 {
	return append([]uint64(nil), s.moduli...)
}

func (s *CRTSpec) Product() *big.Int {
	return new(big.Int).Set(s.product)
}

func (s *CRTSpec) Capacity() *big.Int {
	return new(big.Int).Set(s.capacity)
}

// ValidateMagnitudeBound enforces the non-wrap certificate P > 2M.
func (s *CRTSpec) ValidateMagnitudeBound(m *big.Int) error {
	if m == nil || m.Sign() < 0 {
		return fmt.Errorf("magnitude bound must be a non-negative integer")
	}
	if m.Cmp(s.capacity) > 0 {
		return fmt.Errorf("%w: M=%s exceeds signed-%d capacity %s", ErrBoundExceeded, m, s.width, s.capacity)
	}
	if s.product.Cmp(new(big.Int).Lsh(new(big.Int).Set(m), 1)) <= 0 {
		return fmt.Errorf("%w: P=%s, M=%s", ErrCRTTooSmall, s.product, m)
	}
	return nil
}

// EncodeSigned maps a locally validated signed value into the independent CRT
// plaintext lanes. It is an input encoding operation, not a share conversion.
func (s *CRTSpec) EncodeSigned(x, magnitudeBound *big.Int) ([]uint64, error) {
	if x == nil {
		return nil, errors.New("cannot encode a nil integer")
	}
	if err := s.ValidateMagnitudeBound(magnitudeBound); err != nil {
		return nil, err
	}
	if new(big.Int).Abs(new(big.Int).Set(x)).Cmp(magnitudeBound) > 0 {
		return nil, fmt.Errorf("%w: |%s| > %s", ErrBoundExceeded, x, magnitudeBound)
	}
	residues := make([]uint64, len(s.moduli))
	for i, modulus := range s.moduli {
		residues[i] = new(big.Int).Mod(new(big.Int).Set(x), new(big.Int).SetUint64(modulus)).Uint64()
	}
	return residues, nil
}

// GCBoundary is the complete public contract required by a future exact GC.
// The GC must add party shares modulo each Moduli[i], reconstruct in [0,P),
// map values greater than P/2 to x-P, and enforce |x| <= MagnitudeBound.
// This experiment intentionally does not implement that secret conversion.
type GCBoundary struct {
	Version            string
	SignedWidth        SignedWidth
	Moduli             []uint64
	Product            []byte
	MagnitudeBound     []byte
	ReconstructionRule string
	Digest             [32]byte
}

func (s *CRTSpec) NewGCBoundary(magnitudeBound *big.Int) (GCBoundary, error) {
	if err := s.ValidateMagnitudeBound(magnitudeBound); err != nil {
		return GCBoundary{}, err
	}
	b := GCBoundary{
		Version:            "dsvert-crt-signed-gc-boundary-v1",
		SignedWidth:        s.width,
		Moduli:             s.Moduli(),
		Product:            s.product.Bytes(),
		MagnitudeBound:     magnitudeBound.Bytes(),
		ReconstructionRule: "sum-shares-mod-qi;crt-[0,P);if-x>P/2-subtract-P;assert-abs<=M",
	}
	b.Digest = digestBoundary(b)
	return b, nil
}

func digestBoundary(b GCBoundary) [32]byte {
	h := sha256.New()
	writeBytes(h, []byte("dsvert-lattigo-linear-gc-boundary-v1"))
	writeBytes(h, []byte(b.Version))
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(b.SignedWidth))
	h.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], uint64(len(b.Moduli)))
	h.Write(scalar[:])
	for _, modulus := range b.Moduli {
		binary.BigEndian.PutUint64(scalar[:], modulus)
		h.Write(scalar[:])
	}
	writeBytes(h, b.Product)
	writeBytes(h, b.MagnitudeBound)
	writeBytes(h, []byte(b.ReconstructionRule))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeBytes(w byteWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}
