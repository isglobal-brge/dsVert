package main

// Exact integer sampling with ideal independent bits. The deployed replayable
// HKDF/ChaCha20 reader is pseudorandom, so the deployed guarantee additionally
// assumes its computational indistinguishability from those ideal bits.
// The rejection algorithms and math/big operations are variable time; this is
// a local noise-peer sampler, not a constant-time garbled-circuit primitive.

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const jointDPExactStreamEpochBytes = 65536

// Each epoch uses a separately derived key/nonce, well before ChaCha20's block
// counter limit. The epoch is an arbitrary-precision nonnegative integer, so
// there is no fixed tape length or counter wrap. Decimal epochs are canonical.
type jointDPExactStream struct {
	seed, transcript, contract [32]byte
	epoch                      big.Int
	cipher                     *chacha20.Cipher
	used                       int
}

func (s *jointDPExactStream) Read(out []byte) (int, error) {
	count := 0
	for count < len(out) {
		if s.cipher == nil || s.used == jointDPExactStreamEpochBytes {
			if s.cipher != nil {
				s.epoch.Add(&s.epoch, big.NewInt(1))
			}
			info := append([]byte("dsVert/joint-dp/vector-convolution-private-stream/v4/"), s.contract[:]...)
			info = append(info, '/')
			info = append(info, s.epoch.String()...)
			reader := hkdf.New(sha256.New, s.seed[:], s.transcript[:], info)
			var material [chacha20.KeySize + chacha20.NonceSize]byte
			if _, err := io.ReadFull(reader, material[:]); err != nil {
				return count, err
			}
			cipher, err := chacha20.NewUnauthenticatedCipher(material[:chacha20.KeySize], material[chacha20.KeySize:])
			clear(material[:])
			if err != nil {
				return count, err
			}
			s.cipher, s.used = cipher, 0
		}
		n := min(len(out)-count, jointDPExactStreamEpochBytes-s.used)
		clear(out[count : count+n])
		s.cipher.XORKeyStream(out[count:count+n], out[count:count+n])
		count += n
		s.used += n
	}
	return count, nil
}

func (s *jointDPExactStream) clear() {
	clear(s.seed[:])
	clear(s.transcript[:])
	clear(s.contract[:])
	s.cipher = nil
	s.epoch.SetInt64(0)
}

// Bits are consumed most-significant-first in each byte; there is no alignment
// between uniform draws, rejection attempts, geometric draws, or coordinates.
type jointDPExactBits struct {
	reader io.Reader
	byte   [1]byte
	left   uint
}

func (b *jointDPExactBits) bit() (uint, error) {
	if b.left == 0 {
		if _, err := io.ReadFull(b.reader, b.byte[:]); err != nil {
			return 0, err
		}
		b.left = 8
	}
	b.left--
	return uint((b.byte[0] >> b.left) & 1), nil
}

func (b *jointDPExactBits) uniform(n *big.Int) (*big.Int, error) {
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("uniform bound must be positive")
	}
	width := new(big.Int).Sub(n, big.NewInt(1)).BitLen()
	for {
		value := new(big.Int)
		for i := width - 1; i >= 0; i-- {
			bit, err := b.bit()
			if err != nil {
				return nil, err
			}
			value.SetBit(value, i, bit)
		}
		if value.Cmp(n) < 0 {
			return value, nil
		}
	}
}

// CKS Algorithm 1 on [0,1]: the probability of reaching trial k is
// x^(k-1)/(k-1)!. Odd stopping parity therefore has probability exp(-x).
func (b *jointDPExactBits) bernoulliExpUnit(x *big.Rat) (bool, error) {
	if x.Sign() < 0 || x.Cmp(big.NewRat(1, 1)) > 0 {
		return false, fmt.Errorf("Bernoulli exponential argument outside [0,1]")
	}
	if x.Sign() == 0 {
		return true, nil
	}
	for k := big.NewInt(1); ; k.Add(k, big.NewInt(1)) {
		denominator := new(big.Int).Mul(x.Denom(), k)
		value, err := b.uniform(denominator)
		if err != nil {
			return false, err
		}
		if value.Cmp(x.Num()) >= 0 {
			return k.Bit(0) == 1, nil
		}
	}
}

// For alpha=n/d, sample U with mass proportional to exp(-u/d), 0<=u<d,
// and V geometric with ratio exp(-1). Then d*V+U is geometric with ratio
// exp(-1/d); integer division by n gives ratio exp(-alpha). This is the
// rational-rate form of CKS's efficient geometric construction.
func (b *jointDPExactBits) geometric(alpha *big.Rat) (*big.Int, error) {
	if alpha.Sign() <= 0 {
		return nil, fmt.Errorf("geometric rate must be positive")
	}
	var u *big.Int
	for {
		var err error
		u, err = b.uniform(alpha.Denom())
		if err != nil {
			return nil, err
		}
		accept, err := b.bernoulliExpUnit(new(big.Rat).SetFrac(u, alpha.Denom()))
		if err != nil {
			return nil, err
		}
		if accept {
			break
		}
	}
	v := new(big.Int)
	for {
		accept, err := b.bernoulliExpUnit(big.NewRat(1, 1))
		if err != nil {
			return nil, err
		}
		if !accept {
			break
		}
		v.Add(v, big.NewInt(1))
	}
	v.Mul(v, alpha.Denom())
	v.Add(v, u)
	return v.Quo(v, alpha.Num()), nil
}

// A difference of two independent geometric(q) variables has mass
// (1-q)/(1+q)*q^|z|. No tail, rational probability, or output is rounded.
func (b *jointDPExactBits) laplace(alpha *big.Rat) (*big.Int, error) {
	left, err := b.geometric(alpha)
	if err != nil {
		return nil, err
	}
	right, err := b.geometric(alpha)
	if err != nil {
		return nil, err
	}
	return left.Sub(left, right), nil
}

// Conservative decimal bound for min(1, multiplicity*exp(-exponent)).
// e^3>10 implies exp(-x)<=10^-floor(x/3); rounding the multiplier up to
// a power of ten is outward. Scientific decimal notation never underflows to
// a false zero, even for exponents too large for machine integers.
func jointDPExactExponentialBound(exponent *big.Rat, multiplicity int) string {
	if exponent.Sign() <= 0 || multiplicity < 1 {
		return "1"
	}
	power, factor := 0, big.NewInt(1)
	for factor.Cmp(big.NewInt(int64(multiplicity))) < 0 {
		factor.Mul(factor, big.NewInt(10))
		power++
	}
	n := new(big.Int).Quo(exponent.Num(), new(big.Int).Mul(exponent.Denom(), big.NewInt(3)))
	n.Sub(n, big.NewInt(int64(power)))
	if n.Sign() <= 0 {
		return "1"
	}
	return "1e-" + n.String()
}
