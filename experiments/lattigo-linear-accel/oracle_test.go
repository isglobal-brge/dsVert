package linearaccel

import (
	"errors"
	"fmt"
	"math/big"
)

// decodeCombinedSigned exists only in test builds. It deliberately opens
// combined residues so the HE path can be compared with an independent
// big.Int oracle. The non-test experiment has no corresponding operation.
func (s *CRTSpec) decodeCombinedSigned(residues []uint64, magnitudeBound *big.Int) (*big.Int, error) {
	if len(residues) != len(s.moduli) {
		return nil, fmt.Errorf("got %d residues, want %d", len(residues), len(s.moduli))
	}
	if err := s.ValidateMagnitudeBound(magnitudeBound); err != nil {
		return nil, err
	}

	x := big.NewInt(0)
	for i, modulus := range s.moduli {
		if residues[i] >= modulus {
			return nil, fmt.Errorf("residue %d is not canonical modulo %d", residues[i], modulus)
		}
		mi := new(big.Int).Quo(new(big.Int).Set(s.product), new(big.Int).SetUint64(modulus))
		inverse := new(big.Int).ModInverse(new(big.Int).Mod(mi, new(big.Int).SetUint64(modulus)), new(big.Int).SetUint64(modulus))
		if inverse == nil {
			return nil, errors.New("CRT moduli are not pairwise coprime")
		}
		term := new(big.Int).Mul(new(big.Int).SetUint64(residues[i]), mi)
		term.Mul(term, inverse)
		x.Add(x, term)
	}
	x.Mod(x, s.product)
	half := new(big.Int).Rsh(new(big.Int).Set(s.product), 1)
	if x.Cmp(half) > 0 {
		x.Sub(x, s.product)
	}
	if new(big.Int).Abs(new(big.Int).Set(x)).Cmp(magnitudeBound) > 0 {
		return nil, fmt.Errorf("%w after CRT reconstruction: |%s| > %s", ErrBoundExceeded, x, magnitudeBound)
	}
	return x, nil
}
