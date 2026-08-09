package linearaccel

import (
	"errors"
	"math/big"
	"testing"
)

func TestCRTSpecsCoverSignedTargetsWithoutWrap(t *testing.T) {
	for _, width := range []SignedWidth{Signed63, Signed127, Signed257} {
		t.Run(big.NewInt(int64(width)).String(), func(t *testing.T) {
			spec, err := NewCRTSpec(width, experimentLogN)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Product().Cmp(new(big.Int).Lsh(spec.Capacity(), 1)) <= 0 {
				t.Fatalf("P=%s does not satisfy P>2M for M=%s", spec.Product(), spec.Capacity())
			}
			seen := make(map[uint64]bool)
			for _, modulus := range spec.Moduli() {
				if seen[modulus] {
					t.Fatalf("duplicate CRT modulus %d", modulus)
				}
				seen[modulus] = true
				if modulus%uint64(1<<(experimentLogN+1)) != 1 {
					t.Fatalf("modulus %d is not NTT-friendly for logN=%d", modulus, experimentLogN)
				}
			}

			for _, value := range []*big.Int{
				big.NewInt(0), big.NewInt(1), big.NewInt(-1),
				new(big.Int).Set(spec.Capacity()),
				new(big.Int).Neg(spec.Capacity()),
			} {
				residues, err := spec.EncodeSigned(value, spec.Capacity())
				if err != nil {
					t.Fatalf("encode %s: %v", value, err)
				}
				decoded, err := spec.decodeCombinedSigned(residues, spec.Capacity())
				if err != nil {
					t.Fatalf("decode %s: %v", value, err)
				}
				if decoded.Cmp(value) != 0 {
					t.Fatalf("round trip: got %s, want %s", decoded, value)
				}
			}
		})
	}
}

func TestCRTRejectsBoundsAndNonCanonicalResidues(t *testing.T) {
	spec, err := NewCRTSpec(Signed63, experimentLogN)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := new(big.Int).Add(spec.Capacity(), big.NewInt(1))
	if err := spec.ValidateMagnitudeBound(tooLarge); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("got %v, want ErrBoundExceeded", err)
	}
	if _, err := spec.EncodeSigned(tooLarge, spec.Capacity()); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("got %v, want ErrBoundExceeded", err)
	}

	tiny := &CRTSpec{
		width:    Signed63,
		moduli:   []uint64{3, 5},
		product:  big.NewInt(15),
		capacity: big.NewInt(20),
	}
	if err := tiny.ValidateMagnitudeBound(big.NewInt(8)); !errors.Is(err, ErrCRTTooSmall) {
		t.Fatalf("got %v, want ErrCRTTooSmall", err)
	}

	residues, err := spec.EncodeSigned(big.NewInt(2), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	residues[0] = spec.moduli[0]
	if _, err := spec.decodeCombinedSigned(residues, big.NewInt(2)); err == nil {
		t.Fatal("accepted a non-canonical residue")
	}
}

func TestGCBoundaryDigestBindsAllNumericFields(t *testing.T) {
	spec, err := NewCRTSpec(Signed127, experimentLogN)
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := spec.NewGCBoundary(new(big.Int).Lsh(big.NewInt(1), 80))
	if err != nil {
		t.Fatal(err)
	}
	if got := digestBoundary(boundary); got != boundary.Digest {
		t.Fatal("boundary digest is not canonical")
	}

	mutations := []func(*GCBoundary){
		func(b *GCBoundary) { b.SignedWidth++ },
		func(b *GCBoundary) { b.Moduli[0]++ },
		func(b *GCBoundary) { b.Product[0] ^= 1 },
		func(b *GCBoundary) { b.MagnitudeBound[0] ^= 1 },
		func(b *GCBoundary) { b.ReconstructionRule += ";tampered" },
	}
	for i, mutate := range mutations {
		candidate := cloneBoundary(boundary)
		mutate(&candidate)
		if digestBoundary(candidate) == boundary.Digest {
			t.Fatalf("mutation %d did not change boundary digest", i)
		}
	}
}
