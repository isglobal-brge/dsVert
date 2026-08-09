// Package twopc prototypes a fixed two-compute-peer, additive-share to
// additive-share linear protocol. It is an isolated research spike.
package twopc

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"time"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
)

const (
	LayerXBeta = "x_beta"
	LayerXtR   = "xt_r"
)

var (
	ErrReplay         = errors.New("replayed 2PC message")
	ErrAuthentication = errors.New("2PC message authentication failed")
	ErrTranscript     = errors.New("2PC message does not match the transcript")
	ErrMaskReuse      = errors.New("2PC mask reuse detected")
)

// InputShares contains one compute peer's additive shares. The first index is
// the CRT modulus lane. No method returns this structure after NewPeer.
type InputShares struct {
	X        [][][]uint64
	Beta     [][]uint64
	Residual [][]uint64
}

// Identity is the peer material that a session must pin before any messages
// are accepted. The experiment generates it in memory; production persistence
// and pin rotation are intentionally out of scope.
type Identity struct {
	ID        string
	VerifyKey ed25519.PublicKey
}

// PublicWorkload is server-authoritative metadata. CustodianCount describes K
// upstream custodians whose shares have already been aggregated into exactly
// two compute peers; it does not change the fixed 2PC protocol.
type PublicWorkload struct {
	Rows           int
	Columns        int
	CustodianCount int
	Bounds         linearaccel.PublicBounds
	Boundary       linearaccel.GCBoundary
	Digest         [32]byte
}

type Metrics struct {
	Wall                       time.Duration
	EncryptedInputPayloadBytes uint64
	EncryptedInputWireBytes    uint64
	MaskedOutputPayloadBytes   uint64
	MaskedOutputWireBytes      uint64
	MessageCount               int
	HeapAllocDeltaBytes        int64
	TotalAllocDeltaBytes       uint64
	ProcessSysDeltaBytes       int64
}

func (m Metrics) TotalWireBytes() uint64 {
	return m.EncryptedInputWireBytes + m.MaskedOutputWireBytes
}

type Result struct {
	Session  [32]byte
	Workload PublicWorkload
	Metrics  Metrics
}

// PartyOutput is one peer's still-secret additive output. Combining the two
// PartyOutput values is deliberately absent from non-test code.
type PartyOutput struct {
	PartyID         string
	Session         [32]byte
	Layer           string
	Boundary        linearaccel.GCBoundary
	SharesByModulus [][]uint64
}

func cloneInputShares(input InputShares) InputShares {
	cloned := InputShares{
		X:        make([][][]uint64, len(input.X)),
		Beta:     make([][]uint64, len(input.Beta)),
		Residual: make([][]uint64, len(input.Residual)),
	}
	for lane := range input.X {
		cloned.X[lane] = make([][]uint64, len(input.X[lane]))
		for row := range input.X[lane] {
			cloned.X[lane][row] = append([]uint64(nil), input.X[lane][row]...)
		}
	}
	for lane := range input.Beta {
		cloned.Beta[lane] = append([]uint64(nil), input.Beta[lane]...)
		cloned.Residual[lane] = append([]uint64(nil), input.Residual[lane]...)
	}
	return cloned
}

func validateInputShares(spec *linearaccel.CRTSpec, input InputShares) (rows, columns int, err error) {
	moduli := spec.Moduli()
	if len(input.X) != len(moduli) || len(input.Beta) != len(moduli) || len(input.Residual) != len(moduli) {
		return 0, 0, fmt.Errorf("input must contain exactly %d CRT lanes", len(moduli))
	}
	if len(input.X[0]) == 0 || len(input.X[0][0]) == 0 {
		return 0, 0, errors.New("input X must be non-empty")
	}
	rows, columns = len(input.X[0]), len(input.X[0][0])
	for lane, modulus := range moduli {
		if len(input.X[lane]) != rows || len(input.Beta[lane]) != columns || len(input.Residual[lane]) != rows {
			return 0, 0, fmt.Errorf("CRT lane %d has inconsistent dimensions", lane)
		}
		for row := range input.X[lane] {
			if len(input.X[lane][row]) != columns {
				return 0, 0, fmt.Errorf("CRT lane %d X is not rectangular", lane)
			}
			for column, residue := range input.X[lane][row] {
				if residue >= modulus {
					return 0, 0, fmt.Errorf("X share lane=%d row=%d column=%d is not canonical modulo %d", lane, row, column, modulus)
				}
			}
		}
		for index, residue := range input.Beta[lane] {
			if residue >= modulus {
				return 0, 0, fmt.Errorf("beta share lane=%d index=%d is not canonical modulo %d", lane, index, modulus)
			}
		}
		for index, residue := range input.Residual[lane] {
			if residue >= modulus {
				return 0, 0, fmt.Errorf("residual share lane=%d index=%d is not canonical modulo %d", lane, index, modulus)
			}
		}
	}
	return rows, columns, nil
}

func deriveMagnitudeBound(rows, columns int, bounds linearaccel.PublicBounds) (*big.Int, error) {
	for name, bound := range map[string]*big.Int{"X": bounds.X, "beta": bounds.Beta, "residual": bounds.Residual} {
		if bound == nil || bound.Sign() < 0 {
			return nil, fmt.Errorf("%s bound must be a non-negative integer", name)
		}
	}
	xBeta := new(big.Int).Mul(new(big.Int).Set(bounds.X), bounds.Beta)
	xBeta.Mul(xBeta, big.NewInt(int64(columns)))
	xTr := new(big.Int).Mul(new(big.Int).Set(bounds.X), bounds.Residual)
	xTr.Mul(xTr, big.NewInt(int64(rows)))
	if xTr.Cmp(xBeta) > 0 {
		return xTr, nil
	}
	return xBeta, nil
}

func cloneBoundary(boundary linearaccel.GCBoundary) linearaccel.GCBoundary {
	boundary.Moduli = append([]uint64(nil), boundary.Moduli...)
	boundary.Product = append([]byte(nil), boundary.Product...)
	boundary.MagnitudeBound = append([]byte(nil), boundary.MagnitudeBound...)
	return boundary
}

func cloneWorkload(workload PublicWorkload) PublicWorkload {
	workload.Bounds = linearaccel.PublicBounds{
		X:        new(big.Int).Set(workload.Bounds.X),
		Beta:     new(big.Int).Set(workload.Bounds.Beta),
		Residual: new(big.Int).Set(workload.Bounds.Residual),
	}
	workload.Boundary = cloneBoundary(workload.Boundary)
	return workload
}

func addMod(left, right, modulus uint64) uint64 {
	sum := left + right
	if sum >= modulus {
		sum -= modulus
	}
	return sum
}

func subMod(left, right, modulus uint64) uint64 {
	if left >= right {
		return left - right
	}
	return modulus - (right - left)
}

func mulMod(left, right, modulus uint64) uint64 {
	// CRTSpec currently fixes plaintext primes to 29 bits, so the product fits
	// in uint64 before reduction.
	return (left * right) % modulus
}

func signedDelta(after, before uint64) int64 {
	if after >= before {
		return int64(after - before)
	}
	return -int64(before - after)
}
