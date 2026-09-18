package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/p2p"
)

const crossGridKernelOperation exactGCOperation = "glm-grid-profile-v2"

func (p crossGridKernelPlan) purpose() string {
	b, _ := json.Marshal(p)
	hash := sha256.Sum256(append([]byte("dsvert-cross-grid-fused-v2\x00"), b...))
	return "dsvert-cross-grid-fused-v2/" + hex.EncodeToString(hash[:])
}

// Prepared before protected sources are read. The unexported plan and topology
// cannot be selected by an ordinary exact-GC RPC. Admission is a separate gate.
type crossGridKernelPrepared struct {
	plan    crossGridKernelPlan
	circuit *circuit.Circuit
}

func crossGridKernelPrepare(p crossGridKernelPlan) (*crossGridKernelPrepared, error) {
	c, err := crossGridKernelCompile(p)
	if err != nil {
		return nil, errCrossGridKernel
	}
	if c.Inputs.Size() > exactGCMaxCircuitTypeBits {
		return nil, errCrossGridKernel
	}
	// Own the public plan: later caller mutation cannot change packing or context.
	b, _ := json.Marshal(p)
	var owned crossGridKernelPlan
	if json.Unmarshal(b, &owned) != nil {
		return nil, errCrossGridKernel
	}
	return &crossGridKernelPrepared{owned, c}, nil
}

func (k *crossGridKernelPrepared) run(rw io.ReadWriter, session exactGCSession, source []*big.Int, role exactGCRole) ([]*big.Int, error) {
	if k == nil || k.circuit == nil || rw == nil || session.validate() != nil ||
		session.Spec.Operation != crossGridKernelOperation || session.Spec.VectorLen != len(k.plan.Beta) || session.Purpose != k.plan.purpose() || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
		return nil, errCrossGridKernel
	}
	input, err := crossGridKernelPrivateInput(k.plan, source, role == exactGCRoleGarbler)
	if err != nil {
		return nil, errCrossGridKernel
	}
	defer exactGCZeroBigInts(input)
	var masks []*big.Int
	if role == exactGCRoleGarbler {
		masks = make([]*big.Int, len(k.plan.Beta)+1)
		defer exactGCZeroBigInts(masks)
		for i := range masks {
			masks[i], err = rand.Int(rand.Reader, exactGCModulus(128))
			if err != nil {
				return nil, errCrossGridKernel
			}
		}
		masks[len(k.plan.Beta)].And(masks[len(k.plan.Beta)], big.NewInt(1))
		input = append(input, masks...)
	}
	packed := exactGCPackChunks(input, 128)
	defer packed.SetInt64(0)
	secure, err := newExactGCSecureRecordRW(rw, session, role)
	if err != nil {
		return nil, errCrossGridKernel
	}
	conn := p2p.NewConn(secure)
	var result *big.Int
	if role == exactGCRoleGarbler {
		err = exactGCGarblerProtocolMode(conn, k.circuit, packed, session, true)
	} else {
		result, err = exactGCEvaluatorProtocolMode(conn, k.circuit, packed, session, true)
	}
	if err != nil {
		return nil, errCrossGridKernel
	}
	out := make([]*big.Int, len(k.plan.Beta)+1)
	for i := range out {
		if role == exactGCRoleGarbler {
			out[i] = new(big.Int).Set(masks[i])
		} else {
			out[i] = new(big.Int).Rsh(new(big.Int).Set(result), uint(128*i))
			out[i].And(out[i], exactGCMask(128))
		}
	}
	if result != nil {
		result.SetInt64(0)
	}
	return out, nil
}
