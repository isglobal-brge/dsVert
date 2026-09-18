package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	return crossGridKernelPreparedCircuit(p, c)
}

func crossGridKernelPreparedCircuit(p crossGridKernelPlan, c *circuit.Circuit) (*crossGridKernelPrepared, error) {
	if p.validate() != nil || c == nil || c.Inputs.Size() > exactGCMaxCircuitTypeBits {
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
	return k.runWithSeed(rw, session, source, role, nil)
}

func (p crossGridKernelPlan) matchesPurpose(value string) bool {
	purpose := p.purpose()
	producer := "dp." + p.Family + "-grid-cross.v1"
	return value == purpose || value == fmt.Sprintf("source=%d:%s|purpose=%d:%s", len(producer), producer, len(purpose), purpose)
}

func (k *crossGridKernelPrepared) runWithSeed(rw io.ReadWriter, session exactGCSession, source []*big.Int, role exactGCRole, seed *[32]byte) ([]*big.Int, error) {
	if k == nil || k.circuit == nil || rw == nil || session.validate() != nil ||
		session.Spec.Operation != crossGridKernelOperation || session.Spec.VectorLen != len(k.plan.Beta) || !k.plan.matchesPurpose(session.Purpose) || (role != exactGCRoleGarbler && role != exactGCRoleEvaluator) {
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
			if seed == nil {
				masks[i], err = rand.Int(rand.Reader, exactGCModulus(128))
			} else {
				mac := hmac.New(sha256.New, seed[:])
				fmt.Fprintf(mac, "dsvert-cross-grid-output-mask-v2|%s|%d", k.plan.purpose(), i)
				block := mac.Sum(nil)
				masks[i] = new(big.Int).SetBytes(block[:16])
				clear(block)
			}
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
	if err = exactGCFinishConn(conn, rw, err); err != nil {
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

// Public shape/purpose admission only. Source values never enter this command.
func handleCrossGridBatchPlan() {
	var p crossGridKernelPlan
	mpcReadInput(&p)
	if p.validate() != nil {
		outputError("cross-grid plan rejected")
		return
	}
	source, err := crossGridKernelSource(p)
	if err != nil || len(source) > 2*1024*1024 {
		outputError("cross-grid plan rejected")
		return
	}
	inputBits := 128 * (2*(p.sourceCount()+p.Rows*len(p.Beta)) + len(p.Beta) + 1)
	if inputBits > exactGCMaxCircuitTypeBits {
		outputError("cross-grid plan rejected")
		return
	}
	mpcWriteOutput(map[string]interface{}{"purpose": p.purpose(), "source_records": p.sourceCount(), "input_bits": inputBits, "source_bytes": len(source)})
}
