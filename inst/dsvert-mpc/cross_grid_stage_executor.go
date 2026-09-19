package main

import (
	"crypto/rand"
	"io"
)

type crossGridStageExecutor struct {
	Store *crossGridStageStore
	Base  exactGCSession
	// Internal fault injection for process-death tests; production leaves nil.
	fault func(string, crossGridStageRecord) error
}

func (e *crossGridStageExecutor) checkpoint(event string, r crossGridStageRecord) error {
	if e.fault != nil {
		return e.fault(event, r)
	}
	return nil
}

func crossGridStageStatus(r crossGridStageRecord, phase string) crossGridStageMessage {
	return crossGridStageMessage{StageID: r.StageID, Phase: phase, State: r.State, Role: r.Role,
		Generation: r.Generation, Nonce: r.AttemptNonce, Receipt: r.StageReceipt, Commitments: r.Commitments}
}

func crossGridStageSamePrepared(r crossGridStageRecord, p crossGridStageMessage) bool {
	return (r.State == "PREPARE" || r.State == "COMMIT") && (p.State == "PREPARE" || p.State == "COMMIT") &&
		r.Generation == p.Generation && r.AttemptNonce == p.Nonce && r.StageReceipt == p.Receipt && r.Commitments == p.Commitments
}

// Execute returns only local private outputs. The caller owns the connection
// and must close it on error/process death. No retries occur on a used channel.
// SemanticKey never includes attempt nonces, receipts or transport session IDs:
// final artifact = f(true sufficient statistics, sticky semantic seed).
// This engine does not draw noise. Only the existing once-only DP handoff may
// consume the final committed vector using the pinned SemanticKey.
func (e *crossGridStageExecutor) Execute(rw io.ReadWriter, kernels []crossGridStageCompute) ([]crossGridStageOutput, error) {
	if e.Store == nil || e.Store.lock == nil || len(kernels) != len(e.Store.graph.Stages) ||
		e.Base.validate() != nil || e.Base.GarblerID != e.Store.graph.Authorities[0] ||
		e.Base.EvaluatorID != e.Store.graph.Authorities[1] {
		return nil, errCrossGridStage
	}
	for _, k := range kernels {
		if k == nil {
			return nil, errCrossGridStage
		}
	}
	meta, err := crossGridStageRecoveryChannel(rw, e.Base, e.Store.role, e.Store.plan)
	if err != nil {
		return nil, err
	}
	outputs := make([]crossGridStageOutput, len(kernels))
	receipts, indices := make(map[string][32]byte), make(map[string]int)
	for i, abi := range e.Store.graph.Stages {
		var previous [][32]byte
		var inputs []crossGridStageOutput
		for _, id := range abi.Predecessors {
			previous = append(previous, receipts[id])
			inputs = append(inputs, crossGridStageClone(outputs[indices[id]]))
		}
		r, err := e.Store.load(abi, previous)
		if err != nil {
			return nil, err
		}
		peer, err := crossGridStageExchange(meta, e.Store.role, crossGridStageStatus(r, "recover"))
		if err != nil {
			return nil, err
		}
		switch peer.State {
		case "EMPTY", "ABORTED", "RUNNING", "PREPARE", "COMMIT":
		default:
			return nil, errCrossGridStage
		}
		if r.State == "COMMIT" || peer.State == "COMMIT" {
			// One COMMIT proves the peer had durably PREPAREd this exact receipt.
			// Missing/corrupt PREPARE is a hard failure, never a fresh peer share.
			if !crossGridStageSamePrepared(r, peer) {
				return nil, errCrossGridStage
			}
			if r.State == "PREPARE" {
				r.State = "COMMIT"
				if err := e.Store.save(r); err != nil {
					return nil, err
				}
			}
		} else {
			// No COMMIT: erase BOTH attempt outputs before generating fresh nonce
			// contributions. ABORT acknowledgement prevents old/new share mixing.
			generation := max(r.Generation, peer.Generation)
			if generation == ^uint64(0) {
				return nil, errCrossGridStage
			}
			r = e.Store.empty(abi, previous)
			r.Generation, r.State = generation+1, "ABORTED"
			if err := e.Store.save(r); err != nil {
				return nil, err
			}
			if err := e.checkpoint("after-abort", r); err != nil {
				return nil, err
			}
			peer, err = crossGridStageExchange(meta, e.Store.role, crossGridStageStatus(r, "aborted"))
			if err != nil {
				return nil, err
			}
			if peer.State != "ABORTED" || peer.Generation != r.Generation {
				return nil, errCrossGridStage
			}
			var nonces [2][32]byte
			if _, err := io.ReadFull(rand.Reader, nonces[e.Store.role][:]); err != nil {
				return nil, err
			}
			peer, err = crossGridStageExchange(meta, e.Store.role, crossGridStageMessage{StageID: abi.ID, Phase: "fresh-attempt", Nonce: nonces[e.Store.role]})
			if err != nil {
				return nil, err
			}
			if peer.Nonce == ([32]byte{}) {
				return nil, errCrossGridStage
			}
			nonces[1-e.Store.role] = peer.Nonce
			r.AttemptNonce = crossGridStageHash("joint-attempt-nonces", nonces)
			r.OutputMaskDomainTag = crossGridStageMaskDomain(r.Session, r.StageID, r.AttemptNonce)
			r.State = "RUNNING"
			if err := e.Store.save(r); err != nil {
				return nil, err
			}
			if err := e.checkpoint("after-begin", r); err != nil {
				return nil, err
			}
			attempt := crossGridStageAttempt{r.AttemptNonce, r.OutputMaskDomainTag,
				crossGridStageAttemptSession(e.Base, e.Store.plan, abi.ID, r.AttemptNonce)}
			r.Output, err = kernels[i](rw, attempt, inputs)
			if err != nil {
				return nil, err
			}
			if abi.validateOutput(r.Output) != nil {
				return nil, errCrossGridStage
			}
			r.Output = crossGridStageRemask(r.Output, abi, e.Store.role, attempt)
			if err := e.checkpoint("after-compute", r); err != nil {
				return nil, err
			}
			r.Commitments[e.Store.role] = crossGridStageCommitment(r)
			peer, err = crossGridStageExchange(meta, e.Store.role, crossGridStageStatus(r, "output-commitment"))
			if err != nil {
				return nil, err
			}
			if peer.Generation != r.Generation || peer.Nonce != r.AttemptNonce || peer.State != "RUNNING" ||
				peer.Commitments[1-e.Store.role] == ([32]byte{}) {
				return nil, errCrossGridStage
			}
			r.Commitments[1-e.Store.role] = peer.Commitments[1-e.Store.role]
			r.StageReceipt = crossGridStageReceipt(r)
			r.ShareMAC = crossGridStageShareMAC(e.Store.key, r)
			r.State = "PREPARE"
			if err := e.Store.save(r); err != nil {
				return nil, err
			}
			if err := e.checkpoint("after-prepare", r); err != nil {
				return nil, err
			}
			peer, err = crossGridStageExchange(meta, e.Store.role, crossGridStageStatus(r, "prepared"))
			if err != nil {
				return nil, err
			}
			if !crossGridStageSamePrepared(r, peer) {
				return nil, errCrossGridStage
			}
			if err := e.checkpoint("after-prepare-exchange", r); err != nil {
				return nil, err
			}
			r.State = "COMMIT"
			if err := e.Store.save(r); err != nil {
				return nil, err
			}
		}
		if err := e.checkpoint("after-commit", r); err != nil {
			return nil, err
		}
		peer, err = crossGridStageExchange(meta, e.Store.role, crossGridStageStatus(r, "committed"))
		if err != nil {
			return nil, err
		}
		if peer.State != "COMMIT" || !crossGridStageSamePrepared(r, peer) {
			return nil, errCrossGridStage
		}
		if err := e.checkpoint("after-ack", r); err != nil {
			return nil, err
		}
		outputs[i], receipts[abi.ID], indices[abi.ID] = crossGridStageClone(r.Output), r.StageReceipt, i
	}
	return outputs, nil
}
