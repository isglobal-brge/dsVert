package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMRegisteredPhase20HandoffAdapterTestOwnersV1(
	t *testing.T,
) ([2]*formalGLMRegisteredPhase20TerminalOwnerV1, [2]string,
	[2]formalGLMRegisteredPhase20PreparedEvidenceV1) {
	t.Helper()
	fixture := formalGLMRegisteredPhase20DPShareReceiptTestBuildV1(t)
	base := fixture.evidence
	peers := base.source.plan.DesignatedComputePeers
	roots := [2]string{
		filepath.Join(t.TempDir(), "garbler-rock"),
		filepath.Join(t.TempDir(), "evaluator-rock"),
	}
	var attempts [2]*formalGLMRegisteredPhase19AttemptStoreV1
	for index, peer := range peers {
		var err error
		attempts[index], err = newFormalGLMRegisteredPhase19AttemptStoreV1(
			roots[index], base.record, base.source.contract,
			base.source.inputs.identities.public, peer,
			base.source.inputs.identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
	}
	proposal, _, err := attempts[0].Begin(nil)
	if err != nil {
		t.Fatal(err)
	}
	accept, _, err := attempts[1].Accept(proposal)
	if err != nil {
		t.Fatal(err)
	}
	for index, peer := range peers {
		if err := formalGLMRegisteredPhase19ScheduleTailPersistClaimV1(
			attempts[index], base.record, base.source.contract,
			base.source.inputs.identities.public, peer, proposal, accept); err != nil {
			t.Fatal(err)
		}
	}
	var owners [2]*formalGLMRegisteredPhase20TerminalOwnerV1
	for index, peer := range peers {
		keys, keyErr := newFormalGLMRegisteredPhase20JobKeyProviderV1(
			roots[index], base.source.contract, base.source.inputs.identities.public,
			base.record, peer)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		owners[index], err = newFormalGLMRegisteredPhase20TerminalOwnerV1(
			attempts[index], keys, base.runtime, proposal, accept)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = owners[index].Close() })
	}
	evidence := [2]formalGLMRegisteredPhase20PreparedEvidenceV1{
		fixture.garbler, fixture.evaluator,
	}
	return owners, roots, evidence
}

func formalGLMRegisteredPhase20HandoffAdapterTestSelectV1(
	t *testing.T,
	owners [2]*formalGLMRegisteredPhase20TerminalOwnerV1,
	evidence [2]formalGLMRegisteredPhase20PreparedEvidenceV1,
) ([2]formalGLMRegisteredPhase20SelectedV1, error) {
	t.Helper()
	var zero [2]formalGLMRegisteredPhase20SelectedV1
	for index := range owners {
		if replayed, err := owners[index].SealLocalEvidenceV1(evidence[index]); err != nil {
			return zero, err
		} else if replayed {
			return zero, fmt.Errorf("terminal %d replayed its first seal", index)
		}
	}
	garblerReceipt, err := owners[0].PublishDPShareReceiptV1()
	if err != nil {
		return zero, err
	}
	bundle, replayed, err := owners[1].PrepareFromGarblerReceiptV1(garblerReceipt)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("evaluator replayed its first prepare")
	}
	garblerPrepare, replayed, err := owners[0].PrepareFromEvaluatorBundleV1(bundle)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("garbler replayed its first prepare")
	}
	garblerVote, replayed, err := owners[0].VoteSelectV1(bundle.EvaluatorPrepare)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("garbler replayed its first select vote")
	}
	evaluatorVote, replayed, err := owners[1].VoteSelectV1(garblerPrepare)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("evaluator replayed its first select vote")
	}
	selected0, replayed, err := owners[0].CommitSelectedV1(evaluatorVote)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("garbler replayed Selected")
	}
	selected1, replayed, err := owners[1].CommitSelectedV1(garblerVote)
	if err != nil {
		return zero, err
	} else if replayed {
		return zero, fmt.Errorf("evaluator replayed Selected")
	}
	return [2]formalGLMRegisteredPhase20SelectedV1{selected0, selected1}, nil
}

func formalGLMRegisteredPhase20HandoffAdapterTestOpenV1(
	t *testing.T,
	owner *formalGLMRegisteredPhase20TerminalOwnerV1,
) *formalGLMPhase20HandoffStore {
	t.Helper()
	owner.mu.Lock()
	if owner.closed || owner.attempts == nil || owner.jobKeys == nil || owner.runtime == nil {
		owner.mu.Unlock()
		t.Fatal("terminal owner closed before handoff reopen")
	}
	rockRoot := owner.attempts.root.Name()
	semanticRoot, peer := owner.record.Binding.SemanticRootSHA256, owner.peer
	owner.runtime.mu.Lock()
	backend := owner.runtime.backendKey
	owner.runtime.mu.Unlock()
	owner.jobKeys.mu.Lock()
	storageRoot := owner.jobKeys.storageRoot
	owner.jobKeys.mu.Unlock()
	pins := formalGLMRegisteredPhase20TerminalClonePinsV1(owner.pins)
	owner.mu.Unlock()
	store, err := newFormalGLMPhase20HandoffStore(
		filepath.Join(rockRoot, peer, "formal-glm-phase20-handoff"), semanticRoot, peer,
		storageRoot, backend, pins)
	clear(storageRoot[:])
	if err != nil {
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.close()
		formalGLMRegisteredPhase20TerminalClearPinsV1(pins)
	})
	return store
}

func TestFormalGLMRegisteredPhase20SelectedHandoffAdapterK2(t *testing.T) {
	owners, roots, evidence := formalGLMRegisteredPhase20HandoffAdapterTestOwnersV1(t)
	if _, err := formalGLMRegisteredPhase20CommitSelectedHandoffV1(owners[0]); err == nil {
		t.Fatal("unselected terminal created a Phase20 handoff")
	}
	if _, err := os.Stat(filepath.Join(roots[0], owners[0].peer,
		"formal-glm-phase20-handoff")); !os.IsNotExist(err) {
		t.Fatalf("unselected terminal touched the handoff root: %v", err)
	}
	selected, err := formalGLMRegisteredPhase20HandoffAdapterTestSelectV1(t, owners, evidence)
	if err != nil || !reflect.DeepEqual(selected[0], selected[1]) {
		t.Fatalf("K2 terminal selection failed: %v", err)
	}

	for index, owner := range owners {
		commit, err := formalGLMRegisteredPhase20CommitSelectedHandoffV1(owner)
		if err != nil || commit.Replayed || !formalGLMIsSHA256(commit.SHA256) || commit.Bytes < 64 {
			t.Fatalf("handoff commit %d failed: %#v / %v", index, commit, err)
		}
		replay, err := formalGLMRegisteredPhase20CommitSelectedHandoffV1(owner)
		if err != nil || !replay.Replayed || replay.SHA256 != commit.SHA256 ||
			replay.Bytes != commit.Bytes {
			t.Fatalf("handoff replay %d changed: %#v / %v", index, replay, err)
		}
		handoff := formalGLMRegisteredPhase20HandoffAdapterTestOpenV1(t, owner)
		if _, err := os.Stat(filepath.Join(roots[index], "formal-glm-phase20-handoff")); !os.IsNotExist(err) {
			t.Fatalf("handoff %d escaped the authority root: %v", index, err)
		}
		source, durable, err := handoff.Load()
		if err != nil || durable.SHA256 != commit.SHA256 || durable.Bytes != commit.Bytes ||
			source.Result.Peer != evidence[index].Peer ||
			source.Result.DPShare != evidence[index].CanonicalDPShare {
			source.clear()
			t.Fatalf("handoff reopen %d changed selected source: %#v / %v", index, durable, err)
		}
		source.clear()
		encoded, err := json.Marshal(commit)
		if err != nil || string(encoded) == "{}" ||
			bytes.Contains(encoded, []byte(evidence[index].CanonicalDPShare)) {
			t.Fatalf("handoff commit exposed protected source %d: %s / %v", index, encoded, err)
		}
		formalGLMRegisteredPhase20TerminalTestPrivateJSONV1(t, owner)
	}
	if selected[0].OpeningsPerformed != 0 || selected[0].ProductionReady {
		t.Fatal("adapter accepted a public or opened terminal")
	}
}
