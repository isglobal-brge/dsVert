package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func formalGLMPhase21PublicTerminalTestStageRecordV1(
	t testing.TB,
	fixture formalGLMPublicEndpointTestFixture,
	binding formalFinalizerHandoffBinding,
	index int,
) formalGLMPhase21RockStageRecord {
	t.Helper()
	authority := binding.Authorities[index]
	hash := func(label string) string {
		return sha256Hex([]byte(t.Name() + "/" + authority.PeerName + "/" + label))
	}
	sourceReceipt := jointDPBiomedicalGaussianOneDrawChunkReceipt{
		Version:                  jointDPBiomedicalGaussianOneDrawChunkReceiptVersion,
		Route:                    jointDPBiomedicalGaussianWorkerRoute,
		EnvelopePreimageSHA256:   hash("envelope"),
		ProductiveStreamSHA256:   hash("stream"),
		ReleaseInstanceID:        hash("instance"),
		ReleaseContractSHA256:    hash("release-contract"),
		PlanSHA256:               binding.PlanSHA256,
		CoordinateOrderSHA256:    hash("coordinate-order"),
		TotalCoordinateCount:     1,
		ChunkStart:               0,
		CoordinateCount:          1,
		PeerName:                 authority.PeerName,
		PeerID:                   authority.PeerID,
		Role:                     authority.Role,
		OutputShareSHA256:        hash("output-share"),
		PayloadShareCount:        1,
		ValidityXORShareIncluded: true,
	}
	message, err := jointDPBiomedicalGaussianOneDrawChunkReceiptMessage(sourceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	sourceReceipt.Signature = ed25519.Sign(
		fixture.phase21.keys[authority.PeerName], message)
	sourceSHA256, err := formalGLMPhase21LocalSpoolReceiptSHA256(sourceReceipt)
	if err != nil {
		t.Fatal(err)
	}
	contractSHA256, err := formalGLMPhase21SamplerV2ContractSHA256(
		fixture.phase21.contract)
	if err != nil {
		t.Fatal(err)
	}
	receipt := formalGLMPhase21RockStageReceipt{
		Version:             formalGLMPhase21RockRecordVersion,
		Purpose:             formalGLMPhase21RockStagePurpose,
		ArtifactID:          fixture.resolution.ArtifactID,
		ContractSHA256:      contractSHA256,
		PeerName:            authority.PeerName,
		PeerID:              authority.PeerID,
		Role:                authority.Role,
		FinalPairRootSHA256: binding.FinalPairRootSHA256,
		PlanSHA256:          binding.PlanSHA256,
		SourceReceiptSHA256: sourceSHA256,
		SourceReceipt:       sourceReceipt,
	}
	message, err = formalGLMPhase21RockStageMessage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = ed25519.Sign(
		fixture.phase21.keys[authority.PeerName], message)
	return formalGLMPhase21RockStageRecord{
		Version:    formalGLMPhase21RockRecordVersion,
		Family:     formalFinalizerHandoffFamilyGLM,
		Purpose:    formalGLMPhase21RockStagePurpose,
		ArtifactID: fixture.resolution.ArtifactID,
		Binding:    binding,
		Receipt:    receipt,
	}
}

func formalGLMPhase21PublicTerminalTestPersistV1(
	t testing.TB,
	root string,
	fixture formalGLMPublicEndpointTestFixture,
	terminal formalGLMPublicTerminalEvidenceV1,
) {
	t.Helper()
	for index, authority := range terminal.Contract.Artifact.NoiseAuthorities {
		path, err := formalGLMPhase21RockStageRecordPath(
			root, terminal.Contract.ArtifactID, authority.Role)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMPhase21RockTestWriteJSON(t, path,
			formalGLMPhase21PublicTerminalTestStageRecordV1(
				t, fixture, terminal.Binding, index))
	}
	ticketPath, err := formalGLMPhase21RockTicketRecordPath(
		root, terminal.Contract.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	formalGLMPhase21RockTestWriteJSON(t, ticketPath,
		formalGLMPhase21RockTicketRecord{
			Version:    formalGLMPhase21RockRecordVersion,
			Family:     formalFinalizerHandoffFamilyGLM,
			Purpose:    formalGLMPhase21RockTicketPurpose,
			ArtifactID: terminal.Contract.ArtifactID,
			Binding:    terminal.Binding,
			Ticket:     terminal.Ticket,
		})
	for index, authority := range terminal.Contract.Artifact.NoiseAuthorities {
		commitPath, err := formalGLMPhase21RockCommitRecordPath(
			root, terminal.Contract.ArtifactID, authority.Role)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMPhase21RockTestWriteJSON(t, commitPath, terminal.Commits[index])
		cleanupPath, err := formalGLMPhase21RockCleanupRecordPath(
			root, terminal.Contract.ArtifactID, authority.Role)
		if err != nil {
			t.Fatal(err)
		}
		formalGLMPhase21RockTestWriteJSON(t, cleanupPath, terminal.Cleanups[index])
	}
	ackPath, err := formalGLMPhase21RockAckRecordPath(root, terminal.Contract.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	formalGLMPhase21RockTestWriteJSON(t, ackPath, terminal.Ack)
}

func TestFormalGLMPhase21PublicTerminalStoreK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPublicEndpointTestSetup(t, custodians)
			terminal := formalGLMPublicEndpointTestTerminal(t, fixture)
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "rock")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			formalGLMPhase21PublicTerminalTestPersistV1(t, root, fixture, terminal)

			loaded, err := formalGLMPhase21RockLoadPublicTerminalEvidenceV1(
				root, terminal.Contract, fixture.phase21.pins, fixture.resolution)
			if err != nil || !reflect.DeepEqual(loaded, terminal) {
				t.Fatalf("terminal load changed durable evidence: %#v / %v", loaded, err)
			}
			replayed, err := formalGLMPhase21RockLoadPublicTerminalEvidenceV1(
				root, terminal.Contract, fixture.phase21.pins, fixture.resolution)
			if err != nil || !reflect.DeepEqual(replayed, loaded) {
				t.Fatalf("terminal restart changed durable evidence: %#v / %v", replayed, err)
			}
			encoded, err := json.Marshal(loaded)
			if err != nil || bytes.Contains(encoded, []byte(`"canonical_dp_share"`)) ||
				bytes.Contains(encoded, []byte(`"backend_key"`)) ||
				bytes.Contains(encoded, []byte(`"ciphertext"`)) {
				t.Fatalf("terminal evidence exposed protected source: %s / %v", encoded, err)
			}

			cleanupPath, err := formalGLMPhase21RockCleanupRecordPath(
				root, terminal.Contract.ArtifactID,
				terminal.Contract.Artifact.NoiseAuthorities[1].Role)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(cleanupPath); err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21RockLoadPublicTerminalEvidenceV1(
				root, terminal.Contract, fixture.phase21.pins, fixture.resolution); err == nil {
				t.Fatal("terminal load accepted missing dual cleanup")
			}
		})
	}
}
