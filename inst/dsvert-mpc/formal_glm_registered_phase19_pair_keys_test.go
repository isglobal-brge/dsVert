package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type formalGLMRegisteredPhase19PairKeyTestFixtureV1 struct {
	source    formalGLMSourceContractTestFixtureV1
	root      string
	providers map[string]*formalGLMRegisteredPhase19PairKeyProviderV1
	public    map[string][]byte
	tickets   []formalGLMRegisteredPhase18RecipientTicketV1
	record    formalGLMRegisteredPhase19BindingRecordV1
}

func formalGLMRegisteredPhase19PairKeyTestRecord(t testing.TB,
	source formalGLMSourceContractTestFixtureV1,
	tickets []formalGLMRegisteredPhase18RecipientTicketV1,
) formalGLMRegisteredPhase19BindingRecordV1 {
	t.Helper()
	pins := source.inputs.identities.public
	context, err := formalGLMRegisteredPhase18NewProvenanceContextV1(
		source.contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]formalGLMRegisteredPhase18LocalReceiptV1, 0,
		source.plan.CustodianCount)
	for _, sourceName := range source.plan.CustodianPeers {
		authorization, err := formalGLMProjectRegisteredPhase18AuthorizationV1(
			source.contract, sourceName, pins)
		if err != nil {
			t.Fatal(err)
		}
		authorization.AuthorizationSHA256, err =
			formalGLMRegisteredPhase18AuthorizationSHA256V1(authorization)
		if err != nil {
			t.Fatal(err)
		}
		blocks := make([]formalGLMRegisteredPhase18BlockPairV1, 0,
			authorization.Geometry.TotalBlocks)
		for blockIndex := 0; blockIndex < authorization.Geometry.TotalBlocks; blockIndex++ {
			ciphertexts := make(map[string][]byte, 2)
			for recipientIndex, recipient := range authorization.DesignatedComputePeers {
				ciphertexts[recipient] =
					formalGLMRegisteredPhase18ProvenanceTestCiphertext(
						sourceName, recipient, blockIndex, recipientIndex)
			}
			pair, err := formalGLMRegisteredPhase18BuildBlockPairWithContextV1(
				context, authorization, tickets, blockIndex, ciphertexts,
				source.inputs.identities.private[sourceName])
			if err != nil {
				t.Fatal(err)
			}
			blocks = append(blocks, pair)
		}
		receipt, err := formalGLMRegisteredPhase18BuildLocalReceiptWithContextV1(
			context, authorization, tickets, blocks,
			source.inputs.identities.private[sourceName])
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	receiptSet, err := formalGLMRegisteredPhase18BuildReceiptSetV1(
		source.contract, receipts, pins)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := formalGLMBuildRegisteredPhase19BindingV1(
		source.contract, receiptSet, tickets, pins)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := formalGLMRegisteredPhase18CanonicalTicketsV1(
		tickets, source.contract, pins)
	if err != nil {
		t.Fatal(err)
	}
	record := formalGLMRegisteredPhase19BindingRecordV1{
		Version: formalGLMRegisteredPhase19BindingRecordVersion,
		Purpose: formalGLMRegisteredPhase19BindingRecordPurpose,
		Binding: binding, ReceiptSet: receiptSet, RecipientTickets: ordered,
	}
	if err := formalGLMValidateRegisteredPhase19BindingRecordV1(
		record, source.contract, pins); err != nil {
		t.Fatal(err)
	}
	return record
}

func formalGLMRegisteredPhase19PairKeyTestBuild(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase19PairKeyTestFixtureV1 {
	t.Helper()
	source := formalGLMSourceContractTestFixture(t, custodians)
	root := filepath.Join(t.TempDir(), "pair-key-rock")
	providers := make(
		map[string]*formalGLMRegisteredPhase19PairKeyProviderV1, 2)
	public := make(map[string][]byte, 2)
	tickets := make([]formalGLMRegisteredPhase18RecipientTicketV1, 0, 2)
	for _, peer := range source.plan.DesignatedComputePeers {
		provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
			root, peer, source.contract, source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		providers[peer] = provider
		public[peer], err = provider.PublicKeyV1()
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
			source.contract, peer, public[peer],
			source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
			unsigned, source.contract,
			source.inputs.identities.private[peer],
			source.inputs.identities.public)
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, ticket)
	}
	record := formalGLMRegisteredPhase19PairKeyTestRecord(t, source, tickets)
	fixture := formalGLMRegisteredPhase19PairKeyTestFixtureV1{
		source: source, root: root, providers: providers, public: public,
		tickets: tickets, record: record,
	}
	t.Cleanup(func() {
		for _, provider := range fixture.providers {
			provider.Close()
		}
	})
	return fixture
}

func formalGLMRegisteredPhase19PairKeyTestBackends(t testing.TB,
	fixture formalGLMRegisteredPhase19PairKeyTestFixtureV1,
	record formalGLMRegisteredPhase19BindingRecordV1,
) map[string][32]byte {
	t.Helper()
	result := make(map[string][32]byte, 2)
	for _, peer := range fixture.source.plan.DesignatedComputePeers {
		backend, err := fixture.providers[peer].DeriveBackendV1(record)
		if err != nil {
			t.Fatal(err)
		}
		result[peer] = backend
	}
	return result
}

func formalGLMRegisteredPhase19PairKeyTestAssertSymmetric(t testing.TB,
	fixture formalGLMRegisteredPhase19PairKeyTestFixtureV1,
	backends map[string][32]byte,
) [32]byte {
	t.Helper()
	peers := fixture.source.plan.DesignatedComputePeers
	left, right := backends[peers[0]], backends[peers[1]]
	if left == ([32]byte{}) || left != right {
		t.Fatalf("registered Phase19 pair backend is not symmetric: %x != %x",
			left, right)
	}
	return left
}

func TestFormalGLMRegisteredPhase19PairKeyK2K5SymmetricRestartReplay(
	t *testing.T,
) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, custodians)
			first := formalGLMRegisteredPhase19PairKeyTestAssertSymmetric(
				t, fixture, formalGLMRegisteredPhase19PairKeyTestBackends(
					t, fixture, fixture.record))

			for _, peer := range fixture.source.plan.DesignatedComputePeers {
				again, err := fixture.providers[peer].PublicKeyV1()
				if err != nil || !bytes.Equal(again, fixture.public[peer]) {
					t.Fatalf("same-process public-key replay changed for %s: %v",
						peer, err)
				}
				fixture.providers[peer].Close()
				restarted, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
					fixture.root, peer, fixture.source.contract,
					fixture.source.inputs.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				fixture.providers[peer] = restarted
				after, err := restarted.PublicKeyV1()
				if err != nil || !bytes.Equal(after, fixture.public[peer]) {
					t.Fatalf("restart rerolled public key for %s: %v", peer, err)
				}
			}
			restarted := formalGLMRegisteredPhase19PairKeyTestAssertSymmetric(
				t, fixture, formalGLMRegisteredPhase19PairKeyTestBackends(
					t, fixture, fixture.record))
			if restarted != first {
				t.Fatal("restart rerolled registered Phase19 pair backend")
			}

			if encoded, err := json.Marshal(fixture.providers[fixture.source.plan.DesignatedComputePeers[0]]); err != nil ||
				string(encoded) != "{}" {
				t.Fatalf("pair-key provider serialized private state: %s %v",
					encoded, err)
			}
			walkErr := filepath.WalkDir(fixture.root,
				func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					info, err := entry.Info()
					if err != nil {
						return err
					}
					if entry.IsDir() && info.Mode().Perm() != 0o700 {
						return fmt.Errorf("unsafe directory mode %o at %s",
							info.Mode().Perm(), path)
					}
					if !entry.IsDir() && info.Mode().Perm() != 0o600 {
						return fmt.Errorf("unsafe key mode %o at %s",
							info.Mode().Perm(), path)
					}
					return nil
				})
			if walkErr != nil {
				t.Fatal(walkErr)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19PairKeyRejectsBindingsAndTickets(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 2)
	peer := fixture.source.plan.DesignatedComputePeers[0]
	provider := fixture.providers[peer]

	badSignature := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.record)
	badSignature.RecipientTickets[0].Signature[0] ^= 1
	if _, err := provider.DeriveBackendV1(badSignature); err == nil {
		t.Fatal("tampered recipient-ticket signature was accepted")
	}
	incomplete := formalGLMRegisteredPhase18ProvenanceTestClone(t, fixture.record)
	incomplete.RecipientTickets = incomplete.RecipientTickets[:1]
	if _, err := provider.DeriveBackendV1(incomplete); err == nil {
		t.Fatal("incomplete recipient-ticket pair was accepted")
	}
	changedSemantic := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.record)
	changedSemantic.Binding.SemanticRootSHA256 = sha256Hex([]byte(
		"registered-phase19/pair-key/unauthorized-semantic"))
	if _, err := provider.DeriveBackendV1(changedSemantic); err == nil {
		t.Fatal("caller-selected SemanticRoot was accepted")
	}

	rotated, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := formalGLMRegisteredPhase18BuildRecipientTicketV1(
		fixture.source.contract, peer, rotated.PublicKey().Bytes(),
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	rotatedTicket, err := formalGLMRegisteredPhase18SignRecipientTicketV1(
		unsigned, fixture.source.contract,
		fixture.source.inputs.identities.private[peer],
		fixture.source.inputs.identities.public)
	if err != nil {
		t.Fatal(err)
	}
	validButDifferent := formalGLMRegisteredPhase18ProvenanceTestClone(
		t, fixture.record)
	validButDifferent.RecipientTickets[0] = rotatedTicket
	if _, err := provider.DeriveBackendV1(validButDifferent); err == nil {
		t.Fatal("valid replacement ticket bypassed the fixed local key")
	}

	pins := make(map[string]ed25519.PublicKey,
		len(fixture.source.inputs.identities.public))
	for name, pin := range fixture.source.inputs.identities.public {
		pins[name] = append([]byte(nil), pin...)
	}
	pins[peer][0] ^= 1
	if created, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
		filepath.Join(t.TempDir(), "wrong-pins"), peer,
		fixture.source.contract, pins); err == nil {
		created.Close()
		t.Fatal("tampered pinset opened a registered pair-key provider")
	}
	if created, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
		filepath.Join(t.TempDir(), "wrong-peer"), "not-designated",
		fixture.source.contract,
		fixture.source.inputs.identities.public); err == nil {
		created.Close()
		t.Fatal("non-designated local peer opened a pair-key provider")
	}
}

func TestFormalGLMRegisteredPhase19PairKeyDiskBindingAndCrashClosed(
	t *testing.T,
) {
	t.Run("hardlink", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 2)
		peer := fixture.source.plan.DesignatedComputePeers[0]
		keyPath := filepath.Join(fixture.root,
			fixture.providers[peer].keyRelativePathV1())
		fixture.providers[peer].Close()
		if err := os.Link(keyPath, keyPath+".hardlink"); err != nil {
			t.Fatal(err)
		}
		if reopened, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
			fixture.root, peer, fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			reopened.Close()
			t.Fatal("hard-linked pair key was accepted")
		}
	})

	t.Run("cross-peer-key-copy", func(t *testing.T) {
		fixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 2)
		peers := fixture.source.plan.DesignatedComputePeers
		left := filepath.Join(fixture.root,
			fixture.providers[peers[0]].keyRelativePathV1())
		right := filepath.Join(fixture.root,
			fixture.providers[peers[1]].keyRelativePathV1())
		for _, provider := range fixture.providers {
			provider.Close()
		}
		encoded, err := os.ReadFile(left)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		if err := os.WriteFile(right, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if reopened, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
			fixture.root, peers[1], fixture.source.contract,
			fixture.source.inputs.identities.public); err == nil {
			reopened.Close()
			t.Fatal("pair key copied from the other designated peer was accepted")
		}
	})

	t.Run("cross-artifact-key-copy", func(t *testing.T) {
		leftFixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 2)
		rightFixture := formalGLMRegisteredPhase19PairKeyTestBuild(t, 5)
		leftPeer := leftFixture.source.plan.DesignatedComputePeers[0]
		rightPeer := rightFixture.source.plan.DesignatedComputePeers[0]
		leftPath := filepath.Join(leftFixture.root,
			leftFixture.providers[leftPeer].keyRelativePathV1())
		rightPath := filepath.Join(rightFixture.root,
			rightFixture.providers[rightPeer].keyRelativePathV1())
		leftFixture.providers[leftPeer].Close()
		rightFixture.providers[rightPeer].Close()
		encoded, err := os.ReadFile(leftPath)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		if err := os.WriteFile(rightPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if reopened, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
			rightFixture.root, rightPeer, rightFixture.source.contract,
			rightFixture.source.inputs.identities.public); err == nil {
			reopened.Close()
			t.Fatal("pair key copied from another ArtifactID was accepted")
		}
	})

	for _, boundary := range []string{"mkdir-before-key", "partial-key"} {
		t.Run(boundary, func(t *testing.T) {
			source := formalGLMSourceContractTestFixture(t, 2)
			peer := source.plan.DesignatedComputePeers[0]
			root := filepath.Join(t.TempDir(), "crash-rock")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			index := 0
			peerDir := filepath.Join(root,
				formalGLMRegisteredPhase19PairKeyRelativeDirV1(
					source.contract.Core.ArtifactID, index))
			if err := os.MkdirAll(peerDir, 0o700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(peerDir,
				formalGLMRegisteredPhase19PairKeyFileV1)
			partial := []byte("partial-x25519-secret")
			if boundary == "partial-key" {
				if err := os.WriteFile(keyPath, partial, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if provider, err := newFormalGLMRegisteredPhase19PairKeyProviderV1(
					root, peer, source.contract,
					source.inputs.identities.public); err == nil {
					provider.Close()
					t.Fatal("crash boundary generated a replacement pair key")
				}
			}
			if boundary == "mkdir-before-key" {
				if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
					t.Fatalf("orphan marker generated a pair key: %v", err)
				}
			} else if after, err := os.ReadFile(keyPath); err != nil ||
				!reflect.DeepEqual(after, partial) {
				t.Fatalf("partial pair key was replaced: %x %v", after, err)
			}
		})
	}
}
