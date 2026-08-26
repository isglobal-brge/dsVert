package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalFinalizerHandoffTestFixture struct {
	binding     formalFinalizerHandoffBinding
	public      map[string]ed25519.PublicKey
	private     map[string]ed25519.PrivateKey
	transport   *ecdh.PrivateKey
	storageRoot [32]byte
}

type formalFinalizerHandoffTestPublicationGuard struct {
	wantArtifact    string
	wantCertificate string
	err             error
}

func (guard formalFinalizerHandoffTestPublicationGuard) formalFinalizerHandoffVerifyPublication(
	artifactID, certificateSHA256 string,
) error {
	if artifactID != guard.wantArtifact ||
		certificateSHA256 != guard.wantCertificate {
		return os.ErrInvalid
	}
	return guard.err
}

func formalFinalizerHandoffTestSHA(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func TestFormalFinalizerHandoffAuthorityLockBusyIsTyped(t *testing.T) {
	directory := t.TempDir()
	firstRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer firstRoot.Close()
	secondRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRoot.Close()
	artifactID := formalFinalizerHandoffTestSHA(t.Name())
	first, err := formalFinalizerHandoffAcquireAuthorityLock(firstRoot, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = formalFinalizerHandoffUnlockAuthority(first)
		_ = first.Close()
	}()
	if _, err := formalFinalizerHandoffAcquireAuthorityLock(secondRoot, artifactID); !errors.Is(err, errFormalFinalizerHandoffAuthorityLockBusy) {
		t.Fatalf("second authority lock error=%v; want typed busy", err)
	}
}

func formalFinalizerHandoffTestFixtureForK(t *testing.T, custodians int,
	family string,
) formalFinalizerHandoffTestFixture {
	t.Helper()
	if custodians < 2 {
		t.Fatal("invalid test consortium")
	}
	public := make(map[string]ed25519.PublicKey, custodians)
	private := make(map[string]ed25519.PrivateKey, custodians)
	peers := make([]string, custodians)
	for index := range peers {
		peer := "site" + string(rune('a'+index))
		pin, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peers[index] = peer
		public[peer] = pin
		private[peer] = key
	}
	pinset, err := formalGLMPhase16PinsetSHA256(public)
	if err != nil {
		t.Fatal(err)
	}
	authorities := make([]formalFinalizerHandoffAuthority, 2)
	for index, role := range []string{"garbler", "evaluator"} {
		peerID, err := formalGLMPhase16PeerID(public[peers[index]])
		if err != nil {
			t.Fatal(err)
		}
		authorities[index] = formalFinalizerHandoffAuthority{
			PeerName: peers[index], PeerID: peerID, Role: role,
		}
	}
	purpose := formalFinalizerHandoffGLMPurpose
	if family == formalFinalizerHandoffFamilyCox {
		purpose = formalFinalizerHandoffCoxPurpose
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return formalFinalizerHandoffTestFixture{
		binding: formalFinalizerHandoffBinding{
			Family: family, Purpose: purpose,
			ArtifactID:          formalFinalizerHandoffTestSHA(t.Name() + "/artifact"),
			FinalPairRootSHA256: formalFinalizerHandoffTestSHA(t.Name() + "/pair"),
			PlanSHA256:          formalFinalizerHandoffTestSHA(t.Name() + "/plan"),
			PinsetSHA256:        pinset,
			Authorities:         authorities,
			Finalizer:           authorities[0],
		},
		public: public, private: private, transport: transport,
		storageRoot: sha256.Sum256([]byte(t.Name() + "/owner-storage-root")),
	}
}

func formalFinalizerHandoffTestPayload(t *testing.T,
	fixture formalFinalizerHandoffTestFixture,
	ticket formalFinalizerHandoffTicket, sender, kind string, marker int,
) []byte {
	t.Helper()
	role, peerID := "", ""
	for _, authority := range fixture.binding.Authorities {
		if authority.PeerName == sender {
			role, peerID = authority.Role, authority.PeerID
		}
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		t.Fatal(err)
	}
	nested, version := "", ""
	switch kind {
	case formalFinalizerHandoffGLMOneDrawKind:
		nested, version = "one_draw", formalFinalizerHandoffGLMOneDrawPayloadVersion
	case formalFinalizerHandoffGLMFullKind:
		nested, version = "full", formalFinalizerHandoffGLMFullPayloadVersion
	case formalFinalizerHandoffCoxOpeningKind:
		nested, version = "handoff", formalFinalizerHandoffCoxPayloadVersion
	default:
		t.Fatal("invalid test payload kind")
	}
	value := map[string]any{
		"version": version, "purpose": fixture.binding.Purpose,
		"artifact_id":            fixture.binding.ArtifactID,
		"plan_sha256":            fixture.binding.PlanSHA256,
		"final_pair_root_sha256": fixture.binding.FinalPairRootSHA256,
		"ticket_sha256":          ticketSHA, "sender_peer_name": sender,
		"sender_peer_id": peerID, "sender_role": role,
		nested: map[string]any{"marker": marker, "validity": marker%2 == 0},
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalFinalizerHandoffAuthorityStoreRejectsOppositeRole(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	var stores [2]*formalFinalizerHandoffStore
	for index, authority := range fixture.binding.Authorities {
		root := sha256.Sum256([]byte(t.Name() + "/" + authority.Role))
		var err error
		stores[index], err = newFormalFinalizerHandoffAuthorityStoreForTest(
			filepath.Join(t.TempDir(), authority.Role), fixture.binding,
			authority, root, fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		defer stores[index].Close()
	}
	ticket, secret, _, err := stores[0].IssueTicketOnce(
		fixture.private[fixture.binding.Finalizer.PeerName])
	if err != nil {
		clear(secret)
		t.Fatal(err)
	}
	clear(secret)
	if _, secret, _, err := stores[1].IssueTicketOnce(
		fixture.private[fixture.binding.Finalizer.PeerName]); err == nil ||
		len(secret) != 0 {
		clear(secret)
		t.Fatal("evaluator authority store issued a finalizer ticket")
	}
	if _, _, err := stores[1].CommitTicket(ticket); err != nil {
		t.Fatal(err)
	}
	var envelopes [2]formalFinalizerHandoffEnvelope
	for index, authority := range fixture.binding.Authorities {
		payload := formalFinalizerHandoffTestPayload(t, fixture, ticket,
			authority.PeerName, formalFinalizerHandoffGLMOneDrawKind, index+1)
		envelopes[index], err = formalFinalizerHandoffSealCanonical(
			fixture.binding, ticket, authority.PeerName,
			formalFinalizerHandoffGLMOneDrawKind, payload,
			fixture.private[authority.PeerName], fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := stores[index].CommitOutbox(envelopes[index]); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stores[1-index].CommitOutbox(envelopes[index]); err == nil {
			t.Fatalf("%s store persisted the opposite authority outbox",
				fixture.binding.Authorities[1-index].Role)
		}
	}
	if _, _, err := stores[1].CommitIngress(envelopes[1]); err == nil {
		t.Fatal("evaluator authority store persisted finalizer ingress")
	}
	for _, envelope := range envelopes {
		if _, _, err := stores[0].CommitIngress(envelope); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFormalFinalizerHandoffAuthorityStoreSerializesArtifactLifecycle(
	t *testing.T,
) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 2, formalFinalizerHandoffFamilyGLM)
	local := fixture.binding.Authorities[0]
	dir := filepath.Join(t.TempDir(), local.PeerName)
	first, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		dir, fixture.binding, local, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		dir, fixture.binding, local, fixture.storageRoot, fixture.public); err == nil {
		second.Close()
		first.Close()
		t.Fatal("two processes acquired the same authority ArtifactID lifecycle")
	}
	first.Close()
	restarted, err := newFormalFinalizerHandoffAuthorityStoreForTest(
		dir, fixture.binding, local, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatalf("crash-released authority lifecycle lock was not reusable: %v", err)
	}
	restarted.Close()
}

func TestFormalFinalizerHandoffCapabilityRegistryIsClosed(t *testing.T) {
	capability := formalFinalizerHandoffCapabilities()
	if capability.Version != formalFinalizerHandoffCapabilityVersion ||
		!capability.InternalAvailable || capability.ProductionReady ||
		!capability.ExposedThroughDSI ||
		!reflect.DeepEqual(capability.Families,
			[]formalFinalizerHandoffFamilyCapability{
				{Family: formalFinalizerHandoffFamilyGLM,
					Purpose: formalFinalizerHandoffGLMPurpose,
					PayloadKinds: []string{
						formalFinalizerHandoffGLMOneDrawKind,
						formalFinalizerHandoffGLMFullKind,
					}},
				{Family: formalFinalizerHandoffFamilyCox,
					Purpose: formalFinalizerHandoffCoxPurpose,
					PayloadKinds: []string{
						formalFinalizerHandoffCoxOpeningKind,
					}},
			}) {
		t.Fatalf("unexpected typed handoff capability: %#v", capability)
	}
	for _, invalid := range [][2]string{
		{"", formalFinalizerHandoffGLMPurpose},
		{"glm", formalFinalizerHandoffGLMPurpose},
		{formalFinalizerHandoffFamilyGLM, formalFinalizerHandoffCoxPurpose},
		{formalFinalizerHandoffFamilyCox, "arbitrary"},
	} {
		if _, err := formalFinalizerHandoffLookup(
			invalid[0], invalid[1]); err == nil {
			t.Fatalf("unregistered family/purpose was accepted: %q/%q",
				invalid[0], invalid[1])
		}
	}
	encoded, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"lifetime", "ledger", "reservation", "request_id", "attempt",
		"epoch", "quota", "rate", "catalog", "capsule_id", "run_id",
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("typed handoff capability leaked legacy field %q: %s",
				forbidden, encoded)
		}
	}
	manifest, err := json.Marshal(runtimeCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifest, []byte("finalizer_handoff")) ||
		bytes.Contains(manifest, []byte(formalFinalizerHandoffFamilyGLM)) ||
		bytes.Contains(manifest, []byte(formalFinalizerHandoffFamilyCox)) {
		t.Fatal("unpromoted handoff escaped into runtime-capabilities")
	}
}

func TestFormalFinalizerHandoffConfiguredStateRootIsCanonical(t *testing.T) {
	if got := formalFinalizerHandoffConfiguredStateRootV1(""); got != formalFinalizerHandoffDefaultStateRoot {
		t.Fatalf("default state root = %q", got)
	}
	configured := filepath.Join(t.TempDir(), "finalizer")
	if got := formalFinalizerHandoffConfiguredStateRootV1(configured); got != configured {
		t.Fatalf("configured state root = %q, want %q", got, configured)
	}
	for _, invalid := range []string{
		"relative", configured + "/../other", "\x00unsafe",
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("accepted invalid configured state root %q", invalid)
				}
			}()
			_ = formalFinalizerHandoffConfiguredStateRootV1(invalid)
		}()
	}
}

func TestFormalFinalizerHandoffBindingOrderAndTypedSchemaFailClosed(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 5, formalFinalizerHandoffFamilyGLM)
	ticket, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, fixture.transport.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*formalFinalizerHandoffBinding){
		"authority-order": func(value *formalFinalizerHandoffBinding) {
			value.Authorities[0], value.Authorities[1] =
				value.Authorities[1], value.Authorities[0]
		},
		"finalizer": func(value *formalFinalizerHandoffBinding) {
			value.Finalizer = value.Authorities[1]
		},
		"peer-id": func(value *formalFinalizerHandoffBinding) {
			value.Authorities[0].PeerID = "dsv1_" + strings.Repeat("0", 64)
		},
		"pinset": func(value *formalFinalizerHandoffBinding) {
			value.PinsetSHA256 = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.binding
			candidate.Authorities = append(
				[]formalFinalizerHandoffAuthority(nil), fixture.binding.Authorities...)
			mutate(&candidate)
			if err := formalFinalizerHandoffValidateBinding(
				candidate, fixture.public); err == nil {
				t.Fatal("malformed or reordered binding was accepted")
			}
		})
	}

	valid := formalFinalizerHandoffTestPayload(t, fixture, ticket,
		"sitea", formalFinalizerHandoffGLMOneDrawKind, 1)
	if _, err := formalFinalizerHandoffSealCanonical(
		fixture.binding, ticket, "sitea", formalFinalizerHandoffCoxOpeningKind,
		valid, fixture.private["sitea"], fixture.public); err == nil {
		t.Fatal("cross-family payload kind was accepted")
	}
	for name, payload := range map[string][]byte{
		"arbitrary-bytes":  []byte("not-json"),
		"arbitrary-object": []byte(`{"blob":"AQID"}`),
		"unknown-field":    append(valid[:len(valid)-1], []byte(`,"blob":"AQID"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := formalFinalizerHandoffSealCanonical(
				fixture.binding, ticket, "sitea",
				formalFinalizerHandoffGLMOneDrawKind, payload,
				fixture.private["sitea"], fixture.public); err == nil {
				t.Fatal("untyped or malformed payload was accepted")
			}
		})
	}
	mutatedTicket := ticket
	mutatedTicket.RecipientTransportPublicKey = append(
		[]byte(nil), ticket.RecipientTransportPublicKey...)
	mutatedTicket.RecipientTransportPublicKey[0] ^= 1
	if formalFinalizerHandoffValidateTicket(
		mutatedTicket, fixture.binding, fixture.public) == nil {
		t.Fatal("ticket signature did not bind finalizer X25519 public key")
	}
	for _, invalid := range []string{"a/b", "..", `a\b`, "équipe"} {
		if formalFinalizerHandoffPathSafePeerName(invalid) {
			t.Fatalf("path-unsafe peer name was accepted: %q", invalid)
		}
	}
	for _, validName := range []string{"a", "site-1", "site_a", "site.a"} {
		if !formalFinalizerHandoffPathSafePeerName(validName) {
			t.Fatalf("path-safe peer name was rejected: %q", validName)
		}
	}
}

func TestFormalFinalizerHandoffWitnessCannotIssueSealSignOrDecrypt(t *testing.T) {
	for _, custodians := range []int{3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalFinalizerHandoffTestFixtureForK(
				t, custodians, formalFinalizerHandoffFamilyGLM)
			if _, err := formalFinalizerHandoffIssueTicket(
				fixture.binding, fixture.transport.PublicKey().Bytes(),
				fixture.private["sitec"], fixture.public); err == nil {
				t.Fatal("non-authority witness issued finalizer ticket")
			}
			ticket, err := formalFinalizerHandoffIssueTicket(
				fixture.binding, fixture.transport.PublicKey().Bytes(),
				fixture.private["sitea"], fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			payload := formalFinalizerHandoffTestPayload(t, fixture, ticket,
				"sitea", formalFinalizerHandoffGLMOneDrawKind, 3)
			if _, err := formalFinalizerHandoffSealCanonical(
				fixture.binding, ticket, "sitec",
				formalFinalizerHandoffGLMOneDrawKind, payload,
				fixture.private["sitec"], fixture.public); err == nil {
				t.Fatal("non-authority witness sealed a finalizer payload")
			}
			envelope, err := formalFinalizerHandoffSealCanonical(
				fixture.binding, ticket, "sitea",
				formalFinalizerHandoffGLMOneDrawKind, payload,
				fixture.private["sitea"], fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			store, err := newFormalFinalizerHandoffStoreForTest(
				filepath.Join(t.TempDir(), "handoff"), fixture.binding,
				fixture.storageRoot, fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, _, err := store.CommitTicket(ticket); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.CommitOutbox(envelope); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.CommitIngress(envelope); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.SignIntentOnce(
				ticket, "garbler", formalFinalizerHandoffTestSHA(t.Name()+"/intent"),
				envelope.PayloadSHA256, nil,
				fixture.private["sitec"]); err == nil {
				t.Fatal("non-authority witness passed SignOnce")
			}
			witnessTransport, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalFinalizerHandoffOpenCanonical(
				fixture.binding, ticket, envelope,
				witnessTransport.Bytes(), fixture.public); err == nil {
				t.Fatal("non-recipient witness decrypted finalizer payload")
			}

			missing := make(map[string]ed25519.PublicKey, len(fixture.public)-1)
			for peer, pin := range fixture.public {
				if peer != "sitec" {
					missing[peer] = pin
				}
			}
			if formalFinalizerHandoffValidateBinding(
				fixture.binding, missing) == nil {
				t.Fatal("missing witness escaped K pinset binding")
			}
			extra := make(map[string]ed25519.PublicKey, len(fixture.public)+1)
			for peer, pin := range fixture.public {
				extra[peer] = pin
			}
			extraPin, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			extra["extra-site"] = extraPin
			if formalFinalizerHandoffValidateBinding(
				fixture.binding, extra) == nil {
				t.Fatal("extra witness escaped K pinset binding")
			}
		})
	}
}

func TestFormalFinalizerHandoffK2K3K5ReplayRestartAndOrderedSignOnce(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		for _, family := range []string{
			formalFinalizerHandoffFamilyGLM,
			formalFinalizerHandoffFamilyCox,
		} {
			t.Run(family+"/K"+string(rune('0'+custodians)), func(t *testing.T) {
				fixture := formalFinalizerHandoffTestFixtureForK(
					t, custodians, family)
				ticket, err := formalFinalizerHandoffIssueTicket(
					fixture.binding, fixture.transport.PublicKey().Bytes(),
					fixture.private["sitea"], fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
				if err != nil {
					t.Fatal(err)
				}
				kind := formalFinalizerHandoffGLMOneDrawKind
				if family == formalFinalizerHandoffFamilyCox {
					kind = formalFinalizerHandoffCoxOpeningKind
				}
				payloads := make(map[string][]byte, 2)
				envelopes := make(map[string]formalFinalizerHandoffEnvelope, 2)
				for _, authority := range fixture.binding.Authorities {
					payloads[authority.Role] = formalFinalizerHandoffTestPayload(
						t, fixture, ticket, authority.PeerName, kind,
						map[string]int{"garbler": 1, "evaluator": 2}[authority.Role])
					envelope, err := formalFinalizerHandoffSealCanonical(
						fixture.binding, ticket, authority.PeerName, kind,
						payloads[authority.Role], fixture.private[authority.PeerName],
						fixture.public)
					if err != nil {
						t.Fatal(err)
					}
					envelopes[authority.Role] = envelope
				}

				root := filepath.Join(t.TempDir(), "handoff")
				store, err := newFormalFinalizerHandoffStoreForTest(
					root, fixture.binding, fixture.storageRoot, fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				storedTicket, replayed, err := store.CommitTicket(ticket)
				if err != nil || replayed || !reflect.DeepEqual(storedTicket, ticket) {
					t.Fatalf("initial ticket CAS failed: %#v %v", storedTicket, err)
				}
				for _, role := range []string{"garbler", "evaluator"} {
					stored, replayed, err := store.CommitOutbox(envelopes[role])
					if err != nil || replayed ||
						!reflect.DeepEqual(stored, envelopes[role]) {
						t.Fatalf("initial outbox CAS failed for %s: %#v %v",
							role, stored, err)
					}
					stored, replayed, err = store.CommitIngress(envelopes[role])
					if err != nil || replayed ||
						!reflect.DeepEqual(stored, envelopes[role]) {
						t.Fatalf("initial ingress CAS failed for %s: %#v %v",
							role, stored, err)
					}
					opened, err := store.OpenIngressCanonical(
						role, ticket, fixture.transport.Bytes())
					if err != nil || !bytes.Equal(opened, payloads[role]) {
						t.Fatalf("typed ingress open failed for %s: %q %v",
							role, opened, err)
					}
				}

				garblerIntent := formalFinalizerHandoffTestSHA(
					t.Name() + "/same-public-intent")
				garbler, replayed, err := store.SignIntentOnce(
					ticket, "garbler", garblerIntent,
					envelopes["garbler"].PayloadSHA256, nil,
					fixture.private["sitea"])
				if err != nil || replayed {
					t.Fatalf("garbler SignOnce failed: %#v %v", garbler, err)
				}
				if _, _, err := store.SignIntentOnce(ticket, "evaluator",
					garblerIntent, envelopes["evaluator"].PayloadSHA256, nil,
					fixture.private["siteb"]); err == nil {
					t.Fatal("evaluator signed without the exact garbler predecessor")
				}
				evaluator, replayed, err := store.SignIntentOnce(
					ticket, "evaluator", garblerIntent,
					envelopes["evaluator"].PayloadSHA256,
					[]formalFinalizerHandoffIntentAuthorization{garbler},
					fixture.private["siteb"])
				if err != nil || replayed {
					t.Fatalf("evaluator SignOnce failed: %#v %v", evaluator, err)
				}
				store.Close()

				restarted, err := newFormalFinalizerHandoffStoreForTest(
					root, fixture.binding, fixture.storageRoot, fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				defer restarted.Close()
				if _, replayed, err := restarted.CommitTicket(ticket); err != nil ||
					!replayed {
					t.Fatalf("restarted ticket did not replay: %v / %v", replayed, err)
				}
				for _, role := range []string{"garbler", "evaluator"} {
					stored, replayed, err := restarted.CommitOutbox(envelopes[role])
					if err != nil || !replayed ||
						!reflect.DeepEqual(stored, envelopes[role]) {
						t.Fatalf("restarted outbox did not replay %s: %v / %v",
							role, replayed, err)
					}
				}
				garblerReplay, replayed, err := restarted.SignIntentOnce(
					ticket, "garbler", garblerIntent,
					envelopes["garbler"].PayloadSHA256, nil,
					fixture.private["sitea"])
				if err != nil || !replayed || !reflect.DeepEqual(garblerReplay, garbler) {
					t.Fatalf("SignOnce was not restart-stable: %#v %v / %v",
						garblerReplay, replayed, err)
				}
				if ticketSHA == "" || evaluator.IntentSHA256 != garblerIntent {
					t.Fatal("ordered intent lost its canonical binding")
				}
			})
		}
	}
}

func TestFormalFinalizerHandoffTicketRotationReencryptionAndPairConflict(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 5, formalFinalizerHandoffFamilyGLM)
	first, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, fixture.transport.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, rotatedKey.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	firstSHA, _ := formalFinalizerHandoffTicketSHA256(first)
	rotatedSHA, _ := formalFinalizerHandoffTicketSHA256(rotated)
	if first.ArtifactID != rotated.ArtifactID || firstSHA == rotatedSHA {
		t.Fatal("ticket rotation changed ArtifactID or failed to rotate ticket evidence")
	}
	root := filepath.Join(t.TempDir(), "handoff")
	store, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.CommitTicket(first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CommitTicket(rotated); err == nil {
		t.Fatal("a rotated key replaced the ArtifactID-pinned first ticket")
	}

	payload := formalFinalizerHandoffTestPayload(t, fixture, first,
		"sitea", formalFinalizerHandoffGLMOneDrawKind, 7)
	one, err := formalFinalizerHandoffSealCanonical(
		fixture.binding, first, "sitea", formalFinalizerHandoffGLMOneDrawKind,
		payload, fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	two, err := formalFinalizerHandoffSealCanonical(
		fixture.binding, first, "sitea", formalFinalizerHandoffGLMOneDrawKind,
		payload, fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one.Ciphertext, two.Ciphertext) ||
		one.PayloadSHA256 != two.PayloadSHA256 {
		t.Fatal("re-encryption was not randomized or changed semantic payload")
	}
	firstStored, replayed, err := store.CommitOutbox(one)
	if err != nil || replayed {
		t.Fatal("first outbox CAS failed")
	}
	replayedStored, replayed, err := store.CommitOutbox(two)
	if err != nil || !replayed || !reflect.DeepEqual(firstStored, replayedStored) {
		t.Fatalf("semantic re-encryption did not replay first bytes: %v / %v", replayed, err)
	}
	ingressFirst, replayed, err := store.CommitIngress(one)
	if err != nil || replayed {
		t.Fatal("first randomized ingress CAS failed")
	}
	ingressReplay, replayed, err := store.CommitIngress(two)
	if err != nil || !replayed || !reflect.DeepEqual(ingressFirst, ingressReplay) {
		t.Fatalf("randomized ingress retry did not replay first bytes: %v / %v",
			replayed, err)
	}

	conflictingBinding := fixture.binding
	conflictingBinding.FinalPairRootSHA256 = formalFinalizerHandoffTestSHA(
		t.Name() + "/conflicting-pair")
	conflicting, err := formalFinalizerHandoffIssueTicket(
		conflictingBinding, fixture.transport.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	if conflicting.ArtifactID != first.ArtifactID {
		t.Fatal("pairRoot leaked into the canonical ArtifactID")
	}
	if _, _, err := store.CommitTicket(conflicting); err == nil {
		t.Fatal("same ArtifactID with an alternate pairRoot did not fail closed")
	}
}

func TestFormalFinalizerHandoffTamperAndCommitBeforeAck(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyCox)
	ticket, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, fixture.transport.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	payload := formalFinalizerHandoffTestPayload(t, fixture, ticket,
		"siteb", formalFinalizerHandoffCoxOpeningKind, 9)
	envelope, err := formalFinalizerHandoffSealCanonical(
		fixture.binding, ticket, "siteb", formalFinalizerHandoffCoxOpeningKind,
		payload, fixture.private["siteb"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "handoff")
	store, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.CommitTicket(ticket); err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if _, _, err := store.CommitIngress(tampered); err == nil {
		t.Fatal("tampered ciphertext reached ingress")
	}
	wrongSecret, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := formalFinalizerHandoffOpenCanonical(
		fixture.binding, ticket, envelope, wrongSecret.Bytes(), fixture.public); err == nil {
		t.Fatal("wrong finalizer X25519 key opened the recipient-bound envelope")
	}
	if _, _, err := store.CommitIngress(envelope); err != nil {
		t.Fatal(err)
	}
	opened, err := store.OpenIngressCanonical(
		"evaluator", ticket, fixture.transport.Bytes())
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("valid ciphertext failed after tamper rejection: %q %v", opened, err)
	}

	ticketSHA, _ := formalFinalizerHandoffTicketSHA256(ticket)
	certificateSHA := formalFinalizerHandoffTestSHA(t.Name() + "/certificate")
	proof, err := formalFinalizerHandoffBuildCommitProof(
		fixture.binding, ticketSHA, certificateSHA,
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	missingPublication := formalFinalizerHandoffTestPublicationGuard{
		wantArtifact:    fixture.binding.ArtifactID,
		wantCertificate: certificateSHA, err: os.ErrNotExist,
	}
	if _, _, err := store.AckAfterCommit(proof, missingPublication); err == nil {
		t.Fatal("ACK committed before the canonical publication existed")
	}
	durablePublication := formalFinalizerHandoffTestPublicationGuard{
		wantArtifact:    fixture.binding.ArtifactID,
		wantCertificate: certificateSHA,
	}
	ack, replayed, err := store.AckAfterCommit(proof, durablePublication)
	if err != nil || replayed || !reflect.DeepEqual(ack, proof) {
		t.Fatalf("post-commit ACK failed: %#v %v", ack, err)
	}

	for _, path := range []string{store.dir, filepath.Join(store.dir, "tickets-v1"),
		filepath.Join(store.dir, "ingress-v1"), filepath.Join(store.dir, "acks-v1")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("handoff directory is not owner-only: %s %#v %v", path, info, err)
		}
	}
	err = filepath.Walk(store.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("handoff record is not owner-only: %s %o", path, info.Mode().Perm())
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{
			"coefficient_shares", "capsule_id", "release_instance", "epoch",
			"reservation", "ledger", "lifetime", "quota", "attempt",
		} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("durable handoff record leaked %q: %s", forbidden, encoded)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFormalFinalizerHandoffDurableKeyRestartAndCleanupAfterAck(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	root := filepath.Join(t.TempDir(), "handoff")
	store, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	ticket, secret, replayed, err := store.IssueTicketOnce(
		fixture.private["sitea"])
	if err != nil || replayed || len(secret) != 32 {
		t.Fatalf("durable ticket issuance failed: %v / %v", replayed, err)
	}
	keyPath, err := store.relativePath("transport-keys-v1", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	keyRecord, err := os.ReadFile(filepath.Join(store.dir, keyPath))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(keyRecord, []byte(`"secret_key"`)) ||
		bytes.Contains(keyRecord, secret) ||
		bytes.Contains(keyRecord, []byte(base64.StdEncoding.EncodeToString(secret))) ||
		!bytes.Contains(keyRecord, []byte(`"nonce"`)) ||
		!bytes.Contains(keyRecord, []byte(`"ciphertext"`)) {
		t.Fatalf("durable transport key was not AEAD-only: %s", keyRecord)
	}
	clear(secret)
	envelopes := make(map[string]formalFinalizerHandoffEnvelope, 2)
	for index, authority := range fixture.binding.Authorities {
		payload := formalFinalizerHandoffTestPayload(t, fixture, ticket,
			authority.PeerName, formalFinalizerHandoffGLMFullKind, index+1)
		envelope, err := formalFinalizerHandoffSealCanonical(
			fixture.binding, ticket, authority.PeerName,
			formalFinalizerHandoffGLMFullKind, payload,
			fixture.private[authority.PeerName], fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		envelopes[authority.Role] = envelope
		if _, _, err := store.CommitOutbox(envelope); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.CommitIngress(envelope); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CleanupTransportAfterAck(
		formalFinalizerHandoffCommitProof{}); err == nil {
		t.Fatal("transport cleanup ran before durable ACK")
	}
	store.Close()

	restarted, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	replayedTicket, replayedSecret, replayed, err := restarted.IssueTicketOnce(
		fixture.private["sitea"])
	if err != nil || !replayed || !reflect.DeepEqual(replayedTicket, ticket) ||
		len(replayedSecret) != 32 {
		t.Fatalf("restart rotated durable finalizer key: %v / %v", replayed, err)
	}
	clear(replayedSecret)
	for _, role := range []string{"garbler", "evaluator"} {
		opened, err := restarted.OpenIngressDurableCanonical(role, ticket)
		if err != nil || len(opened) == 0 {
			t.Fatalf("restart could not open %s ingress: %v", role, err)
		}
		clear(opened)
	}
	ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
	if err != nil {
		t.Fatal(err)
	}
	certificateSHA := formalFinalizerHandoffTestSHA(t.Name() + "/certificate")
	proof, err := formalFinalizerHandoffBuildCommitProof(
		fixture.binding, ticketSHA, certificateSHA,
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	guard := formalFinalizerHandoffTestPublicationGuard{
		wantArtifact:    fixture.binding.ArtifactID,
		wantCertificate: certificateSHA,
	}
	if _, _, err := restarted.AckAfterCommit(proof, guard); err != nil {
		t.Fatal(err)
	}
	removed, err := restarted.CleanupTransportAfterAck(proof)
	if err != nil || removed != 5 {
		t.Fatalf("post-ACK transport cleanup removed %d records: %v", removed, err)
	}
	if removedAgain, err := restarted.CleanupTransportAfterAck(proof); err != nil ||
		removedAgain != 0 {
		t.Fatalf("cleanup replay was not idempotent: %d / %v", removedAgain, err)
	}
	if _, err := restarted.loadTicket(); err != nil {
		t.Fatal("cleanup removed the permanent ArtifactID ticket")
	}
	if _, err := restarted.loadAck(); err != nil {
		t.Fatal("cleanup removed the permanent publication ACK")
	}
	if _, _, err := restarted.loadTransportKey(); !os.IsNotExist(err) {
		t.Fatalf("cleanup retained finalizer transport secret: %v", err)
	}
	for _, envelope := range envelopes {
		if _, _, err := restarted.CommitOutbox(envelope); err == nil {
			t.Fatal("late outbox retry recreated transport after terminal ACK")
		} else {
			var terminal *formalFinalizerHandoffTerminalAckError
			if !errors.As(err, &terminal) ||
				terminal.Proof.CertificateSHA256 != certificateSHA {
				t.Fatalf("late outbox did not replay exact terminal ACK: %v", err)
			}
		}
		if _, _, err := restarted.CommitIngress(envelope); err == nil {
			t.Fatal("late ingress retry recreated transport after terminal ACK")
		}
	}
	if _, lateSecret, _, err := restarted.IssueTicketOnce(
		fixture.private["sitea"]); err == nil || len(lateSecret) != 0 {
		clear(lateSecret)
		t.Fatalf("post-cleanup ticket issue recreated a transport secret: %v", err)
	} else {
		var terminal *formalFinalizerHandoffTerminalAckError
		if !errors.As(err, &terminal) ||
			terminal.Proof.CertificateSHA256 != certificateSHA {
			t.Fatalf("post-cleanup ticket issue lost terminal ACK: %v", err)
		}
	}
	for _, directory := range []string{
		"transport-keys-v1", "outbox-v1", "ingress-v1",
	} {
		err := filepath.Walk(filepath.Join(restarted.dir, directory),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.Mode().IsRegular() {
					t.Fatalf("terminal retry recreated transport record: %s", path)
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestFormalFinalizerHandoffCleanupAsymmetricTransportIsIdempotent(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		for _, presentKind := range []string{"ingress-v1", "outbox-v1"} {
			name := "K" + string(rune('0'+custodians)) + "/" + presentKind
			t.Run(name, func(t *testing.T) {
				fixture := formalFinalizerHandoffTestFixtureForK(
					t, custodians, formalFinalizerHandoffFamilyGLM)
				store, err := newFormalFinalizerHandoffStoreForTest(
					filepath.Join(t.TempDir(), "handoff"), fixture.binding,
					fixture.storageRoot, fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				ticket, secret, replayed, err := store.IssueTicketOnce(
					fixture.private[fixture.binding.Finalizer.PeerName])
				if err != nil || replayed || len(secret) != 32 {
					clear(secret)
					t.Fatalf("ticket issue failed: replay=%v err=%v", replayed, err)
				}
				clear(secret)

				for index, authority := range fixture.binding.Authorities {
					payload := formalFinalizerHandoffTestPayload(
						t, fixture, ticket, authority.PeerName,
						formalFinalizerHandoffGLMFullKind, index+1)
					envelope, err := formalFinalizerHandoffSealCanonical(
						fixture.binding, ticket, authority.PeerName,
						formalFinalizerHandoffGLMFullKind, payload,
						fixture.private[authority.PeerName], fixture.public)
					if err != nil {
						t.Fatal(err)
					}
					if presentKind == "ingress-v1" {
						_, _, err = store.CommitIngress(envelope)
					} else {
						_, _, err = store.CommitOutbox(envelope)
					}
					if err != nil {
						t.Fatal(err)
					}
				}

				missingKind := "outbox-v1"
				if presentKind == "outbox-v1" {
					missingKind = "ingress-v1"
				}
				artifact := fixture.binding.ArtifactID
				missingShard := filepath.Join(store.dir, missingKind,
					artifact[:2], artifact[2:4])
				if _, err := os.Lstat(missingShard); !os.IsNotExist(err) {
					t.Fatalf("absent transport shard existed before cleanup: %v", err)
				}

				ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
				if err != nil {
					t.Fatal(err)
				}
				certificateSHA := formalFinalizerHandoffTestSHA(t.Name() + "/certificate")
				proof, err := formalFinalizerHandoffBuildCommitProof(
					fixture.binding, ticketSHA, certificateSHA,
					fixture.private[fixture.binding.Finalizer.PeerName], fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				guard := formalFinalizerHandoffTestPublicationGuard{
					wantArtifact:    fixture.binding.ArtifactID,
					wantCertificate: certificateSHA,
				}
				if _, _, err := store.AckAfterCommit(proof, guard); err != nil {
					t.Fatal(err)
				}
				removed, err := store.CleanupTransportAfterAck(proof)
				if err != nil || removed != 3 {
					t.Fatalf("asymmetric cleanup removed %d records: %v", removed, err)
				}
				if _, err := os.Lstat(missingShard); !os.IsNotExist(err) {
					t.Fatalf("cleanup created absent transport shard: %v", err)
				}
				if removed, err := store.CleanupTransportAfterAck(proof); err != nil || removed != 0 {
					t.Fatalf("asymmetric cleanup replay was not idempotent: %d / %v", removed, err)
				}
			})
		}
	}
}

func TestFormalFinalizerHandoffTransportKeyAEADWrongRootAndTamper(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalFinalizerHandoffTestFixtureForK(
				t, custodians, formalFinalizerHandoffFamilyGLM)
			root := filepath.Join(t.TempDir(), "handoff")
			store, err := newFormalFinalizerHandoffStoreForTest(
				root, fixture.binding, fixture.storageRoot, fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			_, secret, replayed, err := store.IssueTicketOnce(
				fixture.private["sitea"])
			if err != nil || replayed || len(secret) != 32 {
				t.Fatalf("encrypted key issue: replay=%v err=%v", replayed, err)
			}
			relative, err := store.relativePath(
				"transport-keys-v1", "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.dir, relative)
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(`"secret_key"`)) ||
				bytes.Contains(encoded, secret) ||
				bytes.Contains(encoded,
					[]byte(base64.StdEncoding.EncodeToString(secret))) {
				t.Fatal("owner record contained plaintext X25519 secret")
			}
			clear(secret)
			store.Close()

			wrongRoot := sha256.Sum256([]byte(t.Name() + "/wrong-owner-root"))
			wrongStore, err := newFormalFinalizerHandoffStoreForTest(
				root, fixture.binding, wrongRoot, fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			if _, wrongSecret, _, err := wrongStore.IssueTicketOnce(
				fixture.private["sitea"]); err == nil || len(wrongSecret) != 0 {
				clear(wrongSecret)
				t.Fatal("wrong owner root opened the encrypted X25519 secret")
			}
			wrongStore.Close()

			var record formalFinalizerHandoffTransportKeyRecord
			if err := json.Unmarshal(encoded, &record); err != nil ||
				len(record.Ciphertext) == 0 {
				t.Fatal("invalid encrypted key fixture")
			}
			record.Ciphertext[0] ^= 1
			tampered, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			tamperedStore, err := newFormalFinalizerHandoffStoreForTest(
				root, fixture.binding, fixture.storageRoot, fixture.public)
			if err != nil {
				t.Fatal(err)
			}
			defer tamperedStore.Close()
			if _, tamperedSecret, _, err := tamperedStore.IssueTicketOnce(
				fixture.private["sitea"]); err == nil || len(tamperedSecret) != 0 {
				clear(tamperedSecret)
				t.Fatal("tampered encrypted X25519 secret was accepted")
			}
		})
	}
}

func TestFormalFinalizerHandoffTransportKeyConcurrentCASK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalFinalizerHandoffTestFixtureForK(
				t, custodians, formalFinalizerHandoffFamilyGLM)
			root := filepath.Join(t.TempDir(), "handoff")
			const workers = 12
			stores := make([]*formalFinalizerHandoffStore, workers)
			for index := range stores {
				var err error
				stores[index], err = newFormalFinalizerHandoffStoreForTest(
					root, fixture.binding, fixture.storageRoot, fixture.public)
				if err != nil {
					t.Fatal(err)
				}
				defer stores[index].Close()
			}
			type result struct {
				ticket   formalFinalizerHandoffTicket
				secret   []byte
				replayed bool
				err      error
			}
			results := make(chan result, workers)
			var wait sync.WaitGroup
			wait.Add(workers)
			for _, store := range stores {
				go func(store *formalFinalizerHandoffStore) {
					defer wait.Done()
					ticket, secret, replayed, err := store.IssueTicketOnce(
						fixture.private["sitea"])
					results <- result{ticket, secret, replayed, err}
				}(store)
			}
			wait.Wait()
			close(results)
			created := 0
			var canonicalTicket formalFinalizerHandoffTicket
			var canonicalSecret []byte
			for observed := range results {
				if observed.err != nil || len(observed.secret) != 32 {
					t.Fatalf("concurrent encrypted key CAS: %v", observed.err)
				}
				if !observed.replayed {
					created++
				}
				if canonicalSecret == nil {
					canonicalTicket = observed.ticket
					canonicalSecret = append([]byte(nil), observed.secret...)
				} else if !reflect.DeepEqual(canonicalTicket, observed.ticket) ||
					!hmac.Equal(canonicalSecret, observed.secret) {
					t.Fatal("concurrent owner-root CAS returned divergent key material")
				}
				clear(observed.secret)
			}
			clear(canonicalSecret)
			if created != 1 {
				t.Fatalf("concurrent owner-root CAS created %d first records", created)
			}
		})
	}
}

func TestFormalFinalizerHandoffCrashBetweenKeyAndTicketResumesExactKey(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 3, formalFinalizerHandoffFamilyGLM)
	root := filepath.Join(t.TempDir(), "handoff")
	store, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.sealTransportKeyRecord(
		transport.PublicKey().Bytes(), transport.Bytes(),
		fixture.private["sitea"])
	if err != nil {
		t.Fatal(err)
	}
	stored, replayed, err := store.commitTransportKey(record)
	if err != nil || replayed || !reflect.DeepEqual(stored, record) {
		t.Fatalf("pre-ticket key CAS failed: replay=%v err=%v", replayed, err)
	}
	store.Close()

	restarted, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	ticket, secret, replayed, err := restarted.IssueTicketOnce(
		fixture.private["sitea"])
	if err != nil || !replayed ||
		!hmac.Equal(secret, transport.Bytes()) ||
		!hmac.Equal(ticket.RecipientTransportPublicKey,
			transport.PublicKey().Bytes()) {
		clear(secret)
		t.Fatalf("key-to-ticket crash recovery changed key: replay=%v err=%v",
			replayed, err)
	}
	clear(secret)
}

func TestFormalFinalizerHandoffConcurrentSemanticCAS(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 5, formalFinalizerHandoffFamilyGLM)
	ticket, err := formalFinalizerHandoffIssueTicket(
		fixture.binding, fixture.transport.PublicKey().Bytes(),
		fixture.private["sitea"], fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "handoff")
	store, err := newFormalFinalizerHandoffStoreForTest(
		root, fixture.binding, fixture.storageRoot, fixture.public)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.CommitTicket(ticket); err != nil {
		t.Fatal(err)
	}
	payload := formalFinalizerHandoffTestPayload(t, fixture, ticket,
		"sitea", formalFinalizerHandoffGLMOneDrawKind, 11)
	const workers = 24
	stores := make([]*formalFinalizerHandoffStore, workers)
	stores[0] = store
	for index := 1; index < workers; index++ {
		stores[index], err = newFormalFinalizerHandoffStoreForTest(
			root, fixture.binding, fixture.storageRoot, fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		defer stores[index].Close()
	}
	envelopes := make([]formalFinalizerHandoffEnvelope, workers)
	for index := range envelopes {
		envelopes[index], err = formalFinalizerHandoffSealCanonical(
			fixture.binding, ticket, "sitea",
			formalFinalizerHandoffGLMOneDrawKind, payload,
			fixture.private["sitea"], fixture.public)
		if err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		envelope formalFinalizerHandoffEnvelope
		replayed bool
		err      error
	}
	results := make(chan result, workers)
	for index := range envelopes {
		go func(worker *formalFinalizerHandoffStore,
			envelope formalFinalizerHandoffEnvelope) {
			stored, replayed, err := worker.CommitOutbox(envelope)
			results <- result{stored, replayed, err}
		}(stores[index], envelopes[index])
	}
	var canonical *formalFinalizerHandoffEnvelope
	created := 0
	for index := 0; index < workers; index++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.replayed {
			created++
		}
		if canonical == nil {
			value := result.envelope
			canonical = &value
		} else if !reflect.DeepEqual(*canonical, result.envelope) {
			t.Fatal("concurrent semantic CAS returned different ciphertext bytes")
		}
	}
	if created != 1 {
		t.Fatalf("concurrent CAS created %d first records", created)
	}
}

func TestFormalFinalizerHandoffFilesystemTamperFailsClosed(t *testing.T) {
	type prepared struct {
		store      *formalFinalizerHandoffStore
		ticketPath string
	}
	prepare := func(t *testing.T) prepared {
		t.Helper()
		fixture := formalFinalizerHandoffTestFixtureForK(
			t, 2, formalFinalizerHandoffFamilyGLM)
		store, err := newFormalFinalizerHandoffStoreForTest(
			filepath.Join(t.TempDir(), "handoff"), fixture.binding,
			fixture.storageRoot, fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := formalFinalizerHandoffIssueTicket(
			fixture.binding, fixture.transport.PublicKey().Bytes(),
			fixture.private["sitea"], fixture.public)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.CommitTicket(ticket); err != nil {
			t.Fatal(err)
		}
		relative, err := store.relativePath("tickets-v1", "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		return prepared{store: store, ticketPath: filepath.Join(store.dir, relative)}
	}

	t.Run("mode-0644", func(t *testing.T) {
		state := prepare(t)
		defer state.store.Close()
		if err := os.Chmod(state.ticketPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := state.store.loadTicket(); err == nil {
			t.Fatal("world-readable durable ticket was accepted")
		}
	})
	t.Run("hard-link", func(t *testing.T) {
		state := prepare(t)
		defer state.store.Close()
		if err := os.Link(state.ticketPath, state.ticketPath+".external-link"); err != nil {
			t.Fatal(err)
		}
		if _, err := state.store.loadTicket(); err == nil {
			t.Fatal("hard-linked durable ticket was accepted")
		}
	})
	t.Run("symbolic-link", func(t *testing.T) {
		state := prepare(t)
		defer state.store.Close()
		encoded, err := os.ReadFile(state.ticketPath)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "ticket.json")
		if err := os.WriteFile(target, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(state.ticketPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, state.ticketPath); err != nil {
			t.Fatal(err)
		}
		if _, err := state.store.loadTicket(); err == nil {
			t.Fatal("symbolic-linked durable ticket was accepted")
		}
	})
	t.Run("content", func(t *testing.T) {
		state := prepare(t)
		defer state.store.Close()
		encoded, err := os.ReadFile(state.ticketPath)
		if err != nil {
			t.Fatal(err)
		}
		encoded[len(encoded)-8] ^= 1
		if err := os.WriteFile(state.ticketPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := state.store.loadTicket(); err == nil {
			t.Fatal("tampered durable ticket was accepted")
		}
	})
	t.Run("directory-mode", func(t *testing.T) {
		state := prepare(t)
		defer state.store.Close()
		if err := os.Chmod(filepath.Join(state.store.dir, "tickets-v1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := state.store.loadTicket(); err == nil {
			t.Fatal("non-private durable directory was accepted")
		}
	})
	t.Run("root-symlink", func(t *testing.T) {
		fixture := formalFinalizerHandoffTestFixtureForK(
			t, 2, formalFinalizerHandoffFamilyGLM)
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newFormalFinalizerHandoffStoreForTest(
			link, fixture.binding, fixture.storageRoot, fixture.public); err == nil {
			t.Fatal("symbolic-linked durable root was accepted")
		}
	})
}

func TestFormalFinalizerHandoffProductionRootRejectsOpalFiles(t *testing.T) {
	fixture := formalFinalizerHandoffTestFixtureForK(
		t, 2, formalFinalizerHandoffFamilyGLM)
	for _, path := range []string{
		"/home/opal/formal-finalizer", "/srv/opal/files/formal-finalizer",
		"/tmp/formal-finalizer",
	} {
		if _, err := newFormalFinalizerHandoffStore(
			path, fixture.binding, fixture.storageRoot, fixture.public); err == nil {
			t.Fatalf("production store accepted non-Rock path %q", path)
		}
	}
	want := filepath.Join(formalFinalizerHandoffStateRoot,
		fixture.binding.Finalizer.PeerName)
	if err := formalFinalizerHandoffValidateProductionPath(want); err != nil {
		t.Fatalf("canonical Rock subroot was rejected: %v", err)
	}
	if err := formalFinalizerHandoffValidateResolvedProductionPath(
		want, want); err != nil {
		t.Fatalf("unredirected canonical Rock subroot was rejected: %v", err)
	}
	for _, resolved := range []string{
		filepath.Join(formalFinalizerHandoffStateRoot, "siteb"),
		"/srv/dsvert-synopsis/redirected-finalizer",
		"/tmp/redirected-finalizer",
	} {
		if err := formalFinalizerHandoffValidateResolvedProductionPath(
			want, resolved); err == nil {
			t.Fatalf("production store accepted redirected path %q", resolved)
		}
	}
	wrongFinalizer := filepath.Join(formalFinalizerHandoffStateRoot, "siteb")
	if _, err := newFormalFinalizerHandoffStore(
		wrongFinalizer, fixture.binding,
		fixture.storageRoot, fixture.public); err == nil {
		t.Fatal("production store accepted another finalizer subroot")
	}
}
