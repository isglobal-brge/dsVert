package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFormalGLMPhase21ProductiveLifecycleRejectsFullBeforeEffects(
	t *testing.T,
) {
	for _, mode := range []string{
		formalGLMPhase21SamplerV2Full,
		"",
		"unknown",
	} {
		t.Run(mode, func(t *testing.T) {
			counts := map[string]int{
				"source": 0, "run_id": 0, "decrypt": 0, "sampler": 0,
				"ticket": 0,
			}
			_, _, err := formalGLMPhase21RunOrReplayProductiveOneDraw(
				[2]*formalGLMPhase21StickyReleaseStore{},
				formalGLMPhase21SamplerV2Contract{SamplerMode: mode},
				func() ([2]formalGLMPhase21StickyPublication, error) {
					for name := range counts {
						counts[name]++
					}
					return [2]formalGLMPhase21StickyPublication{}, nil
				})
			if err == nil || !strings.Contains(err.Error(),
				"one_draw_exact_gc_v2") {
				t.Fatalf("unsupported mode was not rejected explicitly: %v", err)
			}
			for name, count := range counts {
				if count != 0 {
					t.Fatalf("%s ran before mode rejection: %d", name, count)
				}
			}
		})
	}
}

func TestFormalGLMPhase21ProductiveLifecycleEntersOneDrawOnce(t *testing.T) {
	entered := 0
	err := formalGLMPhase21RunProductiveOneDrawOnly(
		formalGLMPhase21SamplerV2OneDraw, func() error {
			entered++
			return nil
		})
	if err != nil || entered != 1 {
		t.Fatalf("one-draw lifecycle entry: entered=%d err=%v", entered, err)
	}
}

func TestFormalGLMPhase21DistributedLifecycleK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMPhase21TestSetup(t, custodians, "binomial")
			defer fixture.close()
			peers := fixture.formal.ctx.ComputePeers
			reference := peers[0]
			runtime, _, err := formalGLMPhase21LoadAndAdmit(
				fixture.stores[reference], fixture.capsule, fixture.request,
				fixture.backendSignatures, fixture.workerSignatures)
			if err != nil {
				t.Fatal(err)
			}
			artifact, artifactID, err := formalGLMPhase21BuildCanonicalArtifact(
				runtime.Admission.Productive.Compiled.Binding,
				runtime.Source.Plan, fixture.formal.identities.public)
			runtime.clear()
			if err != nil {
				t.Fatal(err)
			}
			contract := formalGLMPhase21SamplerV2TestContractForArtifact(
				t, artifact, artifactID, formalGLMPhase21SamplerV2OneDraw,
				fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			samplerAuthorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			outputByPeer := formalGLMPhase21SamplerV2TestRunOneDraw(
				t, fixture, contract, samplerAuthorizations)
			defer func() {
				for peer := range outputByPeer {
					output := outputByPeer[peer]
					output.clear()
				}
			}()
			binding, err := formalGLMPhase21OneDrawFinalizerBinding(
				fixture.stores[reference], outputByPeer[reference])
			if err != nil {
				t.Fatal(err)
			}
			var outputs [2]formalGLMPhase21OneDrawLocalOutput
			var sources [2]*formalGLMPhase20HandoffStore
			for index, authority := range binding.Authorities {
				outputs[index] = outputByPeer[authority.PeerName]
				sources[index] = fixture.stores[authority.PeerName]
			}

			var sticky [2]*formalGLMPhase21StickyReleaseStore
			var stickyDirs [2]string
			var stickyRoots [2][32]byte
			for index, authority := range binding.Authorities {
				stickyDirs[index] = filepath.Join(
					t.TempDir(), "sticky-"+authority.Role)
				stickyRoots[index] = sha256.Sum256(
					[]byte(t.Name() + "/sticky/" + authority.Role))
				sticky[index], err = newFormalGLMPhase21StickyReleaseStore(
					stickyDirs[index], authority.PeerName, stickyRoots[index],
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				for _, store := range sticky {
					store.close()
				}
			}()
			if _, found, err := formalGLMPhase21DistributedReplayPreflight(
				sticky, artifactID); err != nil || found {
				t.Fatalf("fresh ArtifactID preflight: found=%v err=%v", found, err)
			}

			ingressDir := filepath.Join(t.TempDir(), "ingress")
			ingressRoot := sha256.Sum256([]byte(t.Name() + "/ingress"))
			ingress, err := newFormalFinalizerHandoffAuthorityStoreForTest(
				ingressDir, binding, binding.Finalizer, ingressRoot,
				fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { ingress.Close() }()
			ticket, secret, replayed, err := ingress.IssueTicketOnce(
				fixture.formal.identities.private[reference])
			if err != nil || replayed || len(secret) != 32 {
				clear(secret)
				t.Fatalf("ticket: replay=%v err=%v", replayed, err)
			}
			clear(secret)

			var outboxes [2]*formalFinalizerHandoffStore
			var outboxDirs [2]string
			var outboxRoots [2][32]byte
			var envelopes [2]formalFinalizerHandoffEnvelope
			for index, authority := range binding.Authorities {
				outboxDirs[index] = filepath.Join(
					t.TempDir(), "outbox-"+authority.Role)
				outboxRoots[index] = sha256.Sum256(
					[]byte(t.Name() + "/outbox/" + authority.Role))
				outboxes[index], err = newFormalFinalizerHandoffAuthorityStoreForTest(
					outboxDirs[index], binding, authority, outboxRoots[index],
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				crashBeforeSeal := errors.New("test crash after local spool")
				if _, _, err := formalGLMPhase21SealLocalOneDraw(
					sources[index], outboxes[index], contract, ticket,
					outputs[index],
					fixture.formal.identities.private[authority.PeerName],
					func(phase string) error {
						if phase == "after_local_spool_before_seal" {
							return crashBeforeSeal
						}
						return nil
					}); !errors.Is(err, crashBeforeSeal) {
					t.Fatalf("%s local spool crash hook: %v", authority.Role, err)
				}
				localPayload, err := formalGLMPhase21BuildOneDrawTransit(
					sources[index], binding, ticket, outputs[index])
				if err != nil {
					t.Fatal(err)
				}
				localCanonical, err := formalGLMPhase21MarshalOneDrawTransitCanonical(
					localPayload)
				formalGLMPhase21ClearOneDrawTransit(&localPayload)
				if err != nil {
					t.Fatal(err)
				}
				relative, err := formalGLMPhase21LocalSpoolRelativePath(
					outboxes[index], authority.Role, false)
				if err != nil {
					t.Fatal(err)
				}
				recordBytes, err := outboxes[index].read(relative)
				if err != nil {
					t.Fatal(err)
				}
				ownerRelative, err := formalGLMPhase21LocalSpoolOwnerRelativePath(
					outboxes[index], false)
				if err != nil {
					t.Fatal(err)
				}
				ownerBytes, err := outboxes[index].read(ownerRelative)
				if err != nil {
					t.Fatal(err)
				}
				ticketSHA, err := formalFinalizerHandoffTicketSHA256(ticket)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(recordBytes, localCanonical) ||
					bytes.Contains(recordBytes, []byte(base64.StdEncoding.EncodeToString(
						localCanonical))) ||
					bytes.Contains(recordBytes, outboxes[index].atRestKey[:]) ||
					bytes.Contains(recordBytes, []byte(base64.StdEncoding.EncodeToString(
						outboxes[index].atRestKey[:]))) ||
					bytes.Contains(recordBytes, []byte(`"shares"`)) ||
					bytes.Contains(recordBytes, []byte(`"secret_key"`)) ||
					bytes.Contains(recordBytes, []byte(`"ticket_sha256"`)) ||
					bytes.Contains(recordBytes, []byte(ticketSHA)) ||
					bytes.Contains(ownerBytes, []byte(`"ticket_sha256"`)) ||
					bytes.Contains(ownerBytes, []byte(ticketSHA)) {
					clear(localCanonical)
					clear(recordBytes)
					clear(ownerBytes)
					t.Fatalf("%s local spool leaked plaintext", authority.Role)
				}
				clear(localCanonical)
				clear(ownerBytes)
				info, err := outboxes[index].root.Lstat(relative)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("%s local spool mode: %v / %v",
						authority.Role, info, err)
				}
				var tamperedRecord formalGLMPhase21LocalSpoolRecord
				if err := json.Unmarshal(recordBytes, &tamperedRecord); err != nil ||
					len(tamperedRecord.Ciphertext) == 0 {
					t.Fatalf("%s local spool decode: %v", authority.Role, err)
				}
				tamperedRecord.Ciphertext[0] ^= 1
				tamperedBytes, err := json.Marshal(tamperedRecord)
				clear(tamperedRecord.Ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalGLMPhase21DecodeLocalSpool(
					outboxes[index], contract, tamperedBytes); err == nil {
					t.Fatalf("%s local spool accepted AEAD tamper", authority.Role)
				}
				clear(tamperedBytes)
				wrongRoot := sha256.Sum256(
					[]byte(t.Name() + "/wrong-spool-root/" + authority.Role))
				wrongStore, err := newFormalFinalizerHandoffAuthorityStoreForTest(
					filepath.Join(t.TempDir(), "wrong-spool-root"), binding,
					authority, wrongRoot, fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalGLMPhase21DecodeLocalSpool(
					wrongStore, contract, recordBytes); err == nil {
					wrongStore.Close()
					t.Fatalf("%s local spool opened under wrong root", authority.Role)
				}
				wrongStore.Close()
				clear(recordBytes)
				outboxes[index].Close()
				outboxes[index], err = newFormalFinalizerHandoffAuthorityStoreForTest(
					outboxDirs[index], binding, authority, outboxRoots[index],
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				outputs[index].clear()
				outputs[index], err = formalGLMPhase21LoadLocalOneDrawSpool(
					sources[index], outboxes[index], contract, ticket,
					fixture.capsule, fixture.request, fixture.backendSignatures,
					fixture.workerSignatures)
				if err != nil {
					t.Fatalf("%s local spool restart: %v", authority.Role, err)
				}
				crashAfterSeal := errors.New("test crash after outbox seal")
				if _, _, err := formalGLMPhase21SealLocalOneDraw(
					sources[index], outboxes[index], contract, ticket,
					outputs[index],
					fixture.formal.identities.private[authority.PeerName],
					func(phase string) error {
						if phase == "after_outbox_seal" {
							return crashAfterSeal
						}
						return nil
					}); !errors.Is(err, crashAfterSeal) {
					t.Fatalf("%s outbox crash hook: %v", authority.Role, err)
				}
				outboxes[index].Close()
				outboxes[index], err = newFormalFinalizerHandoffAuthorityStoreForTest(
					outboxDirs[index], binding, authority, outboxRoots[index],
					fixture.formal.identities.public)
				if err != nil {
					t.Fatal(err)
				}
				outputs[index].clear()
				outputs[index], err = formalGLMPhase21LoadLocalOneDrawSpool(
					sources[index], outboxes[index], contract, ticket,
					fixture.capsule, fixture.request, fixture.backendSignatures,
					fixture.workerSignatures)
				if err != nil {
					t.Fatalf("%s sealed spool restart: %v", authority.Role, err)
				}
				envelopes[index], replayed, err = formalGLMPhase21SealLocalOneDraw(
					sources[index], outboxes[index], contract, ticket,
					outputs[index],
					fixture.formal.identities.private[authority.PeerName], nil)
				if err != nil || !replayed {
					t.Fatalf("seal replay %s: replay=%v err=%v",
						authority.Role, replayed, err)
				}
				if index == 0 {
					if _, err := formalGLMPhase21PersistLocalOneDrawSpool(
						sources[1], outboxes[0], contract, outputs[1]); err == nil {
						t.Fatal("one authority store accepted both private shares")
					}
				}
			}
			defer func() {
				for _, store := range outboxes {
					store.Close()
				}
			}()

			reordered := [2]formalFinalizerHandoffEnvelope{
				envelopes[1], envelopes[0]}
			if _, _, err := formalGLMPhase21DistributedIngressPreflight(
				sticky, ingress, contract, ticket, reordered); err == nil {
				t.Fatal("ordered ingress accepted swapped authorities")
			}
			tamperedEnvelope := envelopes
			tamperedEnvelope[0].Ciphertext = append(
				[]byte(nil), envelopes[0].Ciphertext...)
			tamperedEnvelope[0].Ciphertext[0] ^= 1
			if _, _, err := formalGLMPhase21DistributedIngressPreflight(
				sticky, ingress, contract, ticket, tamperedEnvelope); err == nil {
				t.Fatal("ingress accepted tampered ciphertext")
			}
			swappedSticky := [2]*formalGLMPhase21StickyReleaseStore{
				sticky[1], sticky[0]}
			if _, _, err := formalGLMPhase21DistributedIngressPreflight(
				swappedSticky, ingress, contract, ticket, envelopes); err == nil {
				t.Fatal("ingress accepted swapped publication authorities")
			}
			if _, found, err := formalGLMPhase21DistributedIngressPreflight(
				sticky, ingress, contract, ticket, envelopes); err != nil || found {
				t.Fatalf("valid ingress: found=%v err=%v", found, err)
			}
			ingress.Close()
			ingress, err = newFormalFinalizerHandoffAuthorityStoreForTest(
				ingressDir, binding, binding.Finalizer, ingressRoot,
				fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}

			finalizerRelease, err :=
				newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
					filepath.Join(t.TempDir(), "finalizer-release"), reference,
					fixture.runtime[reference].backend,
					fixture.formal.identities.private[reference])
			if err != nil {
				t.Fatal(err)
			}
			for _, crashPhase := range []string{
				"after_public_preflight", "after_import_garbler",
				"after_import_evaluator", "after_candidate_durable",
			} {
				crash := errors.New("test crash at " + crashPhase)
				if _, _, _, err := formalGLMPhase21DistributedOpenAndPrepare(
					sticky, sources[0], finalizerRelease, ingress, contract,
					ticket, fixture.capsule, fixture.request,
					fixture.backendSignatures, fixture.workerSignatures,
					func(phase string) error {
						if phase == crashPhase {
							return crash
						}
						return nil
					}); !errors.Is(err, crash) {
					t.Fatalf("open crash window %s: %v", crashPhase, err)
				}
			}
			candidate, _, found, err :=
				formalGLMPhase21DistributedOpenAndPrepare(
					sticky, sources[0], finalizerRelease, ingress, contract,
					ticket, fixture.capsule, fixture.request,
					fixture.backendSignatures, fixture.workerSignatures, nil)
			if err != nil || found {
				t.Fatalf("open/prepare: found=%v err=%v", found, err)
			}

			tamperedCandidate := candidate
			tamperedCandidate.ClampedScaledValues = append(
				[]string(nil), candidate.ClampedScaledValues...)
			changed, ok := new(big.Int).SetString(
				tamperedCandidate.ClampedScaledValues[0], 10)
			if !ok {
				t.Fatal("invalid fixture candidate")
			}
			if changed.Sign() == 0 {
				changed.SetInt64(1)
			} else {
				changed.Sub(changed, big.NewInt(1))
			}
			tamperedCandidate.ClampedScaledValues[0] = changed.String()
			tamperedCandidate.VectorSHA256, err =
				jointDPBiomedicalGaussianOneDrawVectorSHA256(
					tamperedCandidate.ClampedScaledValues)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := formalGLMPhase21BuildVerifiedOneDrawLocalRelease(
				sources[0], outputs[0], outputs[1].Receipt, tamperedCandidate,
				fixture.formal.identities.private[outputs[0].Peer]); err == nil {
				t.Fatal("authority signed candidate not implied by opposite receipt")
			}

			var localReleases [2]jointDPBiomedicalGaussianOneDrawLocalRelease
			for index, output := range outputs {
				localReleases[index], err =
					formalGLMPhase21BuildVerifiedOneDrawLocalRelease(
						sources[index], output, outputs[1-index].Receipt,
						candidate,
						fixture.formal.identities.private[output.Peer])
				if err != nil {
					t.Fatalf("non-blind %s local release: %v", output.Role, err)
				}
			}
			release, baseCertificate, err :=
				formalGLMPhase21BuildDistributedOneDrawCertificate(
					sources[0], outputs[0], candidate, localReleases, contract)
			if err != nil {
				t.Fatal(err)
			}
			var authorizations [2]formalGLMPhase21DistributedAuthorization
			authorizations[0], replayed, err =
				formalGLMPhase21DistributedSignOnce(
					sources[0], outboxes[0], sticky[0], ticket, contract,
					outputs[0], outputs[1].Receipt, candidate, release,
					baseCertificate,
					fixture.formal.identities.private[outputs[0].Peer], nil, nil)
			if err != nil || replayed {
				t.Fatalf("garbler SignOnce: replay=%v err=%v", replayed, err)
			}
			if _, _, err := formalGLMPhase21DistributedSignOnce(
				sources[1], outboxes[1], sticky[1], ticket, contract,
				outputs[1], outputs[0].Receipt, candidate, release,
				baseCertificate,
				fixture.formal.identities.private[outputs[1].Peer], nil, nil); err == nil {
				t.Fatal("evaluator signed without ordered predecessor")
			}
			authorizations[1], replayed, err =
				formalGLMPhase21DistributedSignOnce(
					sources[1], outboxes[1], sticky[1], ticket, contract,
					outputs[1], outputs[0].Receipt, candidate, release,
					baseCertificate,
					fixture.formal.identities.private[outputs[1].Peer],
					[]formalFinalizerHandoffIntentAuthorization{
						authorizations[0].TransportAuthorization,
					}, []jointDPBiomedicalGaussianSignature{
						authorizations[0].StickyAuthorization,
					})
			if err != nil || replayed {
				t.Fatalf("evaluator SignOnce: replay=%v err=%v", replayed, err)
			}
			encodedAuthorization, err := json.Marshal(authorizations[0])
			if err != nil || !bytes.Equal(encodedAuthorization, []byte("{}")) {
				t.Fatalf("plaintext authorization gained JSON surface: %q / %v",
					encodedAuthorization, err)
			}
			if replayAuthorization, replayed, err :=
				formalGLMPhase21DistributedSignOnce(
					sources[0], outboxes[0], sticky[0], ticket, contract,
					outputs[0], outputs[1].Receipt, candidate, release,
					baseCertificate,
					fixture.formal.identities.private[outputs[0].Peer], nil, nil); err != nil || !replayed || !reflect.DeepEqual(
				replayAuthorization, authorizations[0]) {
				t.Fatalf("garbler SignOnce replay: replay=%v err=%v", replayed, err)
			}
			tamperedAuthorizations := authorizations
			tamperedAuthorizations[0].IntentSHA256 =
				formalFinalizerHandoffTestSHA(t.Name() + "/wrong-intent")
			if _, _, _, err := formalGLMPhase21DistributedPublishAndAck(
				sticky, ingress, ticket, baseCertificate, tamperedAuthorizations,
				fixture.formal.identities.private[reference], nil); err == nil {
				t.Fatal("publication accepted tampered remote authorization")
			}
			swappedAuthorizations := [2]formalGLMPhase21DistributedAuthorization{
				authorizations[1], authorizations[0]}
			if _, _, _, err := formalGLMPhase21DistributedPublishAndAck(
				sticky, ingress, ticket, baseCertificate, swappedAuthorizations,
				fixture.formal.identities.private[reference], nil); err == nil {
				t.Fatal("publication accepted swapped remote authorizations")
			}

			crash := errors.New("test crash after first publication")
			_, _, _, err = formalGLMPhase21DistributedPublishAndAck(
				sticky, ingress, ticket, baseCertificate, authorizations,
				fixture.formal.identities.private[reference],
				func(phase string) error {
					if phase == "after_sticky_commit_garbler" {
						return crash
					}
					return nil
				})
			if !errors.Is(err, crash) {
				t.Fatalf("publication crash hook: %v", err)
			}
			if _, _, err := formalGLMPhase21DistributedReplayPreflight(
				sticky, artifactID); err == nil {
				t.Fatal("partial dual publication did not fail closed")
			}
			publications, proof, replayed, err :=
				formalGLMPhase21DistributedPublishAndAck(
					sticky, ingress, ticket, baseCertificate, authorizations,
					fixture.formal.identities.private[reference], nil)
			if err != nil || replayed ||
				publications[0].CertificateSHA256 !=
					publications[1].CertificateSHA256 ||
				!bytes.Equal(publications[0].Certificate,
					publications[1].Certificate) {
				t.Fatalf("dual publication repair: replay=%v err=%v", replayed, err)
			}
			for index := range sticky {
				sticky[index].close()
				sticky[index], err = newFormalGLMPhase21StickyReleaseStore(
					stickyDirs[index], binding.Authorities[index].PeerName,
					stickyRoots[index], fixture.formal.identities.public)
				if err != nil {
					t.Fatalf("sticky restart %d: %v", index, err)
				}
			}
			if replayPublications, found, err :=
				formalGLMPhase21DistributedReplayPreflight(sticky, artifactID); err != nil || !found || !bytes.Equal(
				replayPublications[0].Certificate,
				publications[0].Certificate) {
				t.Fatalf("canonical replay: found=%v err=%v", found, err)
			}
			if _, _, err := formalGLMPhase21DistributedReplayPreflight(
				[2]*formalGLMPhase21StickyReleaseStore{sticky[1], sticky[0]},
				artifactID); err == nil {
				t.Fatal("public replay accepted swapped authority stores")
			}
			effects := map[string]int{
				"source": 0, "run_id": 0, "sampler": 0, "decrypt": 0,
				"ticket": 0,
			}
			replayOnly, replayed, err :=
				formalGLMPhase21RunOrReplayProductiveOneDraw(
					sticky, contract,
					func() ([2]formalGLMPhase21StickyPublication, error) {
						for name := range effects {
							effects[name]++
						}
						return [2]formalGLMPhase21StickyPublication{},
							errors.New("replay entered productive effects")
					})
			if err != nil || !replayed || !bytes.Equal(
				replayOnly[0].Certificate, publications[0].Certificate) {
				t.Fatalf("pre-source public replay: replay=%v err=%v", replayed, err)
			}
			for name, count := range effects {
				if count != 0 {
					t.Fatalf("canonical replay executed %s: %d", name, count)
				}
			}

			wrongProof := proof
			wrongProof.CertificateSHA256 = formalFinalizerHandoffTestSHA(
				t.Name() + "/wrong-certificate")
			if _, err := formalGLMPhase21DistributedCleanupAfterAck(
				sticky, sources, outboxes, ingress, outputs, wrongProof); err == nil {
				t.Fatal("cleanup accepted a proof for another certificate")
			}
			cleanup, err := formalGLMPhase21DistributedCleanupAfterAck(
				sticky, sources, outboxes, ingress, outputs, proof)
			if err != nil || cleanup.SourceBytesRemoved == 0 ||
				cleanup.LocalSpoolsRemoved != 2 ||
				cleanup.TransportRecordsRemoved != 5 {
				t.Fatalf("post-ACK cleanup: %#v / %v", cleanup, err)
			}
			cleanupReplay, err := formalGLMPhase21DistributedCleanupAfterAck(
				sticky, sources, outboxes, ingress, outputs, proof)
			if err != nil || cleanupReplay.SourceBytesRemoved != 0 ||
				cleanupReplay.LocalSpoolsRemoved != 0 ||
				cleanupReplay.TransportRecordsRemoved != 0 {
				t.Fatalf("cleanup replay: %#v / %v", cleanupReplay, err)
			}
			for index := range outboxes {
				if _, replayed, err := formalGLMPhase21SealLocalOneDraw(
					sources[index], outboxes[index], contract, ticket,
					outputs[index],
					fixture.formal.identities.private[outputs[index].Peer], nil); err == nil || !replayed {
					t.Fatalf("late %s retry recreated terminal transport",
						outputs[index].Role)
				} else {
					var terminal *formalFinalizerHandoffTerminalAckError
					if !errors.As(err, &terminal) ||
						terminal.Proof.CertificateSHA256 != proof.CertificateSHA256 {
						t.Fatalf("late %s retry lost terminal ACK: %v",
							outputs[index].Role, err)
					}
				}
				if _, secret, _, err := outboxes[index].IssueTicketOnce(
					fixture.formal.identities.private[reference]); err == nil ||
					len(secret) != 0 {
					clear(secret)
					t.Fatalf("post-cleanup %s outbox recreated transport key",
						outputs[index].Role)
				}
			}
			if _, secret, _, err := ingress.IssueTicketOnce(
				fixture.formal.identities.private[reference]); err == nil ||
				len(secret) != 0 {
				clear(secret)
				t.Fatal("post-cleanup ticket issue recreated transport key")
			}
			if _, found, err := formalGLMPhase21DistributedReplayPreflight(
				sticky, artifactID); err != nil || !found {
				t.Fatalf("cleanup removed public replay: found=%v err=%v", found, err)
			}
			for _, envelope := range envelopes {
				path, err := ingress.relativePath(
					"ingress-v1", envelope.SenderRole,
					envelope.FinalPairRootSHA256, false)
				if err == nil {
					if _, err := ingress.root.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("ingress ciphertext survived cleanup: %v", err)
					}
				}
			}
		})
	}
}
