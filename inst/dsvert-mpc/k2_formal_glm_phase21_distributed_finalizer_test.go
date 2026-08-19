package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFormalGLMPhase21DistributedOneDrawCiphertextAndNonBlindVerificationK2K3K5(
	t *testing.T,
) {
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
			authorizations := formalGLMPhase21SamplerV2TestAuthorize(
				t, contract, fixture.formal.identities.public,
				fixture.formal.identities.private, fixture.seeds)
			outputs := formalGLMPhase21SamplerV2TestRunOneDraw(
				t, fixture, contract, authorizations)
			defer func() {
				for peer := range outputs {
					output := outputs[peer]
					output.clear()
				}
			}()

			binding, err := formalGLMPhase21OneDrawFinalizerBinding(
				fixture.stores[reference], outputs[reference])
			if err != nil || binding.ArtifactID != artifactID ||
				binding.Finalizer.PeerName != reference ||
				binding.Finalizer.Role != "garbler" {
				t.Fatalf("invalid one-draw finalizer binding: %#v / %v", binding, err)
			}
			for _, peer := range peers {
				peerBinding, err := formalGLMPhase21OneDrawFinalizerBinding(
					fixture.stores[peer], outputs[peer])
				if err != nil || !reflect.DeepEqual(peerBinding, binding) {
					t.Fatalf("authority %s derived another binding: %#v / %v",
						peer, peerBinding, err)
				}
			}

			ingressDir := filepath.Join(t.TempDir(), "typed-ingress")
			ingressRoot := sha256.Sum256([]byte(t.Name() + "/typed-ingress"))
			ingress, err := newFormalFinalizerHandoffStoreForTest(
				ingressDir, binding, ingressRoot, fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			ticket, secret, replayed, err := ingress.IssueTicketOnce(
				fixture.formal.identities.private[reference])
			if err != nil || replayed || len(secret) != 32 {
				clear(secret)
				t.Fatalf("ticket issue: replay=%v err=%v", replayed, err)
			}
			clear(secret)

			envelopes := make(map[string]formalFinalizerHandoffEnvelope, 2)
			for _, peer := range peers {
				output := outputs[peer]
				payload, err := formalGLMPhase21BuildOneDrawTransit(
					fixture.stores[peer], binding, ticket, output)
				if err != nil {
					t.Fatal(err)
				}
				for index, value := range payload.OneDraw.Shares {
					if value != output.Shares[index].String() {
						formalGLMPhase21ClearOneDrawTransit(&payload)
						t.Fatal("Ring128 share changed during decimal encoding")
					}
				}
				decoded, err := formalGLMPhase21DecodeOneDrawTransitShares(
					payload.OneDraw.Shares, output.Receipt.CoordinateCount)
				if err != nil {
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal(err)
				}
				largeExactShare := false
				for index := 0; index < output.Receipt.CoordinateCount; index++ {
					if decoded[index].Cmp(output.Shares[index]) != 0 {
						exactGCZeroBigInts(decoded)
						formalGLMPhase21ClearOneDrawTransit(&payload)
						t.Fatal("Ring128 share changed during exact decoding")
					}
					largeExactShare = largeExactShare || decoded[index].BitLen() > 53
				}
				exactGCZeroBigInts(decoded)
				if !largeExactShare {
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal("test did not exercise an exact share above 2^53")
				}

				outbox, err := newFormalFinalizerHandoffStoreForTest(
					filepath.Join(t.TempDir(), "outbox-"+output.Role), binding,
					sha256.Sum256([]byte(t.Name()+"/outbox/"+output.Role)),
					fixture.formal.identities.public)
				if err != nil {
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal(err)
				}
				if _, _, err := outbox.CommitTicket(ticket); err != nil {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal(err)
				}
				envelope, err := formalFinalizerHandoffSealGLMOneDraw(
					binding, ticket, payload,
					fixture.formal.identities.private[peer],
					fixture.formal.identities.public)
				if err != nil {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal(err)
				}
				encodedEnvelope, err := json.Marshal(envelope)
				if err != nil {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`"shares"`), []byte(`"receipt"`),
					[]byte(`"output_share_sha256"`),
				} {
					if bytes.Contains(encodedEnvelope, forbidden) {
						outbox.Close()
						formalGLMPhase21ClearOneDrawTransit(&payload)
						t.Fatalf("private one-draw field crossed outside ciphertext: %s",
							forbidden)
					}
				}
				stored, replayed, err := outbox.CommitOutbox(envelope)
				if err != nil || replayed || !reflect.DeepEqual(stored, envelope) {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatalf("first outbox CAS: replay=%v err=%v", replayed, err)
				}
				reencrypted, err := formalFinalizerHandoffSealGLMOneDraw(
					binding, ticket, payload,
					fixture.formal.identities.private[peer],
					fixture.formal.identities.public)
				if err != nil || reflect.DeepEqual(reencrypted, envelope) {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatalf("fresh seal was not randomized: %v", err)
				}
				replayedEnvelope, replayed, err := outbox.CommitOutbox(reencrypted)
				if err != nil || !replayed || !reflect.DeepEqual(replayedEnvelope, envelope) {
					outbox.Close()
					formalGLMPhase21ClearOneDrawTransit(&payload)
					t.Fatalf("outbox CAS did not replay first ciphertext: %v / %v",
						replayed, err)
				}
				outbox.Close()
				formalGLMPhase21ClearOneDrawTransit(&payload)
				envelopes[output.Role] = envelope
				if _, replayed, err := ingress.CommitIngress(envelope); err != nil || replayed {
					t.Fatalf("ingress %s: replay=%v err=%v", output.Role, replayed, err)
				}
			}

			ingress.Close()
			ingress, err = newFormalFinalizerHandoffStoreForTest(
				ingressDir, binding, ingressRoot, fixture.formal.identities.public)
			if err != nil {
				t.Fatal(err)
			}
			defer ingress.Close()
			imported := make(map[string]formalGLMPhase21OneDrawLocalOutput, 2)
			defer func() {
				for role := range imported {
					value := imported[role]
					value.clear()
				}
			}()
			for _, role := range []string{"garbler", "evaluator"} {
				opened, err := ingress.OpenIngressDurableCanonical(role, ticket)
				if err != nil {
					t.Fatal(err)
				}
				var payload formalGLMPhase21OneDrawTransitPayload
				if err := formalGLMPhase21DecodeOneDrawTransitCanonical(
					opened, &payload); err != nil {
					clear(opened)
					t.Fatal(err)
				}
				clear(opened)
				value, err := formalGLMPhase21ImportOneDrawTransit(
					fixture.stores[reference], fixture.capsule, fixture.request,
					fixture.backendSignatures, fixture.workerSignatures,
					binding, ticket, payload)
				formalGLMPhase21ClearOneDrawTransit(&payload)
				if err != nil {
					t.Fatal(err)
				}
				imported[role] = value
			}

			releaseStore, err := newJointDPBiomedicalGaussianOneDrawDurableReleaseStore(
				filepath.Join(t.TempDir(), "finalizer-release"), reference,
				fixture.runtime[reference].backend,
				fixture.formal.identities.private[reference])
			if err != nil {
				t.Fatal(err)
			}
			localRelease, err := formalGLMPhase21FinalizeOneDrawLocal(
				fixture.stores[reference], releaseStore,
				imported["garbler"], imported["evaluator"], nil)
			if err != nil {
				t.Fatal(err)
			}
			authority, err := jointDPBiomedicalGaussianOneDrawAuthorityFromEnvelopes(
				[]jointDPBiomedicalGaussianSignedWorkerEnvelope{
					outputs[reference].Admission.Envelope,
				}, outputs[reference].Admission.Trust)
			if err != nil {
				t.Fatal(err)
			}
			candidate := jointDPBiomedicalGaussianOneDrawCommonFromLocal(
				authority, localRelease.Receipt)
			for _, localPeer := range peers {
				local := outputs[localPeer]
				oppositeRole := "garbler"
				if local.Role == "garbler" {
					oppositeRole = "evaluator"
				}
				opposite := outputs[binding.Authorities[0].PeerName].Receipt
				if oppositeRole == "evaluator" {
					opposite = outputs[binding.Authorities[1].PeerName].Receipt
				}
				if err := formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
					fixture.stores[localPeer], local, opposite, candidate); err != nil {
					t.Fatalf("%s could not verify implied opposite share: %v",
						local.Role, err)
				}
			}

			tamperedCandidate := candidate
			tamperedCandidate.ClampedScaledValues = append(
				[]string(nil), candidate.ClampedScaledValues...)
			changed, err := jointDPBiomedicalGaussianParseCanonicalInt(
				tamperedCandidate.ClampedScaledValues[0], "test coordinate", false)
			if err != nil {
				t.Fatal(err)
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
			if err := formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
				fixture.stores[reference], outputs[reference],
				outputs[peers[1]].Receipt, tamperedCandidate); err == nil {
				t.Fatal("authority accepted a candidate not implied by signed shares")
			}
			tamperedLocal := formalGLMPhase21TestCopyOutput(outputs[reference])
			tamperedLocal.Shares[0].Xor(tamperedLocal.Shares[0], big.NewInt(1))
			if err := formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
				fixture.stores[reference], tamperedLocal,
				outputs[peers[1]].Receipt, candidate); err == nil {
				tamperedLocal.clear()
				t.Fatal("authority accepted a local share outside its signed digest")
			}
			tamperedLocal.clear()
			tamperedReceipt := outputs[peers[1]].Receipt
			tamperedReceipt.OutputShareSHA256 = formalFinalizerHandoffTestSHA(
				t.Name() + "/tampered-opposite")
			if err := formalGLMPhase21VerifyOneDrawCandidateAgainstLocal(
				fixture.stores[reference], outputs[reference],
				tamperedReceipt, candidate); err == nil {
				t.Fatal("authority accepted a tampered opposite signed receipt")
			}

			for _, invalid := range []string{"01", "+1", "1.0", "1e3", "-1"} {
				values := make([]string,
					outputs[reference].Receipt.CoordinateCount+1)
				for index := range values {
					values[index] = "0"
				}
				values[0] = invalid
				if decoded, err := formalGLMPhase21DecodeOneDrawTransitShares(
					values, outputs[reference].Receipt.CoordinateCount); err == nil {
					exactGCZeroBigInts(decoded)
					t.Fatalf("non-canonical Ring128 decimal %q was accepted", invalid)
				}
			}

			for _, envelope := range envelopes {
				encoded, err := json.Marshal(envelope)
				if err != nil || bytes.Contains(encoded, []byte(`"shares"`)) {
					t.Fatalf("durable ingress exposed a plaintext share field: %v", err)
				}
			}
			err = filepath.Walk(ingressDir,
				func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return err
					}
					encoded, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					if bytes.Contains(encoded, []byte(`"shares"`)) ||
						bytes.Contains(encoded, []byte(`"receipt"`)) {
						return fmt.Errorf("plaintext transit persisted at %s", path)
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
