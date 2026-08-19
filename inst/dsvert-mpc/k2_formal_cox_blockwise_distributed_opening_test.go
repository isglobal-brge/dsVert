package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func formalCoxBlockwiseDistributedTestHeaders(
	t testing.TB, fixture formalCoxBlockwiseOpeningTestFixture,
) [2]formalCoxBlockwiseOpeningHandoffHeader {
	t.Helper()
	fixture.submitAll(t)
	var headers [2]formalCoxBlockwiseOpeningHandoffHeader
	for index, peer := range fixture.plan.Policy.ComputePeers {
		header, err := fixture.store.loadPrivateHandoff(peer)
		if err != nil {
			t.Fatal(err)
		}
		headers[index] = header
	}
	return headers
}

func TestFormalCoxBlockwiseTypedFinalizerHandoffK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := newFormalCoxBlockwiseOpeningTestFixture(
				t, custodians, "typed-finalizer-handoff")
			defer fixture.store.Close()
			headers := formalCoxBlockwiseDistributedTestHeaders(t, fixture)
			binding, err := formalCoxBlockwiseOpeningFinalizerBinding(
				fixture.store, headers)
			if err != nil || binding.Finalizer != binding.Authorities[0] ||
				binding.Finalizer.Role != "garbler" ||
				binding.ArtifactID != fixture.store.artifactID {
				t.Fatalf("binding: %#v / %v", binding, err)
			}
			transport, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			finalizer := fixture.plan.Policy.ComputePeers[0]
			ticket, err := formalFinalizerHandoffIssueTicket(
				binding, transport.PublicKey().Bytes(), fixture.private[finalizer],
				fixture.pins)
			if err != nil {
				t.Fatal(err)
			}
			for _, authority := range binding.Authorities {
				payload, err := formalCoxBlockwiseBuildOpeningTransit(
					fixture.store, binding, ticket, headers, authority.PeerName)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(encoded, &fields); err != nil ||
					len(fields) != 10 || fields["handoff"] == nil ||
					fields["production_ready"] != nil ||
					fields["family"] != nil {
					t.Fatalf("Cox transit schema escaped its closed shape: %s / %v",
						encoded, err)
				}
				envelope, err := formalFinalizerHandoffSealCox(
					binding, ticket, payload, fixture.private[authority.PeerName],
					fixture.pins)
				if err != nil || envelope.ProductionReady ||
					envelope.PayloadKind != formalFinalizerHandoffCoxOpeningKind ||
					envelope.FinalPairRootSHA256 != binding.FinalPairRootSHA256 {
					t.Fatalf("seal %s: %#v / %v", authority.Role, envelope, err)
				}
				envelopeJSON, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range [][]byte{
					[]byte(`coefficient_shares`), []byte(`validity_share`),
					[]byte(`private_key`), []byte(`storage_key`),
				} {
					if bytes.Contains(bytes.ToLower(envelopeJSON), forbidden) {
						t.Fatalf("transport envelope exposed private field %q", forbidden)
					}
				}
				opened, err := formalFinalizerHandoffOpenCox(
					binding, ticket, envelope, transport.Bytes(), fixture.pins)
				if err != nil || !reflect.DeepEqual(opened, payload) {
					t.Fatalf("open %s: %#v / %v", authority.Role, opened, err)
				}
				formalCoxBlockwiseClearOpeningTransit(&opened)

				wrongRecipient, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalFinalizerHandoffOpenCox(
					binding, ticket, envelope, wrongRecipient.Bytes(), fixture.pins); err == nil {
					t.Fatal("wrong finalizer transport key opened a Cox handoff")
				}
				tampered := payload
				tampered.Handoff.CoefficientShares = append(
					[]string(nil), payload.Handoff.CoefficientShares...)
				tampered.Handoff.CoefficientShares[0] = "0"
				if _, err := formalFinalizerHandoffSealCox(binding, ticket, tampered,
					fixture.private[authority.PeerName], fixture.pins); err == nil {
					t.Fatal("changed local share bypassed its signed digest")
				}
				tampered = payload
				tampered.ProductionReady = true
				if _, err := formalFinalizerHandoffSealCox(binding, ticket, tampered,
					fixture.private[authority.PeerName], fixture.pins); err == nil {
					t.Fatal("ProductionReady Cox transit was accepted")
				}
				tampered = payload
				tampered.FinalPairRootSHA256 = formalFinalizerHandoffTestSHA(
					t.Name() + "/alternate-pair")
				if _, err := formalFinalizerHandoffSealCox(binding, ticket, tampered,
					fixture.private[authority.PeerName], fixture.pins); err == nil {
					t.Fatal("relinked pair root was accepted")
				}
				formalCoxBlockwiseClearOpeningTransit(&payload)
			}
		})
	}
}
