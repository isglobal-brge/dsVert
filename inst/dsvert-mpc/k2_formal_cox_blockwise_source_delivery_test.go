package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormalCoxBlockwiseSourceDeliveryK2K3K5 exercises the production
// boundary between a Rock-local source producer and each recipient-local
// encrypted source store.  It intentionally stops before a public opening.
func TestFormalCoxBlockwiseSourceDeliveryK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			root := t.TempDir()
			for _, directory := range []string{"producer", "recipient", "worker"} {
				if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			sourceDirs := make(map[string]string, len(plan.Policy.CustodianPeers))
			sourceKeys := make(map[string][32]byte, len(plan.Policy.CustodianPeers))
			producers := make(map[string]*formalCoxBlockwiseSourceProducer,
				len(plan.Policy.CustodianPeers))
			storeDirs := make(map[string]string, len(plan.Policy.ComputePeers))
			storeKeys := make(map[string][32]byte, len(plan.Policy.ComputePeers))
			stores := make(map[string]*formalCoxBlockwiseSourceStore,
				len(plan.Policy.ComputePeers))
			for _, recipient := range plan.Policy.ComputePeers {
				storeDirs[recipient] = filepath.Join(root, "recipient", recipient)
				storeKeys[recipient] = sha256.Sum256([]byte(
					"formal-cox-source-delivery/store/" + recipient))
				store, err := newFormalCoxBlockwiseSourceStore(
					storeDirs[recipient], storeKeys[recipient], session, recipient,
					transportSK[recipient])
				if err != nil {
					t.Fatal(err)
				}
				stores[recipient] = store
			}
			defer func() {
				for _, store := range stores {
					_ = store.Close()
				}
				for _, producer := range producers {
					_ = producer.Close()
				}
			}()

			var firstDelivery []byte
			firstSource := plan.Policy.CustodianPeers[0]
			firstRecipient := plan.Policy.ComputePeers[0]
			for sourceIndex, source := range plan.Policy.CustodianPeers {
				sourceDirs[source] = filepath.Join(root, "producer", source)
				sourceKeys[source] = sha256.Sum256([]byte(
					"formal-cox-source-delivery/producer/" + source))
				producer, err := newFormalCoxBlockwiseSourceProducer(
					sourceDirs[source], sourceKeys[source], session, source, signing[source])
				if err != nil {
					t.Fatal(err)
				}
				producers[source] = producer
				binding, err := producer.BlockBinding(0)
				if err != nil {
					t.Fatal(err)
				}
				values, input := formalCoxBlockwiseSourceProducerTestRows(
					plan, 0, sourceIndex)
				result, err := producer.ProduceBlock(binding, bytes.NewReader(input))
				if err != nil || result.Replayed {
					t.Fatalf("produce %s: replay=%v err=%v", source, result.Replayed, err)
				}
				for recipientIndex, recipient := range plan.Policy.ComputePeers {
					delivery, err := producer.Delivery(0, recipient)
					if err != nil || delivery.ReceiptSHA256 != result.ReceiptSHA256 ||
						delivery.RecipientPeerName != recipient {
						t.Fatalf("delivery source=%s recipient=%s: %+v %v",
							source, recipient, delivery, err)
					}
					encoded, err := json.Marshal(delivery)
					if err != nil || !json.Valid(encoded) {
						t.Fatalf("encode delivery: %v", err)
					}
					for _, forbidden := range []string{
						"9007199254740993", "-9007199254740995", sourceDirs[source],
						"recipient_secret_key", "producer_key",
					} {
						if bytes.Contains(encoded, []byte(forbidden)) {
							t.Fatalf("delivery exposed %q", forbidden)
						}
					}
					if source == firstSource && recipientIndex == 0 {
						firstDelivery = append([]byte(nil), encoded...)
						tampered := delivery
						tampered.Envelope = append([]byte(nil), delivery.Envelope...)
						tampered.Envelope[len(tampered.Envelope)-1] ^= 1
						if _, err := tampered.Accept(stores[recipient]); err == nil {
							t.Fatal("tampered delivery reached the recipient store")
						}
						state, stateErr := stores[recipient].readState()
						if stateErr != nil || state.NextSlot != 0 {
							t.Fatalf("tampered delivery advanced recipient state: %+v %v",
								state, stateErr)
						}
						tampered = delivery
						tampered.ReceiptSHA256 = strings.Repeat("0", 64)
						if _, err := tampered.Accept(stores[recipient]); err == nil {
							t.Fatal("tampered receipt digest reached the recipient store")
						}
					}
					replayed, err := delivery.Accept(stores[recipient])
					if err != nil || replayed {
						t.Fatalf("accept source=%s recipient=%s: replay=%v err=%v",
							source, recipient, replayed, err)
					}
					replayed, err = delivery.Accept(stores[recipient])
					if err != nil || !replayed {
						t.Fatalf("replay source=%s recipient=%s: replay=%v err=%v",
							source, recipient, replayed, err)
					}
				}
				exactGCZeroBigInts(values)
			}

			crossRecipient, err := producers[firstSource].Delivery(0, firstRecipient)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := crossRecipient.Accept(stores[plan.Policy.ComputePeers[1]]); err == nil {
				t.Fatal("a ciphertext delivery crossed into the other recipient store")
			}
			if err := producers[firstSource].Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := newFormalCoxBlockwiseSourceProducer(
				sourceDirs[firstSource], sourceKeys[firstSource], session, firstSource,
				signing[firstSource])
			if err != nil {
				t.Fatal(err)
			}
			producers[firstSource] = restarted
			replayedDelivery, err := restarted.Delivery(0, firstRecipient)
			if err != nil {
				t.Fatal(err)
			}
			replayedJSON, err := json.Marshal(replayedDelivery)
			if err != nil || !bytes.Equal(replayedJSON, firstDelivery) {
				t.Fatalf("restart changed the recipient delivery: %v", err)
			}
			if replayed, err := replayedDelivery.Accept(stores[firstRecipient]); err != nil || !replayed {
				t.Fatalf("restart delivery did not replay exactly: replay=%v err=%v", replayed, err)
			}

			for _, store := range stores {
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			bridges := make([]*formalCoxBlockwiseSourceBridge, 0, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				bridge, err := newFormalCoxBlockwiseSourceBridge(
					storeDirs[recipient], storeKeys[recipient], session, recipient,
					transportSK[recipient], filepath.Join(root, "worker", recipient),
					sha256.Sum256([]byte("formal-cox-source-delivery/worker/"+recipient)),
					signing[recipient])
				if err != nil {
					for _, opened := range bridges {
						_ = opened.Close()
					}
					t.Fatal(err)
				}
				bridges = append(bridges, bridge)
			}
			defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
			step := formalCoxBlockwiseSourceTestStep(t, plan, formalCoxBlockwiseStepBlock, 0)
			roots := make([]string, len(bridges))
			for index, bridge := range bridges {
				roots[index], err = bridge.PublicInputRoot(step)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := formalCoxBlockwiseMatchPublicInputRoots(plan, step, roots); err != nil {
				t.Fatalf("recipient deliveries did not form one public source root: %v", err)
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceDeliveryJSONNeverSerializesProducerSecrets(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
	session, _, transportSK := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
	root := t.TempDir()
	source := plan.Policy.CustodianPeers[0]
	key := sha256.Sum256([]byte("formal-cox-source-delivery/json"))
	producer, err := newFormalCoxBlockwiseSourceProducer(
		filepath.Join(root, "producer"), key, session, source, signing[source])
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	binding, err := producer.BlockBinding(0)
	if err != nil {
		t.Fatal(err)
	}
	_, input := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 0)
	if _, err := producer.ProduceBlock(binding, bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	delivery, err := producer.Delivery(0, plan.Policy.ComputePeers[0])
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(delivery)
	if err != nil {
		t.Fatal(err)
	}
	private := signing[source].Seed()
	defer clear(private)
	for _, forbidden := range [][]byte{key[:], private, transportSK[plan.Policy.ComputePeers[0]]} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("delivery JSON serialized producer or recipient private material")
		}
	}
}
