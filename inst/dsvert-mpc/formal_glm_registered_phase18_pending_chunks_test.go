package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFormalGLMRegisteredPhase18PendingPairChunksK2K5RestartReplay(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase18SourceOutboxTestBuild(t, custodians)
			sourceRoot := formalGLMRegisteredPhase18SourceOutboxTestRoot(t, "chunk-source")
			outbox := formalGLMRegisteredPhase18SourceOutboxTestNew(t, sourceRoot, fixture)
			_, pairJSON, _ := formalGLMRegisteredPhase18SourceOutboxTestCommit(t, outbox, fixture)
			defer clear(pairJSON)

			recipient := fixture.provenance.source.plan.DesignatedComputePeers[0]
			recipientRoot := formalGLMRegisteredPhase18PendingPairTestRoot(t, "chunk-recipient")
			stores := formalGLMRegisteredPhase18PendingPairTestOpen(
				t, recipientRoot, fixture.provenance, recipient)
			defer stores.Close()
			firstReceipt, firstChunk, _, err := outbox.ReadBlockChunk(
				fixture.authorization, fixture.tickets, fixture.blockIndex, 0)
			if err != nil {
				t.Fatal(err)
			}
			badReceipt := firstReceipt
			badReceipt.ChunkBytes--
			if _, err := stores.pending.CommitChunk(badReceipt, firstChunk); err == nil {
				clear(firstChunk)
				t.Fatal("accepted a malformed bounded chunk before durable import")
			}
			clear(firstChunk)

			var final formalGLMRegisteredPhase18PendingPairChunkReceiptV1
			for offset := int64(0); ; {
				sourceReceipt, chunk, complete, err := outbox.ReadBlockChunk(
					fixture.authorization, fixture.tickets, fixture.blockIndex, offset)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := stores.pending.CommitChunk(sourceReceipt, chunk)
				clear(chunk)
				if err != nil || receipt.AcceptedThrough <= offset ||
					receipt.ProductionReady {
					t.Fatalf("chunk import offset=%d receipt=%+v err=%v", offset, receipt, err)
				}
				final = receipt
				if complete {
					break
				}
				offset = receipt.AcceptedThrough
			}
			if !final.Complete || final.PendingReceipt == nil ||
				final.PendingReceipt.Recipient != recipient ||
				final.PendingReceipt.PairSHA256 == "" {
				t.Fatalf("chunk transfer did not commit a pending pair: %+v", final)
			}
			outbox.Close()
			stores.Close()

			restartedOutbox := formalGLMRegisteredPhase18SourceOutboxTestNew(t, sourceRoot, fixture)
			defer restartedOutbox.Close()
			restartedStores := formalGLMRegisteredPhase18PendingPairTestOpen(
				t, recipientRoot, fixture.provenance, recipient)
			defer restartedStores.Close()
			sourceReceipt, chunk, _, err := restartedOutbox.ReadBlockChunk(
				fixture.authorization, fixture.tickets, fixture.blockIndex, 0)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := restartedStores.pending.CommitChunk(sourceReceipt, chunk)
			clear(chunk)
			if err != nil || !replayed.Replayed || !replayed.Complete ||
				!bytes.Equal([]byte(replayed.PendingReceipt.PairSHA256),
					[]byte(final.PendingReceipt.PairSHA256)) {
				t.Fatalf("chunk restart replay differs: %#v / %v", replayed, err)
			}
		})
	}
}
