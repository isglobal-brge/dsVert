package main

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type formalGLMPhase18FinalizerFixture struct {
	plan          formalGLMPhase15Plan
	ctx           formalGLMPhase19Context
	identities    formalGLMPhase15TestIdentities
	localKeys     map[string][32]byte
	recipientSK   map[string][]byte
	recipientPK   map[string][]byte
	frames        map[string][][]byte
	frameValues   map[string][]formalGLMPhase18IngressFrame
	localBySource [][]*big.Int
	consensus     [32]byte
}

func formalGLMPhase18TestPack(header formalGLMPhase18PrivateBlockHeader,
	coordinates []*big.Int, validity []byte, ringBits int) ([]byte, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	coordinateBytes, err := formalGLMPhase15EncodeRecords(coordinates, ringBits)
	if err != nil {
		return nil, err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(headerJSON)))
	result := append([]byte(nil), size[:]...)
	result = append(result, headerJSON...)
	result = append(result, coordinateBytes...)
	return append(result, validity...), nil
}

func formalGLMPhase18TestBuildFinalizerFixture(t testing.TB,
	custodians int) formalGLMPhase18FinalizerFixture {
	return formalGLMPhase18TestBuildFinalizerFixtureFamily(
		t, custodians, "binomial")
}

func formalGLMPhase18TestBuildFinalizerFixtureFamily(t testing.TB,
	custodians int, family string) formalGLMPhase18FinalizerFixture {
	t.Helper()
	plan := formalGLMPhase15TestPlan(t, family, custodians, 1, 1, 1, 2)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	pinset, err := formalGLMPhase16PinsetSHA256(identities.public)
	if err != nil {
		t.Fatal(err)
	}
	plan.Kernel.PinsetSHA256 = pinset
	ctx := formalGLMPhase19TestContext(t, plan)
	planDigest, err := formalGLMPhase15PlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture := formalGLMPhase18FinalizerFixture{
		plan: plan, ctx: ctx, identities: identities,
		localKeys:   make(map[string][32]byte, 2),
		recipientSK: make(map[string][]byte, 2),
		recipientPK: make(map[string][]byte, 2),
		frames:      make(map[string][][]byte, 2),
		frameValues: make(map[string][]formalGLMPhase18IngressFrame, 2),
		consensus:   sha256.Sum256([]byte("phase18/finalizer/private-consensus/" + t.Name())),
	}
	curve := ecdh.X25519()
	for _, recipient := range ctx.ComputePeers {
		key := sha256.Sum256([]byte("phase18/finalizer/local-key/" + t.Name() + "/" + recipient))
		fixture.localKeys[recipient] = key
		private, err := curve.GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixture.recipientSK[recipient] = append([]byte(nil), private.Bytes()...)
		fixture.recipientPK[recipient] = append([]byte(nil), private.PublicKey().Bytes()...)
	}
	complete := formalGLMPhase15TestBlock(
		plan, formalGLMPhase15TestInput(plan), 0)
	rng := rand.New(rand.NewSource(int64(181800 + custodians)))
	fixture.localBySource = make([][]*big.Int, custodians)
	for sourceIndex, source := range ctx.CustodianPeers {
		local := make([]*big.Int, len(complete))
		for i := range local {
			local[i] = new(big.Int)
			if plan.CoordinateOwners[i%ctx.CoordinatesPerRow] == source {
				local[i].Set(complete[i])
			}
		}
		fixture.localBySource[sourceIndex] = local
		leftCoordinates, rightCoordinates := exactGCTestSplit(rng, local, plan.RingBits)
		validityLeft := []byte{byte(rng.Intn(2))}
		validityRight := []byte{validityLeft[0] ^ 1}
		gateLeft := byte(rng.Intn(2))
		gateRight := gateLeft ^ 1
		var consensusLeft, consensusRight [32]byte
		for i := range consensusLeft {
			consensusLeft[i] = byte(rng.Intn(256))
			consensusRight[i] = consensusLeft[i] ^ fixture.consensus[i]
		}
		pairCommitment := sha256Hex([]byte("phase18/finalizer/pair/" + t.Name() + "/" + source))
		blockCommitment := sha256Hex([]byte("phase18/finalizer/block/" + t.Name() + "/" + source))
		for recipientSlot, recipient := range ctx.ComputePeers {
			coordinates, validity, gate, consensusShare :=
				leftCoordinates, validityLeft, gateLeft, consensusLeft
			role := "garbler"
			if recipientSlot == 1 {
				coordinates, validity, gate, consensusShare =
					rightCoordinates, validityRight, gateRight, consensusRight
				role = "evaluator"
			}
			ticket := sha256Hex([]byte("phase18/finalizer/ticket/" + t.Name() + "/" + recipient))
			header := formalGLMPhase18PrivateBlockHeader{
				AlignmentSharing: formalGLMPhase18AlignmentSharing,
				BlockIndex:       0, CapsuleID: ctx.CapsuleSHA256,
				CoordinateCount:      ctx.CoordinatesPerRow,
				CoordinateShareBytes: len(coordinates) * plan.ContainerBits / 8,
				GlobalSlotOffset:     0, OpeningsPerformed: 0,
				Phase19RequiredOperation:       formalGLMPhase18RequiredOperation,
				PlanSHA256:                     hex.EncodeToString(planDigest[:]),
				PreExecutionSHA256:             ctx.PreExecutionTokenSHA256,
				PrivateAlignmentConsensusShare: base64.RawURLEncoding.EncodeToString(consensusShare[:]),
				PrivateAlignmentGateShare:      int(gate), Purpose: formalGLMPhase18Purpose,
				RecipientName: recipient, RecipientRole: role,
				RecipientTicketSHA256: ticket, RecordBytes: plan.ContainerBits / 8,
				ReleaseToken: formalGLMPhase18NoRelease, RingBits: plan.RingBits,
				RunID: ctx.RunID, SlotsInBlock: plan.BlockCapacity,
				SourceName: source, SourceSlot: sourceIndex,
				TotalBlocks: plan.TotalBlocks, ValidityShareBytes: plan.BlockCapacity,
				ValiditySharing: formalGLMPhase18ValiditySharing,
				Version:         formalGLMPhase18PrivateBlockV2,
			}
			plaintext, err := formalGLMPhase18TestPack(
				header, coordinates, validity, plan.RingBits)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := transportEncryptBytes(
				plaintext, fixture.recipientPK[recipient])
			for i := range plaintext {
				plaintext[i] = 0
			}
			if err != nil {
				t.Fatal(err)
			}
			cipherDigest := sha256.Sum256(ciphertext)
			frame := formalGLMPhase18IngressFrame{
				CapsuleSHA256:             ctx.CapsuleSHA256,
				PlanSHA256:                hex.EncodeToString(planDigest[:]),
				PreExecutionSHA256:        ctx.PreExecutionTokenSHA256,
				GlobalMaterializationRoot: ctx.GlobalMaterializationRoot,
				RunID:                     ctx.RunID, Source: source, Recipient: recipient,
				RecipientTicketSHA256: ticket, PairCommitment: pairCommitment,
				BlockCommitment:  blockCommitment,
				CiphertextSHA256: hex.EncodeToString(cipherDigest[:]),
				EnvelopeSHA256: sha256Hex(append(
					[]byte("phase18/finalizer/envelope/"+source+"/"+recipient+"/"),
					cipherDigest[:]...)),
				SourceSlot: sourceIndex, RecipientSlot: recipientSlot,
				BlockIndex: 0, TotalBlocks: plan.TotalBlocks,
				GlobalSlotOffset: 0, SlotsInBlock: plan.BlockCapacity,
				CoordinateCount:   ctx.CoordinatesPerRow,
				CoordinateRecords: plan.BlockCapacity * ctx.CoordinatesPerRow,
				RingBits:          plan.RingBits, RecordBytes: plan.ContainerBits / 8,
				ValidityRecords: plan.BlockCapacity, Ciphertext: ciphertext,
			}
			encoded, err := formalGLMPhase18EncodeIngressFrame(
				frame, fixture.localKeys[recipient])
			if err != nil {
				t.Fatal(err)
			}
			fixture.frames[recipient] = append(fixture.frames[recipient], encoded)
			fixture.frameValues[recipient] = append(fixture.frameValues[recipient], frame)
		}
	}
	return fixture
}

func formalGLMPhase18TestMutatePrivateHeader(t testing.TB,
	fixture formalGLMPhase18FinalizerFixture, recipient string, sourceIndex int,
	mutate func(*formalGLMPhase18PrivateBlockHeader)) []byte {
	t.Helper()
	frame := fixture.frameValues[recipient][sourceIndex]
	plaintext, err := transportDecryptBytes(
		frame.Ciphertext, fixture.recipientSK[recipient])
	if err != nil {
		t.Fatal(err)
	}
	header, shares, err := formalGLMPhase18DecodePrivateHeader(plaintext, frame)
	if err != nil {
		t.Fatal(err)
	}
	shares = append([]byte(nil), shares...)
	mutate(&header)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(headerJSON)))
	updated := append([]byte(nil), size[:]...)
	updated = append(updated, headerJSON...)
	updated = append(updated, shares...)
	for i := range plaintext {
		plaintext[i] = 0
	}
	frame.Ciphertext, err = transportEncryptBytes(updated, fixture.recipientPK[recipient])
	for i := range updated {
		updated[i] = 0
	}
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(frame.Ciphertext)
	frame.CiphertextSHA256 = hex.EncodeToString(digest[:])
	frame.EnvelopeSHA256 = sha256Hex(append(
		[]byte("phase18/finalizer/mutated-envelope/"), digest[:]...))
	encoded, err := formalGLMPhase18EncodeIngressFrame(
		frame, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFormalGLMPhase18DurableFinalizerK2K3K5RestartAndPrivateXOR(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run("K"+string(rune('0'+custodians)), func(t *testing.T) {
			fixture := formalGLMPhase18TestBuildFinalizerFixture(t, custodians)
			loaded := make(map[string][]formalGLMPhase19VerifiedSourceBlock, 2)
			for _, recipient := range fixture.ctx.ComputePeers {
				dir := filepath.Join(t.TempDir(), recipient)
				store, err := newFormalGLMPhase18DurableFinalizer(
					dir, recipient, fixture.localKeys[recipient])
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.LoadCompleteBlock(
					fixture.plan, fixture.ctx, 0,
					fixture.recipientSK[recipient]); err == nil ||
					!strings.Contains(err.Error(), "incomplete") {
					t.Fatal("missing K source slots did not fail closed")
				}
				handles := make([]string, custodians)
				for source := 0; source < custodians; source++ {
					finalized, err := store.IngestAndFinalize(
						fixture.plan, fixture.ctx, fixture.frames[recipient][source],
						fixture.recipientSK[recipient])
					if err != nil {
						t.Fatal(err)
					}
					if finalized.Replayed || finalized.Handle == "" {
						t.Fatal("first durable source ingest was reported as a replay")
					}
					handles[source] = finalized.Handle
					if err := formalGLMPhase19VerifySourceBlock(
						fixture.plan, fixture.ctx, finalized.Block,
						fixture.localKeys[recipient]); err != nil {
						t.Fatal(err)
					}
				}
				retry, err := store.IngestAndFinalize(
					fixture.plan, fixture.ctx, fixture.frames[recipient][0],
					fixture.recipientSK[recipient])
				if err != nil || !retry.Replayed || retry.Handle != handles[0] {
					t.Fatalf("exact retry was not idempotent: replay=%v err=%v", retry.Replayed, err)
				}
				// A new process instance recovers exclusively from authenticated
				// ciphertext records; no plaintext checkpoint exists.
				restarted, err := newFormalGLMPhase18DurableFinalizer(
					dir, recipient, fixture.localKeys[recipient])
				if err != nil {
					t.Fatal(err)
				}
				loaded[recipient], err = restarted.LoadCompleteBlock(
					fixture.plan, fixture.ctx, 0, fixture.recipientSK[recipient])
				if err != nil || len(loaded[recipient]) != custodians {
					t.Fatalf("restart failed: blocks=%d err=%v", len(loaded[recipient]), err)
				}
				for _, handle := range handles {
					path, err := restarted.recordPath(handle, false)
					if err != nil {
						t.Fatal(err)
					}
					persisted, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range [][]byte{
						[]byte("private_alignment"), []byte("accepted_phase19"),
						[]byte(hex.EncodeToString(fixture.consensus[:])),
					} {
						if bytes.Contains(persisted, forbidden) {
							t.Fatal("durable ciphertext record contains private alignment material")
						}
					}
				}
			}
			left := loaded[fixture.ctx.ComputePeers[0]]
			right := loaded[fixture.ctx.ComputePeers[1]]
			modulus := exactGCModulus(fixture.plan.RingBits)
			for source := 0; source < custodians; source++ {
				if left[source].alignmentGateShare^right[source].alignmentGateShare != 1 {
					t.Fatal("recipient-local alignment shares do not reconstruct accepted inside GC")
				}
				var consensus [32]byte
				for i := range consensus {
					consensus[i] = left[source].consensusShare[i] ^ right[source].consensusShare[i]
				}
				if consensus != fixture.consensus ||
					left[source].consensusShare == fixture.consensus ||
					right[source].consensusShare == fixture.consensus {
					t.Fatal("a recipient observed, or the pair failed to reconstruct, the consensus digest")
				}
				for row := range left[source].validityShares {
					if left[source].validityShares[row]^right[source].validityShares[row] != 1 {
						t.Fatal("recipient-local validity shares do not reconstruct inside GC")
					}
				}
				for i := range left[source].coordinateShares {
					got := new(big.Int).Add(
						left[source].coordinateShares[i], right[source].coordinateShares[i])
					got.Mod(got, modulus)
					if got.Cmp(fixture.localBySource[source][i]) != 0 {
						t.Fatalf("source %d coordinate %d changed", source, i)
					}
				}
			}
		})
	}
}

func TestFormalGLMPhase18DurableFinalizerRejectsTamperReplayMisrouteAndLegacy(t *testing.T) {
	fixture := formalGLMPhase18TestBuildFinalizerFixture(t, 3)
	recipient := fixture.ctx.ComputePeers[0]
	store, err := newFormalGLMPhase18DurableFinalizer(
		t.TempDir(), recipient, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	original := fixture.frames[recipient][0]
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)/2] ^= 1
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, tampered,
		fixture.recipientSK[recipient]); err == nil ||
		!strings.Contains(err.Error(), "authentication") {
		t.Fatal("unauthenticated frame tamper was accepted")
	}
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, original[:len(original)-1],
		fixture.recipientSK[recipient]); err == nil {
		t.Fatal("truncated ingress frame was accepted")
	}
	if _, err := formalGLMPhase18DecodeIngressFrame(
		make([]byte, formalGLMPhase18MaxIngressFrame+1),
		fixture.localKeys[recipient]); err == nil {
		t.Fatal("oversize ingress frame was accepted")
	}

	frame, err := formalGLMPhase18DecodeIngressFrame(
		original, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	misrouted := frame
	misrouted.Recipient = fixture.ctx.ComputePeers[1]
	misrouted.RecipientSlot = 1
	misroutedEncoded, err := formalGLMPhase18EncodeIngressFrame(
		misrouted, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, misroutedEncoded,
		fixture.recipientSK[recipient]); err == nil {
		t.Fatal("recipient-misrouted frame was accepted")
	}
	wrongSlot := frame
	wrongSlot.SourceSlot = 2
	wrongSlotEncoded, err := formalGLMPhase18EncodeIngressFrame(
		wrongSlot, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, wrongSlotEncoded,
		fixture.recipientSK[recipient]); err == nil {
		t.Fatal("source-slot substitution was accepted")
	}

	otherContext := fixture.ctx
	otherContext.GlobalMaterializationRoot = sha256Hex([]byte("different materialization root"))
	if _, err := store.IngestAndFinalize(
		fixture.plan, otherContext, original,
		fixture.recipientSK[recipient]); err == nil {
		t.Fatal("cross-context replay was accepted")
	}
	roleSwap := formalGLMPhase18TestMutatePrivateHeader(
		t, fixture, recipient, 0, func(header *formalGLMPhase18PrivateBlockHeader) {
			header.RecipientRole = "evaluator"
		})
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, roleSwap,
		fixture.recipientSK[recipient]); err == nil {
		t.Fatal("private compute-role swap was accepted")
	}
	legacy := formalGLMPhase18TestMutatePrivateHeader(
		t, fixture, recipient, 0, func(header *formalGLMPhase18PrivateBlockHeader) {
			header.Version = "dsvert-formal-glm-phase18-private-block-v1"
		})
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, legacy,
		fixture.recipientSK[recipient]); err == nil ||
		!strings.Contains(err.Error(), "legacy") {
		t.Fatal("legacy full-alignment private format was accepted")
	}
	cipherTamper := frame
	cipherTamper.Ciphertext = append([]byte(nil), frame.Ciphertext...)
	cipherTamper.Ciphertext[len(cipherTamper.Ciphertext)-1] ^= 1
	digest := sha256.Sum256(cipherTamper.Ciphertext)
	cipherTamper.CiphertextSHA256 = hex.EncodeToString(digest[:])
	cipherTamper.EnvelopeSHA256 = sha256Hex([]byte("authenticated local ciphertext tamper"))
	cipherTamperEncoded, err := formalGLMPhase18EncodeIngressFrame(
		cipherTamper, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, cipherTamperEncoded,
		fixture.recipientSK[recipient]); err == nil ||
		!strings.Contains(err.Error(), "decryption") {
		t.Fatal("AEAD ciphertext tamper was accepted")
	}

	first, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, original, fixture.recipientSK[recipient])
	if err != nil {
		t.Fatal(err)
	}
	conflict := frame
	conflict.EnvelopeSHA256 = sha256Hex([]byte("conflicting authenticated retry"))
	conflictEncoded, err := formalGLMPhase18EncodeIngressFrame(
		conflict, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestAndFinalize(
		fixture.plan, fixture.ctx, conflictEncoded,
		fixture.recipientSK[recipient]); err == nil ||
		!strings.Contains(err.Error(), "conflicting") {
		t.Fatal("conflicting authenticated duplicate was accepted")
	}

	// Simulate an interrupted pre-link write. Restart removes only its own
	// owner-private temporary file and retains the committed ciphertext slot.
	path, err := store.recordPath(first.Handle, false)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(filepath.Dir(path), ".phase18-finalizer-crash")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-formalGLMPhase18TempGrace - time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(filepath.Dir(path), ".phase18-finalizer-active")
	if err := os.WriteFile(active, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedCrash := filepath.Join(filepath.Dir(path), ".phase18-finalizer-linked-crash")
	if err := os.Link(path, linkedCrash); err != nil {
		t.Fatal(err)
	}
	restarted, err := newFormalGLMPhase18DurableFinalizer(
		store.dir, recipient, fixture.localKeys[recipient])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("stale crash file survived finalizer restart")
	}
	if _, err := os.Lstat(active); err != nil {
		t.Fatal("an active finalizer temporary file was reaped")
	}
	if _, err := os.Lstat(linkedCrash); !os.IsNotExist(err) {
		t.Fatal("a committed hard-link crash temporary survived restart")
	}
	if _, err := restarted.IngestAndFinalize(
		fixture.plan, fixture.ctx, original,
		fixture.recipientSK[recipient]); err != nil {
		t.Fatalf("committed record did not survive restart: %v", err)
	}
}

func TestFormalGLMPhase18CoordinateDecoderRejectsHighPaddingAndWrongShape(t *testing.T) {
	width := exactGCRecordBytes(129)
	canonical := make([]byte, width)
	canonical[16] = 1 // Ring129's highest valid bit.
	if _, err := formalGLMPhase18DecodeCoordinateShares(
		canonical, 1, 129, width); err != nil {
		t.Fatal(err)
	}
	outside := append([]byte(nil), canonical...)
	outside[16] = 2 // First bit above Ring129.
	if _, err := formalGLMPhase18DecodeCoordinateShares(
		outside, 1, 129, width); err == nil ||
		!strings.Contains(err.Error(), "high container padding") {
		t.Fatal("non-zero high container padding was accepted")
	}
	if _, err := formalGLMPhase18DecodeCoordinateShares(
		canonical[:len(canonical)-1], 1, 129, width); err == nil {
		t.Fatal("truncated coordinate record was accepted")
	}
}

func TestFormalGLMPhase18DurableFinalizerCrossInstanceExactRetry(t *testing.T) {
	fixture := formalGLMPhase18TestBuildFinalizerFixture(t, 2)
	recipient := fixture.ctx.ComputePeers[0]
	dir := t.TempDir()
	stores := make([]*formalGLMPhase18DurableFinalizer, 2)
	for i := range stores {
		var err error
		stores[i], err = newFormalGLMPhase18DurableFinalizer(
			dir, recipient, fixture.localKeys[recipient])
		if err != nil {
			t.Fatal(err)
		}
	}
	type outcome struct {
		result formalGLMPhase18FinalizedSource
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, len(stores))
	for _, store := range stores {
		go func(store *formalGLMPhase18DurableFinalizer) {
			<-start
			result, err := store.IngestAndFinalize(
				fixture.plan, fixture.ctx, fixture.frames[recipient][0],
				fixture.recipientSK[recipient])
			results <- outcome{result: result, err: err}
		}(store)
	}
	close(start)
	replays := 0
	handle := ""
	for range stores {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.result.Replayed {
			replays++
		}
		if handle == "" {
			handle = got.result.Handle
		} else if got.result.Handle != handle {
			t.Fatal("cross-instance exact retry produced different slots")
		}
	}
	if replays != 1 {
		t.Fatalf("cross-instance exact retry reported %d replays, want 1", replays)
	}
}

func TestFormalGLMPhase18IngressFrameMatchesRGoldenVector(t *testing.T) {
	ciphertext := make([]byte, 240)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	cipherDigest := sha256.Sum256(ciphertext)
	frame := formalGLMPhase18IngressFrame{
		CapsuleSHA256:             strings.Repeat("a", 64),
		PlanSHA256:                strings.Repeat("b", 64),
		PreExecutionSHA256:        strings.Repeat("c", 64),
		GlobalMaterializationRoot: strings.Repeat("d", 64),
		RunID:                     "phase18-golden-run",
		Source:                    "peer-a",
		Recipient:                 "peer-b",
		RecipientTicketSHA256:     strings.Repeat("e", 64),
		PairCommitment:            strings.Repeat("f", 64),
		BlockCommitment:           strings.Repeat("0", 64),
		CiphertextSHA256:          hex.EncodeToString(cipherDigest[:]),
		EnvelopeSHA256:            strings.Repeat("1", 64),
		SourceSlot:                2,
		RecipientSlot:             1,
		BlockIndex:                1,
		TotalBlocks:               3,
		GlobalSlotOffset:          8,
		SlotsInBlock:              2,
		CoordinateCount:           4,
		CoordinateRecords:         8,
		RingBits:                  128,
		RecordBytes:               16,
		ValidityRecords:           2,
		Ciphertext:                ciphertext,
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	encoded, err := formalGLMPhase18EncodeIngressFrame(frame, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 1026 {
		t.Fatalf("golden frame length = %d, want 1026", len(encoded))
	}
	digest := sha256.Sum256(encoded)
	if got, want := hex.EncodeToString(digest[:]),
		"0fc813f230010c3163f5ad5132794037c233b0990bf35c7110858d7ff268cb5b"; got != want {
		t.Fatalf("R/Go Phase-1.8 framing drift: got %s want %s", got, want)
	}
	decoded, err := formalGLMPhase18DecodeIngressFrame(encoded, key)
	if err != nil || !bytes.Equal(decoded.Ciphertext, ciphertext) {
		t.Fatalf("golden frame did not round-trip: %v", err)
	}
}

func TestFormalGLMPhase18PrivatePlaintextMatchesRGoldenVector(t *testing.T) {
	consensus := make([]byte, 32)
	for i := range consensus {
		consensus[i] = byte(i)
	}
	header := formalGLMPhase18PrivateBlockHeader{
		AlignmentSharing:               formalGLMPhase18AlignmentSharing,
		BlockIndex:                     1,
		CapsuleID:                      strings.Repeat("a", 64),
		CoordinateCount:                4,
		CoordinateShareBytes:           128,
		GlobalSlotOffset:               8,
		OpeningsPerformed:              0,
		Phase19RequiredOperation:       formalGLMPhase18RequiredOperation,
		PlanSHA256:                     strings.Repeat("b", 64),
		PreExecutionSHA256:             strings.Repeat("c", 64),
		PrivateAlignmentConsensusShare: base64.RawURLEncoding.EncodeToString(consensus),
		PrivateAlignmentGateShare:      1,
		Purpose:                        formalGLMPhase18Purpose,
		RecipientName:                  "peer-b",
		RecipientRole:                  "evaluator",
		RecipientTicketSHA256:          strings.Repeat("d", 64),
		RecordBytes:                    16,
		ReleaseToken:                   formalGLMPhase18NoRelease,
		RingBits:                       128,
		RunID:                          "phase18-private-golden",
		SlotsInBlock:                   2,
		SourceName:                     "peer-a",
		SourceSlot:                     2,
		TotalBlocks:                    3,
		ValidityShareBytes:             2,
		ValiditySharing:                formalGLMPhase18ValiditySharing,
		Version:                        formalGLMPhase18PrivateBlockV2,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	share := make([]byte, 130)
	for i := range share {
		share[i] = byte(i)
	}
	packed := make([]byte, 4, 4+len(headerJSON)+len(share))
	binary.BigEndian.PutUint32(packed, uint32(len(headerJSON)))
	packed = append(packed, headerJSON...)
	packed = append(packed, share...)
	if len(packed) != 1391 {
		t.Fatalf("private golden length = %d, want 1391", len(packed))
	}
	digest := sha256.Sum256(packed)
	if got, want := hex.EncodeToString(digest[:]),
		"a3bcfcfda23017b96785bef73660f8206bf97705106279e7b4392a43fc4182af"; got != want {
		t.Fatalf("R/Go Phase-1.8 private plaintext drift: got %s want %s", got, want)
	}
	decoded, decodedShare, err := formalGLMPhase18DecodePrivateHeader(
		packed, formalGLMPhase18IngressFrame{
			CoordinateRecords: 8, RecordBytes: 16, ValidityRecords: 2,
		})
	if err != nil || decoded != header || !bytes.Equal(decodedShare, share) {
		t.Fatalf("R private plaintext golden did not decode canonically: %v", err)
	}
}
