package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type formalCoxBlockwiseSourceProducerErrorReader struct {
	payload []byte
	done    bool
}

func (reader *formalCoxBlockwiseSourceProducerErrorReader) Read(
	destination []byte,
) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	reader.done = true
	return copy(destination, reader.payload), fmt.Errorf("injected source stream failure")
}

func formalCoxBlockwiseSourceProducerTestRows(
	plan formalCoxBlockwisePlan, block, sourceIndex int,
) ([]*big.Int, []byte) {
	rows := formalCoxBlockwiseSourceRowsInBlock(plan, block)
	count := rows * plan.RowWidth
	values := make([]*big.Int, count)
	for index := range values {
		values[index] = new(big.Int)
	}
	if count > 0 {
		values[0].SetInt64(1)
	}
	if count > 1 {
		values[1].SetInt64(int64(block + sourceIndex + 1))
	}
	if count > 2 {
		values[2].SetString("9007199254740993", 10)
	}
	if count > 3 {
		values[3].SetString("-9007199254740995", 10)
	}
	var encoded bytes.Buffer
	for _, value := range values {
		_, _ = fmt.Fprintf(&encoded, "%s\n", value.String())
	}
	return values, encoded.Bytes()
}

func formalCoxBlockwiseSourceProducerTestResidues(
	values []*big.Int, paddedCount, ringBits int,
) []*big.Int {
	result := make([]*big.Int, paddedCount)
	modulus := exactGCModulus(ringBits)
	for index := range result {
		result[index] = new(big.Int)
		if index < len(values) {
			result[index].Mod(new(big.Int).Set(values[index]), modulus)
		}
	}
	return result
}

func formalCoxBlockwiseSourceProducerTestOpen(
	t testing.TB, producer *formalCoxBlockwiseSourceProducer,
	session *formalCoxBlockwiseSourceSession, transportSK map[string][]byte,
	block int,
) map[string][]*big.Int {
	t.Helper()
	opened := make(map[string][]*big.Int, 2)
	for index, recipient := range session.context.plan.Policy.ComputePeers {
		encoded, err := formalCoxBlockwiseReadPrivateFile(
			producer.outboxPath(block, index), 2, session.context.maximum)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := formalCoxBlockwiseSourceDecodeEnvelope(
			encoded, session.context.maximum)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := transportDecryptBytes(
			envelope.Ciphertext, transportSK[recipient])
		if err != nil {
			t.Fatal(err)
		}
		shares, validity, err := formalCoxBlockwiseSourceDecodePrivate(
			envelope.Header, plaintext)
		clear(plaintext)
		if err != nil || validity != nil {
			t.Fatalf("open producer outbox: validity=%v err=%v", validity, err)
		}
		opened[recipient] = shares
	}
	return opened
}

func TestFormalCoxBlockwiseSourceProducerK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, custodians)
			session, _, transportSK := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			if plan.TotalCapacity%plan.BlockCapacity == 0 {
				t.Fatal("producer fixture must exercise a padded final block")
			}
			source := plan.Policy.CustodianPeers[len(plan.Policy.CustodianPeers)-1]
			producerKey := sha256.Sum256([]byte(
				"formal-cox/source-producer/" + source))
			root := filepath.Join(t.TempDir(), "producer")
			producer, err := newFormalCoxBlockwiseSourceProducer(
				root, producerKey, session, source, signing[source])
			if err != nil {
				t.Fatal(err)
			}
			defer producer.Close()

			var previous string
			for block := 0; block < plan.TotalBlocks; block++ {
				binding, err := producer.BlockBinding(block)
				if err != nil {
					t.Fatal(err)
				}
				values, encoded := formalCoxBlockwiseSourceProducerTestRows(
					plan, block, custodians-1)
				result, err := producer.ProduceBlock(
					binding, bytes.NewReader(encoded))
				if err != nil || result.Replayed {
					t.Fatalf("produce block %d: replay=%v err=%v",
						block, result.Replayed, err)
				}
				if result.Receipt.PreviousReceiptSHA256 != previous ||
					result.Receipt.Binding != binding ||
					!formalCoxIsSHA256(result.Receipt.SourceInputCommitment) ||
					!formalCoxIsSHA256(result.Receipt.PairManifestSHA256) ||
					len(result.Receipt.Signature) != ed25519.SignatureSize {
					t.Fatal("producer receipt omitted its canonical public binding")
				}
				if err := formalCoxBlockwiseValidateSourceProductionReceipt(
					session, result.Receipt, signing[source].Public().(ed25519.PublicKey)); err != nil {
					t.Fatalf("validate producer receipt: %v", err)
				}
				previous = result.ReceiptSHA256

				opened := formalCoxBlockwiseSourceProducerTestOpen(
					t, producer, session, transportSK, block)
				left := opened[plan.Policy.ComputePeers[0]]
				right := opened[plan.Policy.ComputePeers[1]]
				want := formalCoxBlockwiseSourceProducerTestResidues(
					values, plan.BlockCapacity*plan.RowWidth, plan.RingBits)
				modulus := exactGCModulus(plan.RingBits)
				for index := range want {
					got := new(big.Int).Add(left[index], right[index])
					got.Mod(got, modulus)
					if got.Cmp(want[index]) != 0 {
						t.Fatalf("block %d coordinate %d changed: got %s want %s",
							block, index, got, want[index])
					}
				}
				rows := formalCoxBlockwiseSourceRowsInBlock(plan, block)
				for index := rows * plan.RowWidth; index < len(left); index++ {
					if left[index].Sign() != 0 || right[index].Sign() != 0 {
						t.Fatal("padded coordinates were split into non-zero shares")
					}
				}
				exactGCZeroBigInts(left)
				exactGCZeroBigInts(right)
				exactGCZeroBigInts(want)
				exactGCZeroBigInts(values)

				public, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{
					"ciphertext", "shares", "9007199254740993",
					"-9007199254740995", root,
				} {
					if bytes.Contains(public, []byte(forbidden)) {
						t.Fatalf("public producer result exposed %q", forbidden)
					}
				}
			}
			if producer.peakPrivateCoordinates > 2*plan.BlockCapacity*plan.RowWidth {
				t.Fatalf("producer retained %d coordinates for a %d-coordinate block",
					producer.peakPrivateCoordinates,
					plan.BlockCapacity*plan.RowWidth)
			}
			state, err := producer.readState()
			if err != nil || state.NextBlock != plan.TotalBlocks {
				t.Fatalf("producer did not commit every block: %+v %v", state, err)
			}
			for _, dir := range append([]string{producer.root, producer.metadataDir},
				producer.outboxDirs[:]...) {
				info, err := os.Lstat(dir)
				if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
					t.Fatalf("producer directory is not 0700: %s %+v %v", dir, info, err)
				}
			}
			walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil {
					return err
				}
				if info.Mode().IsRegular() && info.Mode().Perm() != 0o600 {
					return fmt.Errorf("producer file is not 0600: %s (%v)", path, info.Mode())
				}
				if info.Mode().IsRegular() {
					contents, readErr := os.ReadFile(path)
					if readErr != nil {
						return readErr
					}
					if bytes.Contains(contents, []byte("9007199254740993")) ||
						bytes.Contains(contents, []byte("-9007199254740995")) ||
						bytes.Contains(contents, []byte(`"shares"`)) {
						return fmt.Errorf("producer persisted raw source material in %s", path)
					}
				}
				return nil
			})
			if walkErr != nil {
				t.Fatal(walkErr)
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceProducerRejectsNonCanonicalDecimals(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
	session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
	source := plan.Policy.CustodianPeers[0]
	key := sha256.Sum256([]byte("formal-cox/source-producer/decimal-errors"))
	producer, err := newFormalCoxBlockwiseSourceProducer(
		filepath.Join(t.TempDir(), "producer"), key, session, source, signing[source])
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	binding, err := producer.BlockBinding(0)
	if err != nil {
		t.Fatal(err)
	}
	count := binding.InputCoordinateCount
	for name, token := range map[string]string{
		"leading_zero": "01", "negative_zero": "-0", "plus": "+1",
		"space": " 1", "fraction": "1.0", "ring128_overflow": "170141183460469231731687303715884105728",
	} {
		t.Run(name, func(t *testing.T) {
			lines := make([]string, count)
			for index := range lines {
				lines[index] = "0"
			}
			lines[0] = token
			if _, err := producer.ProduceBlock(
				binding, strings.NewReader(strings.Join(lines, "\n")+"\n")); err == nil {
				t.Fatal("malformed decimal source input was accepted")
			}
		})
	}
	_, valid := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 0)
	if _, err := producer.ProduceBlock(binding,
		&formalCoxBlockwiseSourceProducerErrorReader{payload: valid}); err == nil {
		t.Fatal("a source stream error delivered with its final bytes was ignored")
	}
}

func TestFormalCoxBlockwiseSourceProducerCrashRestartReplayAndCAS(t *testing.T) {
	for _, phase := range []string{
		"after-intent", "after-outbox-0", "after-outbox-1",
		"after-receipt", "after-state",
	} {
		t.Run(phase, func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
			session, _, _ := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			source := plan.Policy.CustodianPeers[1]
			key := sha256.Sum256([]byte("formal-cox/source-producer/crash/" + phase))
			root := filepath.Join(t.TempDir(), "producer")
			producer, err := newFormalCoxBlockwiseSourceProducer(
				root, key, session, source, signing[source])
			if err != nil {
				t.Fatal(err)
			}
			binding, err := producer.BlockBinding(0)
			if err != nil {
				t.Fatal(err)
			}
			_, encoded := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 1)
			injected := false
			producer.hook = func(got string) error {
				if got == phase && !injected {
					injected = true
					return fmt.Errorf("injected crash at %s", phase)
				}
				return nil
			}
			if _, err := producer.ProduceBlock(
				binding, bytes.NewReader(encoded)); err == nil || !injected {
				t.Fatal("injected producer crash was not observed")
			}
			if err := producer.Close(); err != nil {
				t.Fatal(err)
			}

			restarted, err := newFormalCoxBlockwiseSourceProducer(
				root, key, session, source, signing[source])
			if err != nil {
				t.Fatalf("restart at %s: %v", phase, err)
			}
			result, err := restarted.ProduceBlock(
				binding, bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("resume at %s: %v", phase, err)
			}
			replayed, err := restarted.ProduceBlock(
				binding, bytes.NewReader(encoded))
			if err != nil || !replayed.Replayed ||
				replayed.ReceiptSHA256 != result.ReceiptSHA256 {
				t.Fatalf("stable replay at %s: %+v %v", phase, replayed, err)
			}
			changed := append([]byte(nil), encoded...)
			changed[0] = '2'
			if _, err := restarted.ProduceBlock(
				binding, bytes.NewReader(changed)); err == nil {
				t.Fatal("conflicting source replay was accepted")
			}
			if err := restarted.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("partial_outbox_mix_is_bound_to_input", func(t *testing.T) {
		plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
		session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
		source := plan.Policy.CustodianPeers[0]
		key := sha256.Sum256([]byte("formal-cox/source-producer/partial-mix"))
		parent := t.TempDir()
		alternate, err := newFormalCoxBlockwiseSourceProducer(
			filepath.Join(parent, "alternate"), key, session, source, signing[source])
		if err != nil {
			t.Fatal(err)
		}
		binding, _ := alternate.BlockBinding(0)
		_, alternateRows := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 1)
		if _, err := alternate.ProduceBlock(
			binding, bytes.NewReader(alternateRows)); err != nil {
			t.Fatal(err)
		}
		alternateOutbox, err := os.ReadFile(alternate.outboxPath(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		alternateBinding, err := os.ReadFile(alternate.outboxBindingPath(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		if err := alternate.Close(); err != nil {
			t.Fatal(err)
		}

		targetRoot := filepath.Join(parent, "target")
		target, err := newFormalCoxBlockwiseSourceProducer(
			targetRoot, key, session, source, signing[source])
		if err != nil {
			t.Fatal(err)
		}
		_, targetRows := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 0)
		target.hook = func(phase string) error {
			if phase == "after-outbox-0" {
				return fmt.Errorf("injected partial source crash")
			}
			return nil
		}
		if _, err := target.ProduceBlock(
			binding, bytes.NewReader(targetRows)); err == nil {
			t.Fatal("partial source crash was not injected")
		}
		targetOutbox := target.outboxPath(0, 0)
		targetBinding := target.outboxBindingPath(0, 0)
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetOutbox, alternateOutbox, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(targetBinding, alternateBinding, 0o600); err != nil {
			t.Fatal(err)
		}
		restarted, err := newFormalCoxBlockwiseSourceProducer(
			targetRoot, key, session, source, signing[source])
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		if _, err := restarted.ProduceBlock(
			binding, bytes.NewReader(targetRows)); err == nil {
			t.Fatal("a partial ciphertext and binding from another plaintext were reused")
		}
	})

	t.Run("concurrent_CAS", func(t *testing.T) {
		plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
		session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
		source := plan.Policy.CustodianPeers[0]
		key := sha256.Sum256([]byte("formal-cox/source-producer/concurrent"))
		root := filepath.Join(t.TempDir(), "producer")
		producer, err := newFormalCoxBlockwiseSourceProducer(
			root, key, session, source, signing[source])
		if err != nil {
			t.Fatal(err)
		}
		if second, err := newFormalCoxBlockwiseSourceProducer(
			root, key, session, source, signing[source]); err == nil {
			_ = second.Close()
			t.Fatal("a second process owner acquired the producer root")
		}
		binding, _ := producer.BlockBinding(0)
		_, encoded := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 0)
		type result struct {
			value formalCoxBlockwiseSourceProductionResult
			err   error
		}
		results := make(chan result, 2)
		var wait sync.WaitGroup
		for index := 0; index < 2; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				value, err := producer.ProduceBlock(
					binding, bytes.NewReader(encoded))
				results <- result{value: value, err: err}
			}()
		}
		wait.Wait()
		close(results)
		fresh, replay := 0, 0
		var digest string
		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if digest != "" && digest != result.value.ReceiptSHA256 {
				t.Fatal("concurrent producer calls returned different receipts")
			}
			digest = result.value.ReceiptSHA256
			if result.value.Replayed {
				replay++
			} else {
				fresh++
			}
		}
		if fresh != 1 || replay != 1 {
			t.Fatalf("concurrent CAS split fresh=%d replay=%d", fresh, replay)
		}
		_ = producer.Close()
	})
}

func TestFormalCoxBlockwiseSourceProducerBindingAndSessionTamper(t *testing.T) {
	plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
	session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
	source := plan.Policy.CustodianPeers[2]
	key := sha256.Sum256([]byte("formal-cox/source-producer/binding-tamper"))
	producer, err := newFormalCoxBlockwiseSourceProducer(
		filepath.Join(t.TempDir(), "producer"), key, session, source, signing[source])
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := producer.BlockBinding(0)
	_, encoded := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 2)
	mutations := map[string]func(*formalCoxBlockwiseSourceProductionBinding){
		"artifact": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.ArtifactID = strings.Repeat("0", 64)
		},
		"snapshot": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.SnapshotSHA256 = strings.Repeat("0", 64)
		},
		"pinset": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.PinsetSHA256 = strings.Repeat("0", 64)
		},
		"tickets": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.RecipientManifestSHA256 = strings.Repeat("0", 64)
		},
		"source": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.SourcePeerName = plan.Policy.CustodianPeers[0]
		},
		"rows": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.RowsInBlock--
		},
		"encoding": func(value *formalCoxBlockwiseSourceProductionBinding) {
			value.InputEncoding = "raw-double-v1"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := binding
			mutate(&candidate)
			if _, err := producer.ProduceBlock(
				candidate, bytes.NewReader(encoded)); err == nil {
				t.Fatal("tampered source production binding was accepted")
			}
		})
	}
	if entries, err := os.ReadDir(producer.metadataDir); err != nil || len(entries) != 0 {
		t.Fatalf("binding tamper reached producer persistence: %d %v", len(entries), err)
	}
	_ = producer.Close()

	for _, attack := range []string{"ticket_digest", "ticket_order", "pin"} {
		t.Run(attack, func(t *testing.T) {
			attackPlan, attackPins, attackSigning :=
				formalCoxBlockwiseSourceTestPlan(t, 3)
			attackSession, _, _ := formalCoxBlockwiseSourceTestSession(
				t, attackPlan, attackPins, attackSigning)
			attackSource := attackPlan.Policy.CustodianPeers[2]
			switch attack {
			case "ticket_digest":
				attackSession.ticketSHA256[attackPlan.Policy.ComputePeers[0]] =
					strings.Repeat("0", 64)
			case "ticket_order":
				attackSession.manifest.Tickets[0], attackSession.manifest.Tickets[1] =
					attackSession.manifest.Tickets[1], attackSession.manifest.Tickets[0]
			case "pin":
				attackSession.context.pins[attackSource][0] ^= 1
			}
			if candidate, err := newFormalCoxBlockwiseSourceProducer(
				filepath.Join(t.TempDir(), "producer"), key, attackSession,
				attackSource, attackSigning[attackSource]); err == nil {
				_ = candidate.Close()
				t.Fatal("tampered C1 source session was accepted")
			}
		})
	}
}

func TestFormalCoxBlockwiseSourceProducerDurableTamperMixAndLinks(t *testing.T) {
	for _, attack := range []string{
		"outbox_tamper", "outbox_reorder", "outbox_binding_tamper",
		"receipt_tamper", "outbox_missing", "outbox_binding_missing",
		"receipt_missing", "outbox_hardlink", "outbox_binding_hardlink",
		"outbox_symlink", "cursor_hardlink", "metadata_symlink",
	} {
		t.Run(attack, func(t *testing.T) {
			plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
			session, _, _ := formalCoxBlockwiseSourceTestSession(
				t, plan, pins, signing)
			source := plan.Policy.CustodianPeers[1]
			key := sha256.Sum256([]byte("formal-cox/source-producer/durable/" + attack))
			root := filepath.Join(t.TempDir(), "producer")
			producer, err := newFormalCoxBlockwiseSourceProducer(
				root, key, session, source, signing[source])
			if err != nil {
				t.Fatal(err)
			}
			binding, _ := producer.BlockBinding(0)
			_, encoded := formalCoxBlockwiseSourceProducerTestRows(plan, 0, 1)
			if _, err := producer.ProduceBlock(
				binding, bytes.NewReader(encoded)); err != nil {
				t.Fatal(err)
			}
			left := producer.outboxPath(0, 0)
			right := producer.outboxPath(0, 1)
			outboxBinding := producer.outboxBindingPath(0, 0)
			receipt := producer.receiptPath(0)
			if err := producer.Close(); err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "outbox_tamper", "outbox_binding_tamper", "receipt_tamper":
				path := left
				if attack == "outbox_binding_tamper" {
					path = outboxBinding
				}
				if attack == "receipt_tamper" {
					path = receipt
				}
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				contents[len(contents)/2] ^= 1
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			case "outbox_reorder":
				temporary := left + ".swap"
				if err := os.Rename(left, temporary); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(right, left); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(temporary, right); err != nil {
					t.Fatal(err)
				}
			case "outbox_missing":
				if err := os.Remove(left); err != nil {
					t.Fatal(err)
				}
			case "outbox_binding_missing":
				if err := os.Remove(outboxBinding); err != nil {
					t.Fatal(err)
				}
			case "receipt_missing":
				if err := os.Remove(receipt); err != nil {
					t.Fatal(err)
				}
			case "outbox_hardlink":
				if err := os.Link(left, left+".alias"); err != nil {
					t.Fatal(err)
				}
			case "outbox_binding_hardlink":
				if err := os.Link(outboxBinding, outboxBinding+".alias"); err != nil {
					t.Fatal(err)
				}
			case "cursor_hardlink":
				if err := os.Link(producer.statePath, producer.statePath+".alias"); err != nil {
					t.Fatal(err)
				}
			case "outbox_symlink":
				backup := left + ".target"
				if err := os.Rename(left, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup, left); err != nil {
					t.Fatal(err)
				}
			case "metadata_symlink":
				backup := producer.metadataDir + ".target"
				if err := os.Rename(producer.metadataDir, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup, producer.metadataDir); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := newFormalCoxBlockwiseSourceProducer(
				root, key, session, source, signing[source]); err == nil {
				_ = reopened.Close()
				t.Fatal("tampered durable source producer state was accepted")
			}
		})
	}

	t.Run("root_symlink", func(t *testing.T) {
		plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 2)
		session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
		source := plan.Policy.CustodianPeers[0]
		key := sha256.Sum256([]byte("formal-cox/source-producer/root-symlink"))
		parent := t.TempDir()
		actual := filepath.Join(parent, "actual")
		if err := os.Mkdir(actual, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(parent, "alias")
		if err := os.Symlink(actual, alias); err != nil {
			t.Fatal(err)
		}
		if producer, err := newFormalCoxBlockwiseSourceProducer(
			alias, key, session, source, signing[source]); err == nil {
			_ = producer.Close()
			t.Fatal("symlinked source producer root was accepted")
		}
	})

	t.Run("mixed_snapshot_outbox", func(t *testing.T) {
		plan, pins, signing := formalCoxBlockwiseSourceTestPlan(t, 3)
		session, _, _ := formalCoxBlockwiseSourceTestSession(t, plan, pins, signing)
		source := plan.Policy.CustodianPeers[0]
		key := sha256.Sum256([]byte("formal-cox/source-producer/mix"))
		roots := []string{
			filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second"),
		}
		producers := make([]*formalCoxBlockwiseSourceProducer, 2)
		for index := range producers {
			var err error
			producers[index], err = newFormalCoxBlockwiseSourceProducer(
				roots[index], key, session, source, signing[source])
			if err != nil {
				t.Fatal(err)
			}
			binding, _ := producers[index].BlockBinding(0)
			_, encoded := formalCoxBlockwiseSourceProducerTestRows(plan, 0, index)
			if _, err := producers[index].ProduceBlock(
				binding, bytes.NewReader(encoded)); err != nil {
				t.Fatal(err)
			}
		}
		firstRecords := []string{
			producers[0].outboxPath(0, 0), producers[0].outboxPath(0, 1),
			producers[0].receiptPath(0),
		}
		secondRecords := []string{
			producers[1].outboxPath(0, 0), producers[1].outboxPath(0, 1),
			producers[1].receiptPath(0),
		}
		for _, producer := range producers {
			_ = producer.Close()
		}
		for index := range firstRecords {
			mixed, err := os.ReadFile(secondRecords[index])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(firstRecords[index], mixed, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if reopened, err := newFormalCoxBlockwiseSourceProducer(
			roots[0], key, session, source, signing[source]); err == nil {
			_ = reopened.Close()
			t.Fatal("mixed source outbox was accepted")
		}
	})
}
