package twopc

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
)

func TestAdditiveShareProtocolMatchesBigIntOracle(t *testing.T) {
	testCases := []struct {
		name       string
		width      linearaccel.SignedWidth
		custodians int
		input      linearaccel.LinearInput
	}{
		{
			name:       "signed63-k2",
			width:      linearaccel.Signed63,
			custodians: 2,
			input: linearaccel.LinearInput{
				X:        testMatrix([][]string{{"-2", "3"}, {"5", "-7"}}),
				Beta:     testIntegers("11", "-13"),
				Residual: testIntegers("-17", "19"),
				Bounds:   testBounds("7", "13", "19"),
			},
		},
		{
			name:       "signed127-k3-cross-lane-carry",
			width:      linearaccel.Signed127,
			custodians: 3,
			input: linearaccel.LinearInput{
				X: testMatrix([][]string{
					{"2147483655", "-1073741833"},
					{"-2147483661", "1073741841"},
				}),
				Beta:     testIntegers("8589934609", "-4294967311"),
				Residual: testIntegers("-17179869191", "34359738381"),
				Bounds:   testBounds("2147483661", "8589934609", "34359738381"),
			},
		},
		{
			name:       "signed257-k5-large-cross-lane-carry",
			width:      linearaccel.Signed257,
			custodians: 5,
			input: linearaccel.LinearInput{
				X: testMatrix([][]string{
					{testPow2Plus(100, 17), testNeg(testPow2Plus(99, 31))},
					{testNeg(testPow2Plus(98, 43)), testPow2Plus(97, 59)},
				}),
				Beta:     testIntegers(testPow2Plus(120, 67), testNeg(testPow2Plus(119, 71))),
				Residual: testIntegers(testNeg(testPow2Plus(110, 73)), testPow2Plus(109, 79)),
				Bounds:   testBounds(testPow2Plus(101, 0), testPow2Plus(121, 0), testPow2Plus(111, 0)),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := linearaccel.NewCRTSpec(tc.width, 12)
			if err != nil {
				t.Fatal(err)
			}
			firstShares, secondShares := splitForTest(spec, tc.input)
			first, err := NewPeer("compute-1", spec, firstShares)
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewPeer("compute-2", spec, secondShares)
			if err != nil {
				t.Fatal(err)
			}
			session, err := NewSession(spec, len(tc.input.X), len(tc.input.Beta), tc.custodians, tc.input.Bounds, []Identity{first.Identity(), second.Identity()})
			if err != nil {
				t.Fatal(err)
			}
			result, err := session.Run(first, second)
			if err != nil {
				t.Fatal(err)
			}
			if result.Workload.CustodianCount != tc.custodians {
				t.Fatalf("got K=%d, want %d", result.Workload.CustodianCount, tc.custodians)
			}
			wantXBeta, wantXtR := testLinearOracle(tc.input)
			gotXBeta := reconstructOutputsForTest(t, spec, result, first, second, LayerXBeta)
			gotXtR := reconstructOutputsForTest(t, spec, result, first, second, LayerXtR)
			assertTestBigInts(t, gotXBeta, wantXBeta)
			assertTestBigInts(t, gotXtR, wantXtR)

			// X*beta sends one encrypted scalar per coefficient and one
			// masked vector. X^T*r sends one packed residual vector and one
			// authenticated bundle containing the per-column masked vectors.
			// Its message count is therefore independent of the row count.
			expectedMessages := len(spec.Moduli()) * 2 * (len(tc.input.Beta) + 3)
			if result.Metrics.MessageCount != expectedMessages {
				t.Fatalf("got %d messages, want %d", result.Metrics.MessageCount, expectedMessages)
			}
			if result.Metrics.EncryptedInputWireBytes <= result.Metrics.EncryptedInputPayloadBytes ||
				result.Metrics.MaskedOutputWireBytes <= result.Metrics.MaskedOutputPayloadBytes {
				t.Fatal("wire metrics do not include authenticated envelopes")
			}
		})
	}
}

func TestXtRTransportShapeIsIndependentOfRowCount(t *testing.T) {
	const rows = 64
	const columns = 3
	input := linearaccel.LinearInput{
		X:        make([][]*big.Int, rows),
		Beta:     make([]*big.Int, columns),
		Residual: make([]*big.Int, rows),
		Bounds:   testBounds("7", "5", "3"),
	}
	for row := range input.X {
		input.X[row] = make([]*big.Int, columns)
		for column := range input.X[row] {
			input.X[row][column] = big.NewInt(int64((row+column)%7 - 3))
		}
		input.Residual[row] = big.NewInt(int64(row%5 - 2))
	}
	for column := range input.Beta {
		input.Beta[column] = big.NewInt(int64(column - 1))
	}

	spec := mustTestSpec(t, linearaccel.Signed63)
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(spec, rows, columns, 5, input.Bounds,
		[]Identity{first.Identity(), second.Identity()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Run(first, second)
	if err != nil {
		t.Fatal(err)
	}

	wantXBeta, wantXtR := testLinearOracle(input)
	assertTestBigInts(t,
		reconstructOutputsForTest(t, spec, result, first, second, LayerXBeta),
		wantXBeta)
	assertTestBigInts(t,
		reconstructOutputsForTest(t, spec, result, first, second, LayerXtR),
		wantXtR)

	inputMessages := 0
	outputMessages := 0
	for _, message := range session.lastMessages {
		switch message.Stage {
		case "cross-input/" + LayerXtR:
			inputMessages++
			if message.Index != 0 {
				t.Fatalf("packed residual message used index %d", message.Index)
			}
		case "masked-cross/" + LayerXtR:
			outputMessages++
			payloads, decodeErr := decodeCiphertextBundle(
				message.Payload, columns, 64<<20)
			if decodeErr != nil {
				t.Fatalf("decode masked X^T*r bundle: %v", decodeErr)
			}
			if len(payloads) != columns {
				t.Fatalf("got %d bundled column ciphertexts, want %d",
					len(payloads), columns)
			}
		}
	}
	wantPerStage := 2 * len(spec.Moduli())
	if inputMessages != wantPerStage || outputMessages != wantPerStage {
		t.Fatalf("packed X^T*r stages: inputs=%d outputs=%d, want %d each",
			inputMessages, outputMessages, wantPerStage)
	}
	wantMessages := len(spec.Moduli()) * 2 * (columns + 3)
	if result.Metrics.MessageCount != wantMessages {
		t.Fatalf("got %d total messages for %d rows, want %d",
			result.Metrics.MessageCount, rows, wantMessages)
	}
}

func TestRandomSmallMatricesMatchOracle(t *testing.T) {
	random := rand.New(rand.NewSource(20260802))
	for replicate := 0; replicate < 12; replicate++ {
		rows, columns := 1+random.Intn(4), 1+random.Intn(4)
		input := linearaccel.LinearInput{
			X:        make([][]*big.Int, rows),
			Beta:     make([]*big.Int, columns),
			Residual: make([]*big.Int, rows),
			Bounds:   testBounds("12", "12", "12"),
		}
		for row := range input.X {
			input.X[row] = make([]*big.Int, columns)
			for column := range input.X[row] {
				input.X[row][column] = big.NewInt(int64(random.Intn(25) - 12))
			}
			input.Residual[row] = big.NewInt(int64(random.Intn(25) - 12))
		}
		for column := range input.Beta {
			input.Beta[column] = big.NewInt(int64(random.Intn(25) - 12))
		}

		spec := mustTestSpec(t, linearaccel.Signed63)
		firstShares, secondShares := splitForTest(spec, input)
		first, err := NewPeer("compute-1", spec, firstShares)
		if err != nil {
			t.Fatal(err)
		}
		second, err := NewPeer("compute-2", spec, secondShares)
		if err != nil {
			t.Fatal(err)
		}
		session, err := NewSession(spec, rows, columns, 2+replicate%4, input.Bounds, []Identity{first.Identity(), second.Identity()})
		if err != nil {
			t.Fatal(err)
		}
		var result Result
		if replicate%2 == 0 {
			result, err = session.Run(first, second)
		} else {
			result, err = session.Run(second, first)
		}
		if err != nil {
			t.Fatalf("replicate %d: %v", replicate, err)
		}
		wantXBeta, wantXtR := testLinearOracle(input)
		assertTestBigInts(t, reconstructOutputsForTest(t, spec, result, first, second, LayerXBeta), wantXBeta)
		assertTestBigInts(t, reconstructOutputsForTest(t, spec, result, first, second, LayerXtR), wantXtR)
	}
}

func TestFreshRunsProduceFreshOutputSharings(t *testing.T) {
	spec, first, second, session := newSmallProtocol(t)
	firstResult, err := session.Run(first, second)
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := session.Run(first, second)
	if err != nil {
		t.Fatal(err)
	}
	firstOutput, err := first.Output(firstResult, LayerXBeta)
	if err != nil {
		t.Fatal(err)
	}
	secondOutput, err := first.Output(secondResult, LayerXBeta)
	if err != nil {
		t.Fatal(err)
	}
	if equalResidueMatrices(firstOutput.SharesByModulus, secondOutput.SharesByModulus) {
		t.Fatal("fresh sessions unexpectedly produced the same additive output sharing")
	}
	_ = spec
}

func TestPeerDeepCopiesItsOnlyInputShare(t *testing.T) {
	spec := mustTestSpec(t, linearaccel.Signed63)
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	for lane := range firstShares.X {
		for row := range firstShares.X[lane] {
			for column := range firstShares.X[lane][row] {
				firstShares.X[lane][row][column] = 0
			}
		}
		for index := range firstShares.Beta[lane] {
			firstShares.Beta[lane][index] = 0
		}
		for index := range firstShares.Residual[lane] {
			firstShares.Residual[lane][index] = 0
		}
	}
	session, err := NewSession(spec, 2, 2, 4, input.Bounds, []Identity{first.Identity(), second.Identity()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Run(first, second)
	if err != nil {
		t.Fatal(err)
	}
	wantXBeta, _ := testLinearOracle(input)
	got := reconstructOutputsForTest(t, spec, result, first, second, LayerXBeta)
	assertTestBigInts(t, got, wantXBeta)
}

func TestAuthenticatedRouterRejectsTamperReplayAndSubstitution(t *testing.T) {
	_, first, second, session := newSmallProtocol(t)
	if _, err := session.Run(first, second); err != nil {
		t.Fatal(err)
	}
	if len(session.lastMessages) == 0 {
		t.Fatal("protocol emitted no authenticated messages")
	}
	original := session.lastMessages[0]
	want := expectationFromMessage(original)
	if _, err := session.router.accept(original, want); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}

	tampered := original
	tampered.Payload = append([]byte(nil), original.Payload...)
	tampered.Payload[len(tampered.Payload)/2] ^= 1
	if _, err := session.router.accept(tampered, want); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper: got %v, want ErrAuthentication", err)
	}

	substituted := original
	substituted.Receiver = "wrong-receiver"
	var sender *Peer
	if substituted.Sender == first.id {
		sender = first
	} else {
		sender = second
	}
	if err := substituted.sign(sender.signingKey); err != nil {
		t.Fatal(err)
	}
	if _, err := session.router.accept(substituted, want); !errors.Is(err, ErrTranscript) {
		t.Fatalf("substitution: got %v, want ErrTranscript", err)
	}
}

func TestMaskReuseAndUnknownPinnedPeerFailClosed(t *testing.T) {
	spec := mustTestSpec(t, linearaccel.Signed63)
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	if err := first.registerMask("operation-a", 0, []uint64{1, 2}); err != nil {
		first.mu.Unlock()
		t.Fatal(err)
	}
	if err := first.registerMask("operation-a", 0, []uint64{3, 4}); !errors.Is(err, ErrMaskReuse) {
		first.mu.Unlock()
		t.Fatalf("operation reuse: got %v, want ErrMaskReuse", err)
	}
	if err := first.registerMask("operation-b", 0, []uint64{1, 2}); !errors.Is(err, ErrMaskReuse) {
		first.mu.Unlock()
		t.Fatalf("mask reuse: got %v, want ErrMaskReuse", err)
	}
	first.mu.Unlock()

	session, err := NewSession(spec, 2, 2, 2, input.Bounds, []Identity{first.Identity(), second.Identity()})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Run(first, replacement); err == nil {
		t.Fatal("session accepted a peer whose identity did not match the pin")
	}
}

func TestInputSharesAndSessionMetadataAreValidated(t *testing.T) {
	spec := mustTestSpec(t, linearaccel.Signed63)
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	firstShares.X[0][0][0] = spec.Moduli()[0]
	if _, err := NewPeer("compute-1", spec, firstShares); err == nil {
		t.Fatal("accepted a non-canonical additive share")
	}
	valid, err := NewPeer("compute-1", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(spec, 2, 2, 1, input.Bounds, []Identity{valid.Identity(), valid.Identity()}); err == nil {
		t.Fatal("accepted K<2 and duplicate peer pins")
	}
	tooLarge := linearaccel.PublicBounds{X: spec.Capacity(), Beta: spec.Capacity(), Residual: big.NewInt(1)}
	other, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(spec, 2, 2, 2, tooLarge, []Identity{valid.Identity(), other.Identity()}); !errors.Is(err, linearaccel.ErrBoundExceeded) {
		t.Fatalf("oversized workload: got %v, want ErrBoundExceeded", err)
	}
}

func newSmallProtocol(t *testing.T) (*linearaccel.CRTSpec, *Peer, *Peer, *Session) {
	t.Helper()
	spec := mustTestSpec(t, linearaccel.Signed63)
	input := smallFullInput()
	firstShares, secondShares := splitForTest(spec, input)
	first, err := NewPeer("compute-1", spec, firstShares)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPeer("compute-2", spec, secondShares)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(spec, 2, 2, 2, input.Bounds, []Identity{first.Identity(), second.Identity()})
	if err != nil {
		t.Fatal(err)
	}
	return spec, first, second, session
}

func expectationFromMessage(message envelope) expectation {
	return expectation{
		Session:        message.Session,
		WorkloadDigest: message.WorkloadDigest,
		Stage:          message.Stage,
		Sender:         message.Sender,
		Receiver:       message.Receiver,
		Lane:           message.Lane,
		Index:          message.Index,
		Sequence:       message.Sequence,
	}
}
