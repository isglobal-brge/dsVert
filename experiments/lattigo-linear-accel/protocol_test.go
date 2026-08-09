package linearaccel

import (
	"errors"
	"math/big"
	"testing"
)

func TestMultipartyLinearLayersMatchBigIntOracle(t *testing.T) {
	testCases := []struct {
		name  string
		width SignedWidth
		roles int
		input LinearInput
	}{
		{
			name:  "signed63-two-roles",
			width: Signed63,
			roles: 2,
			input: LinearInput{
				X:        matrix([][]string{{"-2", "3"}, {"5", "-7"}}),
				Beta:     integers("11", "-13"),
				Residual: integers("-17", "19"),
				Bounds:   bounds("7", "13", "19"),
			},
		},
		{
			name:  "signed127-three-roles-and-crt-carry",
			width: Signed127,
			roles: 3,
			input: LinearInput{
				X: matrix([][]string{
					{"2147483655", "-1073741833"},
					{"-2147483661", "1073741841"},
				}),
				Beta:     integers("8589934609", "-4294967311"),
				Residual: integers("-17179869191", "34359738381"),
				Bounds:   bounds("2147483661", "8589934609", "34359738381"),
			},
		},
		{
			name:  "signed257-two-roles-large-carry",
			width: Signed257,
			roles: 2,
			input: LinearInput{
				X: matrix([][]string{
					{pow2Plus(100, 17), neg(pow2Plus(99, 31))},
					{neg(pow2Plus(98, 43)), pow2Plus(97, 59)},
				}),
				Beta:     integers(pow2Plus(120, 67), neg(pow2Plus(119, 71))),
				Residual: integers(neg(pow2Plus(110, 73)), pow2Plus(109, 79)),
				Bounds:   bounds(pow2Plus(101, 0), pow2Plus(121, 0), pow2Plus(111, 0)),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			experiment, err := NewExperiment(tc.width, tc.roles)
			if err != nil {
				t.Fatal(err)
			}
			result, err := experiment.Run(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Metrics.CollectiveComputeRoles != tc.roles {
				t.Fatalf("got %d roles in metrics, want %d", result.Metrics.CollectiveComputeRoles, tc.roles)
			}
			gotXBeta := reconstructForOracle(t, experiment, result, layerXBeta)
			gotXtR := reconstructForOracle(t, experiment, result, layerXtR)
			wantXBeta, wantXtR := linearOracle(tc.input)
			assertBigIntVectorEqual(t, gotXBeta, wantXBeta)
			assertBigIntVectorEqual(t, gotXtR, wantXtR)

			// The carry cases exceed one native plaintext lane, so equality above
			// genuinely exercises cross-lane CRT reconstruction.
			if tc.width != Signed63 {
				threshold := new(big.Int).SetUint64(experiment.spec.moduli[0])
				if maxAbs(append(wantXBeta, wantXtR...)).Cmp(threshold) <= 0 {
					t.Fatal("test fixture did not cross a CRT lane modulus")
				}
			}
		})
	}
}

func TestRelayRejectsTamperReplayAndTranscriptSubstitution(t *testing.T) {
	experiment, err := NewExperiment(Signed63, 2)
	if err != nil {
		t.Fatal(err)
	}
	result, err := experiment.Run(smallInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(experiment.lastEnvelopes) == 0 {
		t.Fatal("run produced no authenticated public shares")
	}
	original := experiment.lastEnvelopes[0]
	want := envelopeExpectation{
		Session:        original.Session,
		BoundaryDigest: original.BoundaryDigest,
		CiphertextHash: original.CiphertextHash,
		Stage:          original.Stage,
		Sender:         original.Sender,
		Lane:           original.Lane,
		Output:         original.Output,
		Sequence:       original.Sequence,
	}
	if _, err := experiment.relay.accept(original, want); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}

	tampered := original
	tampered.Payload = append([]byte(nil), original.Payload...)
	tampered.Payload[len(tampered.Payload)/2] ^= 1
	if _, err := experiment.relay.accept(tampered, want); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tamper: got %v, want ErrBadSignature", err)
	}

	substituted := original
	substituted.Stage = "enc-to-share/substituted"
	var sender *computeRole
	for _, role := range experiment.roles {
		if role.id == substituted.Sender {
			sender = role
			break
		}
	}
	if sender == nil {
		t.Fatal("test sender disappeared")
	}
	if err := signEnvelope(sender.privateKey, &substituted); err != nil {
		t.Fatal(err)
	}
	if _, err := experiment.relay.accept(substituted, want); !errors.Is(err, ErrTranscript) {
		t.Fatalf("substitution: got %v, want ErrTranscript", err)
	}

	wrongResult := result
	wrongResult.Boundary.Digest[0] ^= 1
	if _, err := experiment.GCInput(wrongResult, experiment.roles[0].id, layerXBeta); err == nil {
		t.Fatal("accepted a GC handoff with a substituted boundary")
	}
}

func TestLocalMaskGuardRejectsOperationAndMaskReuse(t *testing.T) {
	role := &computeRole{operations: make(map[string]struct{}), maskHashes: make(map[[32]byte]struct{})}
	if err := role.registerMask("session-a/output-a", []byte("mask-a")); err != nil {
		t.Fatal(err)
	}
	if err := role.registerMask("session-a/output-a", []byte("mask-b")); !errors.Is(err, ErrMaskReuse) {
		t.Fatalf("same operation: got %v, want ErrMaskReuse", err)
	}
	if err := role.registerMask("session-b/output-b", []byte("mask-a")); !errors.Is(err, ErrMaskReuse) {
		t.Fatalf("same mask: got %v, want ErrMaskReuse", err)
	}
}

func TestInputBoundsFailClosedBeforeEncryption(t *testing.T) {
	spec, err := NewCRTSpec(Signed63, experimentLogN)
	if err != nil {
		t.Fatal(err)
	}
	input := smallInput()
	input.X[0][0] = big.NewInt(9)
	if _, _, _, err := validateLinearInput(input, spec, 4096); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("got %v, want ErrBoundExceeded", err)
	}

	input = smallInput()
	input.Bounds.X = spec.Capacity()
	input.Bounds.Beta = spec.Capacity()
	if _, _, _, err := validateLinearInput(input, spec, 4096); !errors.Is(err, ErrBoundExceeded) {
		t.Fatalf("oversized derived output: got %v, want ErrBoundExceeded", err)
	}
}

func reconstructForOracle(t *testing.T, experiment *Experiment, result RunResult, layer string) []*big.Int {
	t.Helper()
	inputs := make([]GCPartyInput, len(experiment.roles))
	for i, role := range experiment.roles {
		input, err := experiment.GCInput(result, role.id, layer)
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = input
	}
	valueCount := len(inputs[0].SharesByModulus[0])
	bound := new(big.Int).SetBytes(result.Boundary.MagnitudeBound)
	values := make([]*big.Int, valueCount)
	for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
		combined := make([]uint64, len(experiment.spec.moduli))
		for laneIndex, modulus := range experiment.spec.moduli {
			var sum uint64
			for _, input := range inputs {
				sum = addMod(sum, input.SharesByModulus[laneIndex][valueIndex], modulus)
			}
			combined[laneIndex] = sum
		}
		value, err := experiment.spec.decodeCombinedSigned(combined, bound)
		if err != nil {
			t.Fatal(err)
		}
		values[valueIndex] = value
	}
	return values
}

func linearOracle(input LinearInput) (xBeta, xTr []*big.Int) {
	rows := len(input.X)
	columns := len(input.Beta)
	xBeta = make([]*big.Int, rows)
	for row := 0; row < rows; row++ {
		xBeta[row] = big.NewInt(0)
		for column := 0; column < columns; column++ {
			xBeta[row].Add(xBeta[row], new(big.Int).Mul(input.X[row][column], input.Beta[column]))
		}
	}
	xTr = make([]*big.Int, columns)
	for column := 0; column < columns; column++ {
		xTr[column] = big.NewInt(0)
		for row := 0; row < rows; row++ {
			xTr[column].Add(xTr[column], new(big.Int).Mul(input.X[row][column], input.Residual[row]))
		}
	}
	return xBeta, xTr
}

func addMod(left, right, modulus uint64) uint64 {
	return new(big.Int).Mod(
		new(big.Int).Add(new(big.Int).SetUint64(left), new(big.Int).SetUint64(right)),
		new(big.Int).SetUint64(modulus),
	).Uint64()
}

func assertBigIntVectorEqual(t *testing.T, got, want []*big.Int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Cmp(want[i]) != 0 {
			t.Fatalf("value %d: got %s, want %s", i, got[i], want[i])
		}
	}
}

func smallInput() LinearInput {
	return LinearInput{
		X:        matrix([][]string{{"1", "-2"}, {"3", "4"}}),
		Beta:     integers("5", "-6"),
		Residual: integers("7", "-8"),
		Bounds:   bounds("4", "6", "8"),
	}
}

func matrix(values [][]string) [][]*big.Int {
	result := make([][]*big.Int, len(values))
	for i := range values {
		result[i] = integers(values[i]...)
	}
	return result
}

func integers(values ...string) []*big.Int {
	result := make([]*big.Int, len(values))
	for i, value := range values {
		parsed, ok := new(big.Int).SetString(value, 10)
		if !ok {
			panic("invalid test integer " + value)
		}
		result[i] = parsed
	}
	return result
}

func bounds(x, beta, residual string) PublicBounds {
	return PublicBounds{X: integers(x)[0], Beta: integers(beta)[0], Residual: integers(residual)[0]}
}

func pow2Plus(power uint, add int64) string {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), power), big.NewInt(add)).String()
}

func neg(value string) string {
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid test integer " + value)
	}
	return parsed.Neg(parsed).String()
}

func maxAbs(values []*big.Int) *big.Int {
	max := big.NewInt(0)
	for _, value := range values {
		absolute := new(big.Int).Abs(new(big.Int).Set(value))
		if absolute.Cmp(max) > 0 {
			max = absolute
		}
	}
	return max
}
