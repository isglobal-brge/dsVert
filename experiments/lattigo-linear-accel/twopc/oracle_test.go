package twopc

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	linearaccel "github.com/isglobal-brge/dsvert/experiments/lattigo-linear-accel"
)

func splitForTest(spec *linearaccel.CRTSpec, input linearaccel.LinearInput) (InputShares, InputShares) {
	rows, columns := len(input.X), len(input.Beta)
	first := allocateTestShares(len(spec.Moduli()), rows, columns)
	second := allocateTestShares(len(spec.Moduli()), rows, columns)
	for lane, modulus := range spec.Moduli() {
		for row := 0; row < rows; row++ {
			for column := 0; column < columns; column++ {
				residue := testSignedResidue(input.X[row][column], modulus)
				first.X[lane][row][column] = deterministicTestShare("x", lane, row*columns+column, modulus)
				second.X[lane][row][column] = subMod(residue, first.X[lane][row][column], modulus)
			}
		}
		for index := 0; index < columns; index++ {
			residue := testSignedResidue(input.Beta[index], modulus)
			first.Beta[lane][index] = deterministicTestShare("beta", lane, index, modulus)
			second.Beta[lane][index] = subMod(residue, first.Beta[lane][index], modulus)
		}
		for index := 0; index < rows; index++ {
			residue := testSignedResidue(input.Residual[index], modulus)
			first.Residual[lane][index] = deterministicTestShare("residual", lane, index, modulus)
			second.Residual[lane][index] = subMod(residue, first.Residual[lane][index], modulus)
		}
	}
	return first, second
}

func allocateTestShares(lanes, rows, columns int) InputShares {
	shares := InputShares{
		X:        make([][][]uint64, lanes),
		Beta:     make([][]uint64, lanes),
		Residual: make([][]uint64, lanes),
	}
	for lane := 0; lane < lanes; lane++ {
		shares.X[lane] = make([][]uint64, rows)
		for row := 0; row < rows; row++ {
			shares.X[lane][row] = make([]uint64, columns)
		}
		shares.Beta[lane] = make([]uint64, columns)
		shares.Residual[lane] = make([]uint64, rows)
	}
	return shares
}

func deterministicTestShare(domain string, lane, index int, modulus uint64) uint64 {
	hash := sha256.Sum256([]byte(domain + "/" + big.NewInt(int64(lane)).String() + "/" + big.NewInt(int64(index)).String()))
	return binary.BigEndian.Uint64(hash[:8]) % modulus
}

func reconstructOutputsForTest(t *testing.T, spec *linearaccel.CRTSpec, result Result, first, second *Peer, layer string) []*big.Int {
	t.Helper()
	firstOutput, err := first.Output(result, layer)
	if err != nil {
		t.Fatal(err)
	}
	secondOutput, err := second.Output(result, layer)
	if err != nil {
		t.Fatal(err)
	}
	count := len(firstOutput.SharesByModulus[0])
	bound := new(big.Int).SetBytes(result.Workload.Boundary.MagnitudeBound)
	values := make([]*big.Int, count)
	for index := 0; index < count; index++ {
		residues := make([]uint64, len(spec.Moduli()))
		for lane, modulus := range spec.Moduli() {
			residues[lane] = addMod(firstOutput.SharesByModulus[lane][index], secondOutput.SharesByModulus[lane][index], modulus)
		}
		values[index] = decodeTestCRT(t, spec, residues, bound)
	}
	return values
}

func decodeTestCRT(t *testing.T, spec *linearaccel.CRTSpec, residues []uint64, bound *big.Int) *big.Int {
	t.Helper()
	product := spec.Product()
	x := big.NewInt(0)
	for index, modulus := range spec.Moduli() {
		mi := new(big.Int).Quo(new(big.Int).Set(product), new(big.Int).SetUint64(modulus))
		inverse := new(big.Int).ModInverse(new(big.Int).Mod(mi, new(big.Int).SetUint64(modulus)), new(big.Int).SetUint64(modulus))
		if inverse == nil {
			t.Fatal("test CRT moduli are not coprime")
		}
		term := new(big.Int).Mul(new(big.Int).SetUint64(residues[index]), mi)
		term.Mul(term, inverse)
		x.Add(x, term)
	}
	x.Mod(x, product)
	if x.Cmp(new(big.Int).Rsh(new(big.Int).Set(product), 1)) > 0 {
		x.Sub(x, product)
	}
	if new(big.Int).Abs(new(big.Int).Set(x)).Cmp(bound) > 0 {
		t.Fatalf("test reconstruction %s exceeds public bound %s", x, bound)
	}
	return x
}

func testLinearOracle(input linearaccel.LinearInput) (xBeta, xTr []*big.Int) {
	rows, columns := len(input.X), len(input.Beta)
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

func smallFullInput() linearaccel.LinearInput {
	return linearaccel.LinearInput{
		X:        testMatrix([][]string{{"1", "-2"}, {"3", "4"}}),
		Beta:     testIntegers("5", "-6"),
		Residual: testIntegers("7", "-8"),
		Bounds:   testBounds("4", "6", "8"),
	}
}

func mustTestSpec(t *testing.T, width linearaccel.SignedWidth) *linearaccel.CRTSpec {
	t.Helper()
	spec, err := linearaccel.NewCRTSpec(width, 12)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func testSignedResidue(value *big.Int, modulus uint64) uint64 {
	return new(big.Int).Mod(new(big.Int).Set(value), new(big.Int).SetUint64(modulus)).Uint64()
}

func testMatrix(values [][]string) [][]*big.Int {
	result := make([][]*big.Int, len(values))
	for row := range values {
		result[row] = testIntegers(values[row]...)
	}
	return result
}

func testIntegers(values ...string) []*big.Int {
	result := make([]*big.Int, len(values))
	for index, value := range values {
		parsed, ok := new(big.Int).SetString(value, 10)
		if !ok {
			panic("invalid test integer " + value)
		}
		result[index] = parsed
	}
	return result
}

func testBounds(x, beta, residual string) linearaccel.PublicBounds {
	return linearaccel.PublicBounds{X: testIntegers(x)[0], Beta: testIntegers(beta)[0], Residual: testIntegers(residual)[0]}
}

func testPow2Plus(power uint, add int64) string {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), power), big.NewInt(add)).String()
}

func testNeg(value string) string {
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid test integer " + value)
	}
	return parsed.Neg(parsed).String()
}

func assertTestBigInts(t *testing.T, got, want []*big.Int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d", len(got), len(want))
	}
	for index := range got {
		if got[index].Cmp(want[index]) != 0 {
			t.Fatalf("value %d: got %s, want %s", index, got[index], want[index])
		}
	}
}

func equalResidueMatrices(left, right [][]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for lane := range left {
		if len(left[lane]) != len(right[lane]) {
			return false
		}
		for index := range left[lane] {
			if left[lane][index] != right[lane][index] {
				return false
			}
		}
	}
	return true
}
