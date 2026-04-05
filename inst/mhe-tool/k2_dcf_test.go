package main

import (
	"testing"
)

func TestDCFBasic(t *testing.T) {
	// DCF: f(x) = 1 if x < 5, else 0. Domain [0, 16) (4 bits).
	alpha := uint64(5)
	beta := int64(1)
	numBits := 4

	key0, key1 := DCFGen(alpha, beta, numBits)

	for x := uint64(0); x < 16; x++ {
		v0 := DCFEval(0, key0, x)
		v1 := DCFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x < alpha {
			expected = beta
		}

		if result != expected {
			t.Errorf("DCF(x=%d): got %d, want %d (v0=%d, v1=%d)", x, result, expected, v0, v1)
		}
	}
	t.Log("DCF basic test passed for all 16 values")
}

func TestDCFLargerDomain(t *testing.T) {
	// 8-bit domain [0, 256), threshold at 100
	alpha := uint64(100)
	beta := int64(1)
	numBits := 8

	key0, key1 := DCFGen(alpha, beta, numBits)

	errors := 0
	for x := uint64(0); x < 256; x++ {
		v0 := DCFEval(0, key0, x)
		v1 := DCFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x < alpha {
			expected = beta
		}

		if result != expected {
			errors++
			if errors <= 5 {
				t.Errorf("DCF(x=%d): got %d, want %d", x, result, expected)
			}
		}
	}
	if errors > 0 {
		t.Errorf("Total errors: %d/256", errors)
	} else {
		t.Log("DCF 8-bit test passed for all 256 values")
	}
}

func TestDCFWithBeta(t *testing.T) {
	// DCF with beta = 42
	alpha := uint64(3)
	beta := int64(42)
	numBits := 4

	key0, key1 := DCFGen(alpha, beta, numBits)

	for x := uint64(0); x < 16; x++ {
		v0 := DCFEval(0, key0, x)
		v1 := DCFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x < alpha {
			expected = beta
		}

		if result != expected {
			t.Errorf("DCF(x=%d): got %d, want %d", x, result, expected)
		}
	}
}

func TestDPFBasic(t *testing.T) {
	// DPF: f(x) = 1 if x == 7, else 0. Domain [0, 16).
	alpha := uint64(7)
	beta := int64(1)
	numBits := 4

	key0, key1 := DPFGen(alpha, beta, numBits)

	for x := uint64(0); x < 16; x++ {
		v0 := DPFEval(0, key0, x)
		v1 := DPFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x == alpha {
			expected = beta
		}

		if result != expected {
			t.Errorf("DPF(x=%d): got %d, want %d", x, result, expected)
		}
	}
	t.Log("DPF basic test passed for all 16 values")
}

func TestDPF8Bit(t *testing.T) {
	alpha := uint64(200)
	beta := int64(1)
	numBits := 8

	key0, key1 := DPFGen(alpha, beta, numBits)

	errors := 0
	for x := uint64(0); x < 256; x++ {
		v0 := DPFEval(0, key0, x)
		v1 := DPFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x == alpha {
			expected = beta
		}

		if result != expected {
			errors++
			if errors <= 5 {
				t.Errorf("DPF(x=%d): got %d, want %d", x, result, expected)
			}
		}
	}
	if errors > 0 {
		t.Errorf("Total errors: %d/256", errors)
	} else {
		t.Log("DPF 8-bit test passed for all 256 values")
	}
}

func TestDCF16Bit(t *testing.T) {
	// 16-bit domain, threshold at 30000
	alpha := uint64(30000)
	beta := int64(1)
	numBits := 16

	key0, key1 := DCFGen(alpha, beta, numBits)

	// Test a sample of values
	testPoints := []uint64{0, 1, 100, 29999, 30000, 30001, 50000, 65535}
	for _, x := range testPoints {
		v0 := DCFEval(0, key0, x)
		v1 := DCFEval(1, key1, x)
		result := v0 + v1

		expected := int64(0)
		if x < alpha {
			expected = beta
		}

		if result != expected {
			t.Errorf("DCF16(x=%d): got %d, want %d", x, result, expected)
		}
	}
	t.Log("DCF 16-bit sample test passed")
}
