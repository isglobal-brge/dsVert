package main

import (
	"testing"
)

func TestSecureCompareBasic(t *testing.T) {
	numBits := 8
	threshold := uint64(100)
	// Use extended domain for shares (matching what the comparison function does)
	N := uint64(1) << (numBits + 2) // extBits = numBits + 2

	errors := 0
	for x := uint64(0); x < 256; x++ {
		x0 := cryptoRandUint64K2() % N
		x1 := (N + x - x0) % N

		bit0, bit1 := SecureComparePublicThreshold(x0, x1, threshold, numBits)
		result := bit0 ^ bit1

		expected := byte(0)
		if x < threshold {
			expected = 1
		}

		if result != expected {
			errors++
			if errors <= 5 {
				t.Errorf("x=%d < %d: got %d want %d", x, threshold, result, expected)
			}
		}
	}
	if errors > 0 {
		t.Errorf("Total comparison errors: %d/256", errors)
	} else {
		t.Log("SecureCompare: 256/256 correct")
	}
}

func TestSecureCompare16Bit(t *testing.T) {
	numBits := 16
	threshold := uint64(30000)
	N := uint64(1) << (numBits + 2)

	testPoints := []uint64{0, 1, 100, 29999, 30000, 30001, 50000, 65535}
	for _, x := range testPoints {
		x0 := cryptoRandUint64K2() % N
		x1 := (N + x - x0) % N

		bit0, bit1 := SecureComparePublicThreshold(x0, x1, threshold, numBits)
		result := bit0 ^ bit1

		expected := byte(0)
		if x < threshold {
			expected = 1
		}

		if result != expected {
			t.Errorf("x=%d < %d: got %d want %d", x, threshold, result, expected)
		}
	}
	t.Log("SecureCompare 16-bit: test complete")
}

func TestSecureEqualBasic(t *testing.T) {
	numBits := 8
	value := uint64(42)
	N := uint64(1) << (numBits + 2)

	errors := 0
	for x := uint64(0); x < 256; x++ {
		x0 := cryptoRandUint64K2() % N
		x1 := (N + x - x0) % N

		bit0, bit1 := SecureEqualPublicValue(x0, x1, value, numBits)
		result := bit0 ^ bit1

		expected := byte(0)
		if x == value {
			expected = 1
		}

		if result != expected {
			errors++
			if errors <= 5 {
				t.Errorf("x=%d == %d: got %d want %d", x, value, result, expected)
			}
		}
	}
	if errors > 0 {
		t.Errorf("Total equality errors: %d/256", errors)
	} else {
		t.Log("SecureEqual: 256/256 correct")
	}
}
