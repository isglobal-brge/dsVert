package main

import (
    "testing"
)

func TestMulModConsistency(t *testing.T) {
    rp := DefaultRingParams()
    cfg := DefaultKelkarExpConfig()
    q := cfg.PrimeQ
    
    // Compare mulMod with rp.ModMul
    a := uint64(1234567890123)
    b := uint64(9876543210987)
    
    r1 := mulMod(a, b, q)
    
    // rp.ModMul uses bits.Mul64
    r2 := rp.ModMul(a, b)
    
    t.Logf("mulMod(%d, %d, q) = %d", a, b, r1)
    t.Logf("rp.ModMul(%d, %d) = %d (mod=%d)", a, b, r2, rp.Modulus)
    t.Logf("Moduli: q=%d, ring=%d", q, rp.Modulus)
    
    // Check: does truncMul128 match rp.TruncMulFP?
    share := uint64(7123456789012345678)
    log2eFP := rp.FromDouble(1.4426950408889634073599)
    
    tm1 := truncMul128(share, log2eFP, rp)
    // rp doesn't have TruncMulFP, but let's compute it manually
    // The TruncMul should be: (share * log2eFP) >> fracBits mod Modulus
    
    t.Logf("truncMul128(%d, %d) = %d", share, log2eFP, tm1)
    
    // Verify with ModMul (which does (a*b) mod Modulus, NOT truncated)
    mm := rp.ModMul(share, log2eFP)
    t.Logf("rp.ModMul(%d, %d) = %d (ring multiply, no truncation)", share, log2eFP, mm)
}
