package main

import "testing"

func TestCoxGridCrossMeasuredAdmission(t *testing.T) {
	s := coxLossSpec{Capacity: coxLossAdmittedRows, Candidates: coxLossAdmittedCandidates, GridBits: 8, Profile: CoxGridCrossProfileID, Caps: make([]uint64, coxLossAdmittedCandidates)}
	for i := range s.Caps {
		s.Caps[i] = 1000000
	}
	r := registerCoxGridCrossLoss()
	if _, err := r.SharedPlan(s); err != nil {
		t.Fatal(err)
	}
	for _, rows := range []bool{true, false} {
		bad := s
		if rows {
			bad.Capacity++
		} else {
			bad.Candidates++
			bad.Caps = append(append([]uint64(nil), s.Caps...), 1000000)
		}
		if _, err := r.SharedPlan(bad); err == nil {
			t.Fatal("admitted excess public capacity")
		}
		p, err := coxLossPlanShares(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.SharedCompile(p); err == nil {
			t.Fatal("compiled excess capacity")
		}
		// Nil transport/programs: rejection must precede any I/O or source use.
		out, err := r.RunShares(nil, true, p, nil, exactGCSession{}, [32]byte{}, nil, nil, nil)
		if err == nil || len(out.Coordinates) != 0 {
			t.Fatal("ran excess capacity")
		}
	}
}

// Main exp/log tiles do not depend on lattice bits or candidate loss caps.
// Bound the only varying tile so admission retains its measured headroom.
func TestCoxGridCrossFinalizerResourceBound(t *testing.T) {
	var maximum uint64
	for _, rows := range []int{2000, 4000, 10000} {
		for bits := 8; bits <= 18; bits++ {
			cap, err := coxLossCap(rows, bits, []float64{4, 4})
			if err != nil {
				t.Fatal(err)
			}
			for _, limit := range []uint64{1, cap / 2, cap} {
				s := coxLossSpec{rows, 1, bits, []uint64{limit}, CoxGridCrossProfileID}
				source, w, g, e, o := coxLossFinalizeSource(s, 0)
				program := coxTestCompile(t, source, w, g, e, o)
				maximum = max(maximum, program.Circuit.Stats.NumNonXOR())
				if program.Circuit.Stats.NumNonXOR() > 4096 {
					t.Fatal("finalizer exceeds public resource bound")
				}
			}
		}
	}
	t.Logf("maximum finalizer non-XOR gates: %d", maximum)
}
