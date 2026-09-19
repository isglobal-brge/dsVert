package main

import "io"

// Measured public rectangle, mirrored by both signed R contract validators.
const coxLossAdmittedRows = 4000
const coxLossAdmittedCandidates = 50

func coxLossAdmit(s coxLossSpec) error {
	if s.validate() != nil || s.Capacity > coxLossAdmittedRows || s.Candidates > coxLossAdmittedCandidates {
		return coxLossError()
	}
	return nil
}

func coxLossAdmittedPlan(s coxLossSpec) (coxLossSharedPlan, error) {
	if err := coxLossAdmit(s); err != nil {
		return coxLossSharedPlan{}, err
	}
	return coxLossPlanShares(s)
}

func coxLossAdmittedCompile(p coxLossSharedPlan) (*coxLossSharedPrograms, error) {
	if err := coxLossAdmit(p.Spec); err != nil {
		return nil, err
	}
	return coxLossCompileShares(p)
}

func coxLossAdmittedRun(rw io.ReadWriter, owner bool, p coxLossSharedPlan, programs *coxLossSharedPrograms, base exactGCSession, contract [32]byte, packed []Uint128, controls, ends []bool) (coxLossShareResult, error) {
	if err := coxLossAdmit(p.Spec); err != nil {
		return coxLossShareResult{}, err
	}
	return coxLossRunShares(rw, owner, p, programs, base, contract, packed, controls, ends)
}
