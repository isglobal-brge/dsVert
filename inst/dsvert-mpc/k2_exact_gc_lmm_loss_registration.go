package main

import "math/big"

// One family registration; all fields are internal composition components.
// None grants production authorization, source access or a release capability.
type groupedLMMRegistration struct {
	Profile          string
	Prepare          func(groupedLMMMomentPlan, []groupedWord) (*groupedLMMMoments, error)
	PrecisionCompile func(groupedLMMSpec) (*primitiveVProgram, error)
	PrecisionShares  func(*groupedLMMMoments, groupedLMMSpec, []groupedWord) ([]groupedWord, error)
	LiftCompile      func(int) (*primitiveVProgram, error)
	GridShares       func(groupedLMMMomentPlan, []groupedWord, []groupedWord, [][]*big.Int) ([][2]groupedWord, error)
	FinalCompile     func(int, int64) (*primitiveVProgram, error)
	LegacyCompile    func(groupedLMMSpec) (*primitiveVProgram, error)
}

func groupedLMMRegistry() groupedLMMRegistration {
	return groupedLMMRegistration{"grouped-lmm-stats-f264-q64-v2", groupedLMMPrepareMoments, groupedLMMPrecisionCompile, groupedLMMPrecisionShares, groupedLMMLiftCompile, groupedLMMGridShares, groupedLMMFinalCompile, groupedLMMCompile}
}
