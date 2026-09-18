package main

type groupedGEERegistration struct {
	LegacyCompile  func(groupedGEESpec) (*primitiveVProgram, error)
	MomentOperands func(groupedGEESpec, []groupedWord) ([]groupedWord, []groupedWord, error)
	MomentSums     func(groupedGEESpec, []groupedWord) ([]groupedWord, error)
	MomentBoundary func(groupedGEESpec) (*primitiveVProgram, error)
	MeatOperands   func(groupedGEESpec, []groupedWord) ([]groupedWord, []groupedWord, error)
	MeatFinal      func(groupedGEESpec) (*primitiveVProgram, error)
}

func groupedGEERegistry() groupedGEERegistration {
	return groupedGEERegistration{groupedGEECompile, groupedGEEMomentOperands, groupedGEEMomentSums, groupedGEEMomentBoundaryCompile, groupedGEEMeatOperands, groupedGEEMeatFinalCompile}
}
