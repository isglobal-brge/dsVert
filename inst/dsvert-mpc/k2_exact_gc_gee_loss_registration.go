package main

import "io"

type groupedGEERegistration struct {
	ProduceFactors func(io.ReadWriter, exactGCSession, exactGCRole, [32]byte, groupedGEESpec, []groupedWord) (*groupedGEEFactorResult, error)
	Certificate    func(groupedGEESpec) (*groupedGEECertificate, error)
	LegacyCompile  func(groupedGEESpec) (*primitiveVProgram, error)
	MomentOperands func(groupedGEESpec, []groupedWord) ([]groupedWord, []groupedWord, error)
	MomentSums     func(groupedGEESpec, []groupedWord) ([]groupedWord, error)
	MomentBoundary func(groupedGEESpec) (*primitiveVProgram, error)
	MeatOperands   func(groupedGEESpec, []groupedWord) ([]groupedWord, []groupedWord, error)
	MeatFinal      func(groupedGEESpec) (*primitiveVProgram, error)
}

func groupedGEERegistry() groupedGEERegistration {
	return groupedGEERegistration{groupedGEEProduceFactors, groupedGEEWhiteningCertificate, groupedGEECompile, groupedGEEMomentOperands, groupedGEEMomentSums, groupedGEEMomentBoundaryCompile, groupedGEEMeatOperands, groupedGEEMeatFinalCompile}
}
