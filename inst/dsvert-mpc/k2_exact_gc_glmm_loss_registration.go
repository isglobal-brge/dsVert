package main

type groupedGLMMShareRegistration struct {
	PredictorCompile func(int, int) (*primitiveVProgram, error)
	ScalarCompile    func(string, int) (*primitiveVProgram, error)
	ScoreShares      func(groupedGLMMSpec, exactGCRole, []groupedWord, []groupedWord, []groupedWord, []groupedWord) ([5]groupedWord, error)
	CenterCompile    func(groupedGLMMSpec) (*primitiveVProgram, error)
	FinalCompile     func(groupedGLMMSpec, int64) (*primitiveVProgram, error)
}

func groupedGLMMShareRegistry() groupedGLMMShareRegistration {
	return groupedGLMMShareRegistration{groupedPredictorCompile, groupedWideScalarCompile, groupedGLMMScoreShares, groupedGLMMCenterCompile, groupedGLMMFinalCompile}
}
