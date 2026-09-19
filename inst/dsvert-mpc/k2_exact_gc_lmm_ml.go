package main

// Certified finite ML variance grid. The retained fixed-covariance quadratic
// remains unchanged. REML is not this objective and is not admitted here.
import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const groupedLMMMLProfile = "grouped-lmm-ml-variance-f264-q64-log-up-v1"
const groupedLMMMLCertificateSHA256 = "0f93bcef61647e6810bb5691f09563c8758c75b25f7d86de03d37ada3cd6bea5"

type groupedLMMVariance struct {
	Sigma2Q64, Tau2Q64 *big.Int
}

func groupedLMMValidateObjective(s groupedLMMStagedSpec) error {
	if s.Objective == "" {
		if len(s.VarianceGrid) != 0 || len(s.Caps) != len(s.Beta) {
			return primitiveVError()
		}
		return nil
	}
	if s.Objective != "ml" || len(s.VarianceGrid) == 0 || len(s.VarianceGrid) > 256/len(s.Beta) || len(s.Caps) != len(s.Beta)*len(s.VarianceGrid) {
		return primitiveVError()
	}
	for i, variance := range s.VarianceGrid {
		numeric := s.Numeric
		numeric.Sigma2Q64, numeric.Tau2Q64 = variance.Sigma2Q64, variance.Tau2Q64
		if groupedLMMValidate(numeric) != nil ||
			new(big.Int).And(variance.Sigma2Q64, exactGCMask(48)).Sign() != 0 ||
			new(big.Int).And(variance.Tau2Q64, exactGCMask(48)).Sign() != 0 {
			return primitiveVError()
		}
		if i == 0 {
			if variance.Sigma2Q64.Cmp(s.Numeric.Sigma2Q64) != 0 || variance.Tau2Q64.Cmp(s.Numeric.Tau2Q64) != 0 {
				return primitiveVError()
			}
		} else {
			previous := s.VarianceGrid[i-1]
			comparison := previous.Sigma2Q64.Cmp(variance.Sigma2Q64)
			if comparison > 0 || (comparison == 0 && previous.Tau2Q64.Cmp(variance.Tau2Q64) >= 0) {
				return primitiveVError()
			}
		}
	}
	return nil
}

// For 0<=z<=1/3, log((1+z)/(1-z)) is the positive atanh series.
// The exact rational tail is bounded by
// 2*z^(2N+1)/((2N+1)*(1-z*z)); N=32 is fixed by the profile.
func groupedLMMMLAtanhBounds(z *big.Rat) (*big.Rat, *big.Rat) {
	square := new(big.Rat).Mul(z, z)
	power, lower := new(big.Rat).Set(z), new(big.Rat)
	for j := 0; j < 32; j++ {
		term := new(big.Rat).Mul(power, big.NewRat(2, int64(2*j+1)))
		lower.Add(lower, term)
		power.Mul(power, square)
	}
	tail := new(big.Rat).Mul(power, big.NewRat(2, 65))
	tail.Quo(tail, new(big.Rat).Sub(big.NewRat(1, 1), square))
	return lower, new(big.Rat).Add(lower, tail)
}

// Inputs here are PUBLIC exact variance/count table arguments in [1,2112].
// Reducing by powers of two gives 1<=m<2, hence z=(m-1)/(m+1)<1/3.
func groupedLMMMLLogBounds(x *big.Rat) (*big.Rat, *big.Rat, error) {
	if x == nil || x.Cmp(big.NewRat(1, 1)) < 0 || x.Cmp(big.NewRat(2112, 1)) > 0 {
		return nil, nil, primitiveVError()
	}
	m := new(big.Rat).Set(x)
	exponent := int64(0)
	for m.Cmp(big.NewRat(2, 1)) >= 0 {
		m.Quo(m, big.NewRat(2, 1))
		exponent++
	}
	z := new(big.Rat).Quo(new(big.Rat).Sub(m, big.NewRat(1, 1)), new(big.Rat).Add(m, big.NewRat(1, 1)))
	lower, upper := groupedLMMMLAtanhBounds(z)
	ln2Lower, ln2Upper := groupedLMMMLAtanhBounds(big.NewRat(1, 3))
	lower.Add(lower, new(big.Rat).Mul(big.NewRat(exponent, 1), ln2Lower))
	upper.Add(upper, new(big.Rat).Mul(big.NewRat(exponent, 1), ln2Upper))
	return lower, upper, nil
}

// D[n]=(n-1)log(4*sigma²)+log(4*(sigma²+n*tau²)), D[0]=0.
// This is log|V_n|+n*log(4), never a revealed cluster count. Each q64 table
// entry is rounded UP from a rational upper enclosure of width <2^-80;
// 0<=table/2^64-D[n]<2^-64+2^-80<2^-63. No binary floating log is used.
func groupedLMMMLLogTable(s groupedLMMSpec) ([]*big.Int, error) {
	if groupedLMMValidate(s) != nil {
		return nil, primitiveVError()
	}
	argument := func(value *big.Int) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Lsh(new(big.Int).Set(value), 2), primitiveVScale)
	}
	baseLower, baseUpper, err := groupedLMMMLLogBounds(argument(s.Sigma2Q64))
	if err != nil {
		return nil, err
	}
	table := make([]*big.Int, s.Slots+1)
	table[0] = new(big.Int)
	for n := 1; n <= s.Slots; n++ {
		value := new(big.Int).Add(s.Sigma2Q64, new(big.Int).Mul(big.NewInt(int64(n)), s.Tau2Q64))
		lower, upper, err := groupedLMMMLLogBounds(argument(value))
		if err != nil {
			return nil, err
		}
		lower.Add(lower, new(big.Rat).Mul(big.NewRat(int64(n-1), 1), baseLower))
		upper.Add(upper, new(big.Rat).Mul(big.NewRat(int64(n-1), 1), baseUpper))
		width := new(big.Rat).Sub(upper, lower)
		if width.Sign() < 0 || width.Cmp(new(big.Rat).SetFrac(big.NewInt(1), exactGCModulus(80))) >= 0 {
			return nil, primitiveVError()
		}
		scaled := new(big.Rat).Mul(upper, new(big.Rat).SetInt(primitiveVScale))
		ceiling, remainder := new(big.Int), new(big.Int)
		ceiling.QuoRem(scaled.Num(), scaled.Denom(), remainder)
		if remainder.Sign() > 0 {
			ceiling.Add(ceiling, big.NewInt(1))
		}
		if ceiling.Sign() < 0 || ceiling.Cmp(new(big.Int).Mul(big.NewInt(int64(12*n)), primitiveVScale)) >= 0 {
			return nil, primitiveVError()
		}
		table[n] = ceiling
	}
	return table, nil
}

func groupedLMMMLLogCompile(s groupedLMMSpec, table []*big.Int) (*primitiveVProgram, error) {
	if groupedLMMValidate(s) != nil || len(table) != s.Slots+1 {
		return nil, primitiveVError()
	}
	var source strings.Builder
	source.WriteString("package main\nfunc main(g [3]uint192,e [1]uint192) [2]uint192 {\nn:=g[0]+e[0]\nd:=uint192(0)\nv:=uint192(0)\n")
	for n, value := range table {
		if value == nil || value.Sign() < 0 || value.BitLen() > 73 {
			return nil, primitiveVError()
		}
		count := new(big.Int).Lsh(big.NewInt(int64(n)), 50)
		fmt.Fprintf(&source, "if n==uint192(%s) {d=uint192(%s)\nv=uint192(1)}\n", count, value)
	}
	source.WriteString("var out [2]uint192\nout[0]=d-g[1]\nout[1]=v-g[2]\nreturn out\n}\n")
	return primitiveVCompile(source.String(), 192, 3, 1, 2)
}

func groupedLMMBuildMLStagedGraph(s groupedLMMStagedSpec, role exactGCRole) (*groupedLMMStagedGraph, error) {
	// Pin caller-owned big integers/slices before capturing them in kernels.
	raw, err := json.Marshal(s)
	var pinned groupedLMMStagedSpec
	if err != nil || json.Unmarshal(raw, &pinned) != nil {
		return nil, primitiveVError()
	}
	s = pinned
	tables := make([][]*big.Int, len(s.VarianceGrid))
	for i, variance := range s.VarianceGrid {
		numeric := s.Numeric
		numeric.Sigma2Q64, numeric.Tau2Q64 = variance.Sigma2Q64, variance.Tau2Q64
		tables[i], err = groupedLMMMLLogTable(numeric)
		if err != nil {
			return nil, err
		}
	}
	// Public log entries AND their deterministic generating profile enter every
	// stage's receipt domain. Coefficient order is variance-major/beta-major.
	profile := crossGridStageHash(groupedLMMMLProfile, struct {
		Certificate string
		Spec        groupedLMMStagedSpec
		LogTables   [][]*big.Int
	}{groupedLMMMLCertificateSHA256, s, tables})
	graph := &groupedLMMStagedGraph{}
	countRows := s.Moments.Clusters * s.Moments.Slots * s.Moments.Columns
	add := func(plan crossGridStagePlan, compute crossGridStageCompute) {
		plan.ProfileDigest = profile
		plan.PublicBounds["variance_candidates"] = len(s.VarianceGrid)
		plan.PublicBounds["coefficient_candidates"] = len(s.Beta)
		graph.Plans = append(graph.Plans, plan)
		graph.Compute = append(graph.Compute, compute)
	}
	terminalIDs := make([]string, len(s.VarianceGrid))
	for varianceIndex, variance := range s.VarianceGrid {
		base := s
		base.Objective, base.VarianceGrid = "", nil
		base.Numeric.Sigma2Q64, base.Numeric.Tau2Q64 = variance.Sigma2Q64, variance.Tau2Q64
		base.Caps = s.Caps[varianceIndex*len(s.Beta) : (varianceIndex+1)*len(s.Beta)]
		quadratic, err := groupedLMMBuildStagedGraph(base, role)
		if err != nil {
			return nil, err
		}
		prefix := fmt.Sprintf("lmm.ml.variance.%03d", varianceIndex)
		ids := make(map[string]string)
		for _, plan := range quadratic.Plans {
			if plan.ID != "lmm.moments" && !strings.HasPrefix(plan.ID, "lmm.products.") {
				ids[plan.ID] = prefix + strings.TrimPrefix(plan.ID, "lmm")
			}
		}
		var terminal crossGridStagePlan
		var terminalCompute crossGridStageCompute
		for i, plan := range quadratic.Plans {
			shared := plan.ID == "lmm.moments" || strings.HasPrefix(plan.ID, "lmm.products.")
			if shared && varianceIndex > 0 {
				continue // Sufficient statistics and OT products are computed ONCE.
			}
			oldID := plan.ID
			if renamed, ok := ids[plan.ID]; ok {
				plan.ID = renamed
			}
			for j, previous := range plan.Predecessors {
				if renamed, ok := ids[previous]; ok {
					plan.Predecessors[j] = renamed
				}
			}
			if oldID == "lmm.terminal" {
				terminal, terminalCompute = plan, quadratic.Compute[i]
			} else {
				add(plan, quadratic.Compute[i])
			}
		}
		logID, objectiveID := prefix+".logdet", prefix+".objective"
		coordinates := make([]string, s.Moments.Clusters)
		for c := range coordinates {
			coordinates[c] = fmt.Sprintf("cluster:%d:shifted-log-determinant", c)
		}
		logPlan := crossGridStagePlan{ID: logID, Kind: "lmm.ml.private-count-logdet", Ring: 192, FPScale: 64,
			CoordOrder: coordinates, PublicBounds: map[string]int{"clusters": s.Moments.Clusters, "slots": s.Moments.Slots},
			SourceDigest: s.SourceDigest, Predecessors: []string{s.RoutedStage}}
		table, numeric := tables[varianceIndex], base.Numeric
		add(logPlan, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 1 {
				return crossGridStageOutput{}, primitiveVError()
			}
			rows, err := groupedLMMStagedWords(in[0], countRows)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			moments, err := groupedLMMPrepareMoments(s.Moments, rows)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			program, err := groupedLMMMLLogCompile(numeric, table)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			values, flags := make([]groupedWord, s.Moments.Clusters), append([]byte(nil), in[0].Validity...)
			for c := range values {
				out, err := groupedLMMStagedPrimitive(rw, attempt, role, fmt.Sprintf("ml-logdet/%d", c), profile, program,
					[]groupedWord{moments.Sums[c*s.Moments.Columns]})
				if err != nil {
					return crossGridStageOutput{}, err
				}
				values[c] = out[0]
				flags = append(flags, byte(out[1][0]&1))
			}
			return groupedLMMStagedOutput(rw, attempt, role, values, []crossGridStageOutput{{Validity: flags}})
		})
		// Copy the original wide-grid ABI, then add D[n] before any clamp or
		// quantization. q64 -> f264 is a linear Ring192 -> Ring384 map because
		// the multiplier 2^200 annihilates every possible Ring192 wrap carry.
		objective := quadratic.Plans[len(quadratic.Plans)-2]
		objective.ID, objective.Kind = objectiveID, "lmm.ml.shifted-negative-log-likelihood"
		objective.Predecessors = []string{ids["lmm.grid"], logID}
		add(objective, func(rw io.ReadWriter, attempt crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
			if len(in) != 2 {
				return crossGridStageOutput{}, primitiveVError()
			}
			grid, err := groupedLMMStagedWords(in[0], 2*s.Moments.Clusters*len(s.Beta))
			if err != nil {
				return crossGridStageOutput{}, err
			}
			logs, err := groupedLMMStagedWords(in[1], s.Moments.Clusters)
			if err != nil {
				return crossGridStageOutput{}, err
			}
			for c, value := range logs {
				for j := range s.Beta {
					i := 2*(c*len(s.Beta)+j) + 1
					grid[i] = grid[i].add(value.shl(8))
				}
			}
			return groupedLMMStagedOutput(rw, attempt, role, grid, in)
		})
		terminal.Predecessors = []string{objectiveID}
		terminal.Kind = "lmm.ml.certified-clamp-quantize-ring128"
		add(terminal, terminalCompute)
		terminalIDs[varianceIndex] = terminal.ID
	}
	coordinates := make([]string, len(s.Caps))
	for i := range coordinates {
		coordinates[i] = fmt.Sprintf("variance:%d:candidate:%d", i/len(s.Beta), i%len(s.Beta))
	}
	final := crossGridStagePlan{ID: "lmm.terminal", Kind: "lmm.ml.variance-major-loss-assembly", Ring: 128, FPScale: s.Numeric.GridBits,
		CoordOrder: coordinates, PublicBounds: map[string]int{"clusters": s.Moments.Clusters, "slots": s.Moments.Slots, "candidates": len(s.Caps)},
		SourceDigest: s.SourceDigest, Predecessors: terminalIDs}
	add(final, func(_ io.ReadWriter, _ crossGridStageAttempt, in []crossGridStageOutput) (crossGridStageOutput, error) {
		if len(in) != len(s.VarianceGrid) {
			return crossGridStageOutput{}, primitiveVError()
		}
		output := crossGridStageOutput{}
		for _, value := range in {
			if len(value.Share) != 16*len(s.Beta) || len(value.Validity) != len(s.Beta) {
				return crossGridStageOutput{}, primitiveVError()
			}
			output.Share = append(output.Share, value.Share...)
			output.Validity = append(output.Validity, value.Validity...)
		}
		return output, nil
	})
	return graph, nil
}
