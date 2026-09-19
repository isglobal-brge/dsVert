package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGroupedGEEPrivateFactorProtocol(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		for _, cor := range []string{"independence", "exchangeable", "ar1"} {
			t.Run(family+"/"+cor, func(t *testing.T) {
				s := groupedGEESpec{Slots: 3, Predictors: 1, GridBits: 16, Family: family, Correlation: cor, ScoreClipQ16: 65536, RowLossCap: 10000000, BreadCap: 100000000, MaxOutcome: 1}
				if family == "poisson" {
					s.MaxOutcome = 4
				}
				if cor != "independence" {
					s.RhoQ16 = 32768
				}
				rows := []groupedGEERow{
					{new(big.Int).Lsh(big.NewInt(-3), 64), []*big.Int{new(big.Int).Lsh(big.NewInt(1), 49)}, s.MaxOutcome, 1},
					{new(big.Int).Lsh(big.NewInt(99), 64), []*big.Int{big.NewInt(-10)}, 99, 0},
					{new(big.Int).Lsh(big.NewInt(2), 64), []*big.Int{new(big.Int).Lsh(big.NewInt(1), 50)}, 0, 1},
				}
				if family == "poisson" {
					rows[0].Outcome = 3
				}
				if family == "poisson" && cor == "ar1" {
					s.Predictors = 3
					for i := range rows {
						rows[i].FeaturesF50 = append(rows[i].FeaturesF50, big.NewInt(1), new(big.Int).Lsh(big.NewInt(3), 48))
					}
				}
				raw := []groupedWord{}
				for _, row := range rows {
					raw = append(raw, groupedWordFromBig(new(big.Int).Lsh(new(big.Int).Set(row.EtaQ64), 36)))
					for _, feature := range row.FeaturesF50 {
						raw = append(raw, groupedWordFromBig(feature))
					}
					raw = append(raw, groupedWordFromBig(big.NewInt(row.Outcome)), groupedWordFromBig(big.NewInt(row.Live)))
				}
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				left.SetDeadline(time.Now().Add(3 * time.Minute))
				right.SetDeadline(time.Now().Add(3 * time.Minute))
				a, b := make([]groupedWord, len(raw)), make([]groupedWord, len(raw))
				for i, v := range raw {
					m, err := groupedRandomWord()
					if err != nil {
						t.Fatal(err)
					}
					a[i] = m
					b[i] = v.sub(m)
				}
				session := exactGCTestSession(exactGCCircuitSpec{Operation: exactGCPrimitiveV, RingBits: 192, VectorLen: 1})
				contract := sha256.Sum256([]byte("synthetic GEE whitening producer"))
				type result struct {
					value *groupedGEEFactorResult
					err   error
				}
				ch := make(chan result, 1)
				l, r := &primitiveVCountingRW{Conn: left}, &primitiveVCountingRW{Conn: right}
				start := time.Now()
				go func() {
					v, err := groupedGEEProduceFactors(l, session, exactGCRoleGarbler, contract, s, a)
					if err != nil {
						left.Close()
					}
					ch <- result{v, err}
				}()
				v, err := groupedGEEProduceFactors(r, session, exactGCRoleEvaluator, contract, s, b)
				if err != nil {
					right.Close()
				}
				peer := <-ch
				if err != nil || peer.err != nil {
					t.Fatalf("factor protocol %v / %v", peer.err, err)
				}
				t.Logf("factor_producer_bytes=%d seconds=%.6f", l.Written+r.Written, time.Since(start).Seconds())
				if peer.value.ScheduleSHA256 != v.ScheduleSHA256 || v.ScheduleSHA256 == ([32]byte{}) || v.Certificate.Profile != groupedGEEWhiteningProfile {
					t.Fatal("profile binding")
				}
				valid := peer.value.Valid.add(v.Valid)
				if valid != (groupedWord{1, 0, 0}) {
					t.Fatal("validity")
				}
				factors := make([]groupedWord, len(v.Factors))
				for i := range factors {
					factors[i] = v.Factors[i].add(peer.value.Factors[i])
				}
				x, y, err := groupedGEEMomentOperands(s, factors)
				if err != nil {
					t.Fatal(err)
				}
				product := func(x, y []groupedWord) []groupedWord {
					out := make([]groupedWord, len(x))
					for i := range x {
						out[i] = x[i].mul(y[i])
					}
					return out
				}
				sums, err := groupedGEEMomentSums(s, product(x, y))
				if err != nil {
					t.Fatal(err)
				}
				args := make([]*big.Int, 0, len(sums)+1)
				for _, w := range sums {
					args = append(args, groupedWordInteger(w))
				}
				args = append(args, big.NewInt(1))
				boundary, err := groupedGEEMomentBoundaryCompile(s)
				if err != nil {
					t.Fatal(err)
				}
				out := groupedGEETestBoundary(t, boundary, args, len(args))
				d := s.Predictors + 1
				tri := d * (d + 1) / 2
				clips := make([]groupedWord, d)
				for i := range clips {
					clips[i] = groupedWordFromBig(out[i])
				}
				x, y, err = groupedGEEMeatOperands(s, clips)
				if err != nil {
					t.Fatal(err)
				}
				args = nil
				for _, w := range product(x, y) {
					args = append(args, groupedWordInteger(w))
				}
				args = append(args, big.NewInt(1))
				meatProgram, err := groupedGEEMeatFinalCompile(s)
				if err != nil {
					t.Fatal(err)
				}
				meat := groupedGEETestBoundary(t, meatProgram, args, len(args))
				likelihoodProgram, err := groupedGEELikelihoodCompile(s, 100000000)
				if err != nil {
					t.Fatal(err)
				}
				likelihood := groupedGEETestBoundary(t, likelihoodProgram, []*big.Int{groupedWordInteger(v.Likelihood.add(peer.value.Likelihood)), big.NewInt(1)}, 2)
				got := []int64{likelihood[0].Int64()}
				for _, z := range out[d : d+tri] {
					got = append(got, z.Int64())
				}
				for _, z := range meat[:tri] {
					got = append(got, z.Int64())
				}
				want, ok := groupedGEEWhiteningOracle(s, rows, 100000000)
				if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("integer composition got=%v want=%v valid=%v", got, want, ok)
				}
			})
		}
	}
}
