package main

import (
	"github.com/markkurossi/mpc/compiler"
	"math/big"
	"strings"
	"testing"
)

func dpIRLSStageUnitPlan(t testing.TB, family string, rows int) dpIRLSStagePlan {
	t.Helper()
	c, err := dpIRLSProducerCertificate(family, 3, rows, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := dpIRLSStagePlan{Beta: []string{"16384", "-32768", "65536"}, CertificateDigest: dpIRLSProducerCertificateDigest(c), Family: family, OffsetMode: "offset", Owners: 2, P: 3, Predecessor: strings.Repeat("1", 64), Purpose: "optimizer", Root: strings.Repeat("2", 64), Rows: rows, StageID: strings.Repeat("3", 64), StageIndex: 0, Version: dpIRLSStageVersion}
	p.PointDigest = p.pointDigest()
	return p
}

func TestDPIRLSStagePlanBinding(t *testing.T) {
	p := dpIRLSStageUnitPlan(t, "binomial", 1)
	k, err := dpIRLSStageKernelPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	before := k.purpose()
	p.Beta[0] = "0"
	if k.purpose() != before {
		t.Fatal("kernel plan aliases caller beta")
	}
	altered := *k.IRLS
	altered.Beta = append([]string(nil), altered.Beta...)
	altered.Beta[0] = "0"
	if altered.validate() == nil {
		t.Fatal("alternate point accepted without binding")
	}
	for _, edit := range []func(*dpIRLSStagePlan){func(p *dpIRLSStagePlan) { p.Rows = 65 }, func(p *dpIRLSStagePlan) { p.P = 5 }, func(p *dpIRLSStagePlan) { p.OffsetMode = "exposure" }, func(p *dpIRLSStagePlan) { p.CertificateDigest = strings.Repeat("0", 64) }, func(p *dpIRLSStagePlan) { p.Predecessor = strings.Repeat("4", 64) }} {
		altered = *k.IRLS
		edit(&altered)
		if altered.validate() == nil {
			t.Fatal("uncertified plan accepted")
		}
	}
	k.Family = "binomial"
	if k.validate() == nil {
		t.Fatal("ambiguous grid/IRLS plan accepted")
	}
}

func TestDPIRLSStageCompileSmoke(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		p := dpIRLSStageUnitPlan(t, family, 1)
		k, err := dpIRLSStageKernelPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := crossGridKernelPrepare(k)
		if err != nil {
			t.Fatal(family, err)
		}
		t.Logf("family=%s rows=1 gates=%d wires=%d inputs=%d", family, prepared.circuit.NumGates, prepared.circuit.NumWires, prepared.circuit.Inputs.Size())
	}
}

// The generic RPC compiler must never acquire an implementation for this
// purpose-bound producer, and even the internal runner rejects another point
// before it consumes any private source or starts an OT transcript.
func TestDPIRLSStagePrivateOnlySurface(t *testing.T) {
	p := dpIRLSStageUnitPlan(t, "binomial", 1)
	plan, err := dpIRLSStageKernelPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	spec := exactGCCircuitSpec{Operation: dpIRLSStageOperation, RingBits: 128, VectorLen: 9}
	if _, err := exactGCCompileCircuit(spec); err == nil {
		t.Fatal("ordinary compiler accepted internal producer")
	}
	k, err := crossGridKernelPrepare(plan)
	if err != nil {
		t.Fatal(err)
	}
	if k.circuit.Outputs.Size() != 128*10 {
		t.Fatal("producer must return nine masked aggregates and one masked validity only")
	}
	session := exactGCTestSession(spec)
	session.Purpose = plan.purpose() + "-other-point"
	if _, err := k.runWithSeed(dpIRLSStageNoIO{}, session, nil, exactGCRoleGarbler, nil); err == nil {
		t.Fatal("alternate purpose accepted")
	}
	if _, err := crossGridKernelPrivateInput(plan, nil, true); err == nil {
		t.Fatal("missing private input accepted")
	}
}

type dpIRLSStageNoIO struct{}

func (dpIRLSStageNoIO) Read([]byte) (int, error) { panic("rejected public point attempted private IO") }
func (dpIRLSStageNoIO) Write([]byte) (int, error) {
	panic("rejected public point attempted private IO")
}

func TestDPIRLSStageSourceClamp128(t *testing.T) {
	source := "package main\n" + dpIRLSClampUnitSource() + "func main(g uint128,e uint128) int32 { return irlsClampUnit(g+e) }\n"
	c, _, err := compiler.New(crossGridPWCompilerParams()).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	minimum := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	values := []*big.Int{minimum, big.NewInt(-65537), big.NewInt(-65536), big.NewInt(-1), big.NewInt(0), big.NewInt(1), big.NewInt(65536), big.NewInt(65537), maximum}
	for _, value := range values {
		left := new(big.Int).Sub(exactGCModulus(128), big.NewInt(170001))
		right := new(big.Int).Mod(new(big.Int).Sub(value, left), exactGCModulus(128))
		got, err := c.Compute([]*big.Int{left, right})
		if err != nil {
			t.Fatal(err)
		}
		want := int64(0)
		switch {
		case value.Cmp(big.NewInt(-65536)) < 0:
			want = -65536
		case value.Cmp(big.NewInt(65536)) > 0:
			want = 65536
		default:
			want = value.Int64()
		}
		if int64(int32(got[0].Uint64())) != want {
			t.Fatalf("clamp(%s)=%s; want %d", value, got[0], want)
		}
	}
}
