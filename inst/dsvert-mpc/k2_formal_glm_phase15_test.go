package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/markkurossi/mpc/circuit"
)

type formalGLMPhase15TestIdentities struct {
	public  map[string]ed25519.PublicKey
	private map[string]ed25519.PrivateKey
}

func formalGLMPhase15TestPolicy(family string, custodians, block,
	coefficients int) formalGLMPhase1Policy {
	policy := formalGLMTestExpandedPolicy(family, block, coefficients)
	policy.CustodianPeers = make([]string, custodians)
	for i := range policy.CustodianPeers {
		policy.CustodianPeers[i] = "peer-" + string(rune('a'+i))
	}
	policy.ComputePeers = []string{"peer-a", "peer-b"}
	return policy
}

func formalGLMPhase15TestOwners(policy formalGLMPhase1Policy) []string {
	result := make([]string, policy.CoefficientCount+3)
	for i := range result {
		result[i] = policy.CustodianPeers[i%len(policy.CustodianPeers)]
	}
	return result
}

func formalGLMPhase15TestPlan(t testing.TB, family string, custodians,
	block, coefficients, total, iterations int) formalGLMPhase15Plan {
	t.Helper()
	policy := formalGLMPhase15TestPolicy(family, custodians, block, coefficients)
	runID := sha256.Sum256([]byte("phase15-plan/" + t.Name()))
	plan, err := buildFormalGLMPhase15Plan(policy, total, iterations,
		formalGLMPhase15TestOwners(policy), hexString(runID[:]))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func hexString(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for i, b := range value {
		result[2*i], result[2*i+1] = digits[b>>4], digits[b&15]
	}
	return string(result)
}

func formalGLMPhase15TestIsolatedCircuitCache(t testing.TB) {
	t.Helper()
	formalGLMPhase15CircuitCache.Lock()
	previousEntries := formalGLMPhase15CircuitCache.entries
	previousFlights := formalGLMPhase15CircuitCache.flights
	previousOrder := formalGLMPhase15CircuitCache.order
	formalGLMPhase15CircuitCache.entries = make(map[string]*circuit.Circuit)
	formalGLMPhase15CircuitCache.flights = make(map[string]*formalGLMPhase15CircuitFlight)
	formalGLMPhase15CircuitCache.order = nil
	formalGLMPhase15CircuitCache.Unlock()
	t.Cleanup(func() {
		formalGLMPhase15CircuitCache.Lock()
		formalGLMPhase15CircuitCache.entries = previousEntries
		formalGLMPhase15CircuitCache.flights = previousFlights
		formalGLMPhase15CircuitCache.order = previousOrder
		formalGLMPhase15CircuitCache.Unlock()
	})
}

func TestFormalGLMPhase15CircuitCompileCoalesces(t *testing.T) {
	formalGLMPhase15TestIsolatedCircuitCache(t)

	started := make(chan struct{})
	release := make(chan struct{})
	secondEntered := make(chan struct{})
	var calls atomic.Int32
	compile := func(string) (*circuit.Circuit, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return &circuit.Circuit{}, nil
	}
	type result struct {
		circ *circuit.Circuit
		err  error
	}
	results := make(chan result, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		circ, err := compileFormalGLMPhase15SourceWith("package main", "test", compile)
		results <- result{circ: circ, err: err}
	}()
	<-started
	go func() {
		defer workers.Done()
		close(secondEntered)
		circ, err := compileFormalGLMPhase15SourceWith("package main", "test", compile)
		results <- result{circ: circ, err: err}
	}()
	<-secondEntered
	for index := 0; index < 128; index++ {
		runtime.Gosched()
	}
	if calls.Load() != 1 {
		close(release)
		workers.Wait()
		t.Fatalf("identical circuit compiled %d times", calls.Load())
	}
	close(release)
	workers.Wait()
	close(results)
	for value := range results {
		if value.err != nil || value.circ == nil {
			t.Fatalf("coalesced compile failed: circuit=%v error=%v", value.circ, value.err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("identical circuit compiled %d times", calls.Load())
	}
}

func TestFormalGLMPhase15CircuitCompileFailureDoesNotPoisonCache(t *testing.T) {
	formalGLMPhase15TestIsolatedCircuitCache(t)

	var calls atomic.Int32
	compile := func(string) (*circuit.Circuit, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("expected compiler failure")
		}
		return &circuit.Circuit{}, nil
	}
	if circ, err := compileFormalGLMPhase15SourceWith("package main", "test", compile); err == nil || circ != nil {
		t.Fatalf("failing compile returned circuit=%v error=%v", circ, err)
	}
	circ, err := compileFormalGLMPhase15SourceWith("package main", "test", compile)
	if err != nil || circ == nil || calls.Load() != 2 {
		t.Fatalf("cache retained a compiler failure: circuit=%v calls=%d error=%v", circ, calls.Load(), err)
	}
}

func TestFormalGLMPhase15CircuitCacheRetainsRecentPublicSources(t *testing.T) {
	formalGLMPhase15TestIsolatedCircuitCache(t)
	const expectedEntries = 8

	var calls atomic.Int32
	compile := func(string) (*circuit.Circuit, error) {
		calls.Add(1)
		return &circuit.Circuit{}, nil
	}
	compileSource := func(source string) {
		t.Helper()
		circ, err := compileFormalGLMPhase15SourceWith(source, "test", compile)
		if err != nil || circ == nil {
			t.Fatalf("compile %q: circuit=%v error=%v", source, circ, err)
		}
	}

	for index := 0; index < expectedEntries; index++ {
		compileSource(fmt.Sprintf("package source%d", index))
	}
	if calls.Load() != expectedEntries {
		t.Fatalf("initial public sources compiled %d times", calls.Load())
	}
	compileSource("package source0")
	if calls.Load() != expectedEntries {
		t.Fatalf("recent public source was evicted: calls=%d", calls.Load())
	}
	compileSource("package source8")
	compileSource("package source0")
	if calls.Load() != expectedEntries+1 {
		t.Fatalf("most-recent public source was evicted: calls=%d", calls.Load())
	}
	compileSource("package source1")
	if calls.Load() != expectedEntries+2 {
		t.Fatalf("least-recent public source was not evicted: calls=%d", calls.Load())
	}
	formalGLMPhase15CircuitCache.Lock()
	defer formalGLMPhase15CircuitCache.Unlock()
	if len(formalGLMPhase15CircuitCache.entries) != expectedEntries ||
		len(formalGLMPhase15CircuitCache.order) != expectedEntries {
		t.Fatalf("circuit cache is not bounded: entries=%d order=%d",
			len(formalGLMPhase15CircuitCache.entries),
			len(formalGLMPhase15CircuitCache.order))
	}
	seen := make(map[string]bool, expectedEntries)
	for _, key := range formalGLMPhase15CircuitCache.order {
		if seen[key] || formalGLMPhase15CircuitCache.entries[key] == nil {
			t.Fatalf("circuit cache order diverged")
		}
		seen[key] = true
	}
}

func formalGLMPhase15TestIdentitySet(t testing.TB,
	peers []string) formalGLMPhase15TestIdentities {
	t.Helper()
	result := formalGLMPhase15TestIdentities{
		public:  make(map[string]ed25519.PublicKey, len(peers)),
		private: make(map[string]ed25519.PrivateKey, len(peers)),
	}
	for _, peer := range peers {
		publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		result.public[peer], result.private[peer] = publicKey, privateKey
	}
	return result
}

func formalGLMPhase15TestApprovals(t testing.TB, plan formalGLMPhase15Plan,
	identities formalGLMPhase15TestIdentities) []formalGLMPhase15Approval {
	t.Helper()
	result := make([]formalGLMPhase15Approval, len(plan.Kernel.CustodianPeers))
	for i, peer := range plan.Kernel.CustodianPeers {
		approval, err := formalGLMPhase15SignPlan(plan, peer, identities.private[peer])
		if err != nil {
			t.Fatal(err)
		}
		result[i] = approval
	}
	return result
}

func formalGLMPhase15TestInput(plan formalGLMPhase15Plan) []*big.Int {
	p := plan.Kernel.CoefficientCount
	result := make([]*big.Int, 0, plan.TotalCapacity*(p+3))
	for row := 0; row < plan.TotalCapacity; row++ {
		result = append(result, big.NewInt(256))
		for j := 0; j < p; j++ {
			value := int64(256)
			if j == 1 && row%2 == 0 {
				value = 0
			} else if j > 1 && row%2 == 0 {
				value = -128
			}
			result = append(result, formalGLMResidue(big.NewInt(value), plan.RingBits))
		}
		outcome := int64((row % 2) * 256)
		if plan.Kernel.Family == "poisson" {
			outcome = int64((row % 3) * 256)
		}
		result = append(result, big.NewInt(outcome),
			formalGLMResidue(big.NewInt(int64((row%3-1)*64)), plan.RingBits))
	}
	return result
}

func formalGLMPhase15TestBlock(plan formalGLMPhase15Plan, complete []*big.Int,
	block int) []*big.Int {
	coordinates := plan.Kernel.CoefficientCount + 3
	result := make([]*big.Int, plan.BlockCapacity*coordinates)
	for i := range result {
		result[i] = new(big.Int)
		row := block*plan.BlockCapacity + i/coordinates
		if row < plan.TotalCapacity {
			result[i].Set(complete[row*coordinates+i%coordinates])
		}
	}
	return result
}

func formalGLMPhase15Unpack(value *big.Int, count, ringBits int) []*big.Int {
	result := make([]*big.Int, count)
	stride := exactGCTypeBits(ringBits)
	for i := range result {
		result[i] = new(big.Int).Rsh(new(big.Int).Set(value), uint(i*stride))
		result[i].And(result[i], exactGCMask(ringBits))
	}
	return result
}

func formalGLMPhase15DirectExecute(plan formalGLMPhase15Plan, input []*big.Int,
	rng *rand.Rand) ([]*big.Int, error) {
	blockCircuit, err := compileFormalGLMPhase15Block(plan)
	if err != nil {
		return nil, err
	}
	finalCircuit, err := compileFormalGLMPhase15Finalize(plan)
	if err != nil {
		return nil, err
	}
	p := plan.Kernel.CoefficientCount
	betaG, betaE := make([]*big.Int, p), make([]*big.Int, p)
	for j := 0; j < p; j++ {
		betaG[j], betaE[j] = new(big.Int), new(big.Int)
	}
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		gradientG, gradientE := make([]*big.Int, p), make([]*big.Int, p)
		for j := 0; j < p; j++ {
			gradientG[j], gradientE[j] = new(big.Int), new(big.Int)
		}
		for block := 0; block < plan.TotalBlocks; block++ {
			secretBlock := formalGLMPhase15TestBlock(plan, input, block)
			rowG, rowE := exactGCTestSplit(rng, secretBlock, plan.RingBits)
			localG := append(append(append([]*big.Int{}, rowG...), betaG...), gradientG...)
			localE := append(append(append([]*big.Int{}, rowE...), betaE...), gradientE...)
			masks := make([]*big.Int, 2*p)
			for j := range masks {
				masks[j] = exactGCTestRandomResidue(rng, plan.RingBits)
			}
			packed, err := blockCircuit.Compute([]*big.Int{
				exactGCPackChunks(append(append([]*big.Int{}, localG...), masks...),
					plan.ContainerBits),
				exactGCPackChunks(localE, plan.ContainerBits),
			})
			if err != nil || len(packed) != 1 {
				if err == nil {
					err = errors.New("formal-glm: unexpected direct block output arity")
				}
				return nil, err
			}
			decoded := formalGLMPhase15Unpack(packed[0], 2*p, plan.RingBits)
			betaG, betaE = append([]*big.Int(nil), masks[:p]...),
				append([]*big.Int(nil), decoded[:p]...)
			gradientG, gradientE = append([]*big.Int(nil), masks[p:]...),
				append([]*big.Int(nil), decoded[p:]...)
		}
		localG := append(append([]*big.Int{}, betaG...), gradientG...)
		localE := append(append([]*big.Int{}, betaE...), gradientE...)
		masks := make([]*big.Int, p)
		for j := range masks {
			masks[j] = exactGCTestRandomResidue(rng, plan.RingBits)
		}
		packed, err := finalCircuit.Compute([]*big.Int{
			exactGCPackChunks(append(append([]*big.Int{}, localG...), masks...),
				plan.ContainerBits),
			exactGCPackChunks(localE, plan.ContainerBits),
		})
		if err != nil || len(packed) != 1 {
			if err == nil {
				err = errors.New("formal-glm: unexpected direct finalizer output arity")
			}
			return nil, err
		}
		betaG, betaE = masks, formalGLMPhase15Unpack(packed[0], p, plan.RingBits)
	}
	result := make([]*big.Int, p)
	for j := range result {
		result[j] = exactGCReferenceReconstruct(betaG[j], betaE[j], plan.RingBits)
	}
	return result, nil
}

func TestFormalGLMPhase15PlanIsFixedBoundedAndUnanimousForK2K3K5(t *testing.T) {
	for _, k := range []int{2, 3, 5} {
		t.Run(string(rune('0'+k))+" custodians", func(t *testing.T) {
			plan := formalGLMPhase15TestPlan(t, "binomial", k, 2, 2, 5, 3)
			if err := validateFormalGLMPhase15Plan(plan); err != nil {
				t.Fatal(err)
			}
			if plan.TotalBlocks != (plan.TotalCapacity+plan.BlockCapacity-1)/plan.BlockCapacity ||
				plan.ScheduleSteps != plan.Iterations*(plan.TotalBlocks+1) ||
				plan.BlockCost.EstimatedWorkingByte > formalGLMPhase15MaxEstimatedWorkingBytes ||
				plan.FinalizeCost.EstimatedWorkingByte > formalGLMPhase15MaxEstimatedWorkingBytes ||
				plan.ProductionReady {
				t.Fatalf("invalid public plan: %+v", plan)
			}
			identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
			approvals := formalGLMPhase15TestApprovals(t, plan, identities)
			if err := formalGLMPhase15VerifyPlanApprovals(plan, approvals,
				identities.public); err != nil {
				t.Fatal(err)
			}
			if err := formalGLMPhase15VerifyPlanApprovals(plan,
				approvals[:len(approvals)-1], identities.public); err == nil {
				t.Fatal("plan without unanimous custodian approval was accepted")
			}
			changed := plan
			changed.TotalCapacity++
			if err := formalGLMPhase15VerifyPlanApprovals(changed, approvals,
				identities.public); err == nil {
				t.Fatal("approval was replayed on a changed plan")
			}
		})
	}
}

func TestFormalGLMPhase15PlannerUsesDynamicRingAndFailsTypedBeyond4096(t *testing.T) {
	policy := formalGLMPhase15TestPolicy("binomial", 2, 2, 1)
	policy.CoefficientBox = []string{
		new(big.Int).Lsh(big.NewInt(1), 150).String(),
	}
	policy.XKind = []string{"numeric"}
	policy.XLower, policy.XUpper = []string{"0"}, []string{"0"}
	policy.LinkKnots = []string{"-512", "0", "512"}
	policy.LinkValues = []string{"128", "128", "128"}
	policy.LinkSlopes = []string{"0", "0"}
	run := sha256.Sum256([]byte("phase15-dynamic-ring"))
	plan, err := buildFormalGLMPhase15Plan(policy, 3, 2,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	if err != nil {
		t.Fatal(err)
	}
	if plan.RingBits <= 128 || plan.RingBits > exactGCMaxRingBits ||
		plan.ContainerBits != 256 {
		t.Fatalf("dynamic ring was not selected: %+v", plan)
	}

	policy = formalGLMPhase15TestPolicy("poisson", 2, 1, 1)
	huge := "1" + strings.Repeat("0", 1199)
	policy.WeightUpper, policy.OutcomeUpper = huge, huge
	policy.LinkValues = []string{huge, huge, huge}
	policy.LinkSlopes = []string{"0", "0"}
	_, err = buildFormalGLMPhase15Plan(policy, 1, 2,
		formalGLMPhase15TestOwners(policy), hexString(run[:]))
	var typed *formalGLMNumericBackendError
	if !errors.As(err, &typed) || typed.Code != "numeric_backend_unrepresentable" ||
		typed.RequiredBits <= exactGCMaxRingBits {
		t.Fatalf("expected typed Ring4096 failure, got %T %v", err, err)
	}
}

func TestFormalGLMPhase15SignedFanInIsCompletePairedAndDurable(t *testing.T) {
	for _, k := range []int{2, 3, 5} {
		t.Run(string(rune('0'+k))+" custodians", func(t *testing.T) {
			plan := formalGLMPhase15TestPlan(t, "binomial", k, 1, 1, 2, 2)
			identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
			approvals := formalGLMPhase15TestApprovals(t, plan, identities)
			curve := ecdh.X25519()
			recipientSecret := make(map[string][]byte, 2)
			recipientPublic := make(map[string][]byte, 2)
			for _, peer := range plan.Kernel.ComputePeers {
				key, err := curve.GenerateKey(crand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				recipientSecret[peer] = key.Bytes()
				recipientPublic[peer] = key.PublicKey().Bytes()
			}
			complete := formalGLMPhase15TestInput(plan)
			block := formalGLMPhase15TestBlock(plan, complete, 0)
			byRecipient := map[string][]formalGLMPhase15SourceEnvelope{
				plan.Kernel.ComputePeers[0]: {}, plan.Kernel.ComputePeers[1]: {},
			}
			for _, custodian := range plan.Kernel.CustodianPeers {
				local := make([]*big.Int, len(block))
				for i := range local {
					local[i] = new(big.Int)
					if plan.CoordinateOwners[i%(plan.Kernel.CoefficientCount+3)] == custodian {
						local[i].Set(block[i])
					}
				}
				envelopes, err := formalGLMPhase15ProduceBlock(plan, approvals,
					identities.public, custodian, identities.private[custodian],
					recipientPublic, 0, local)
				if err != nil {
					t.Fatal(err)
				}
				for _, envelope := range envelopes {
					byRecipient[envelope.Recipient] = append(
						byRecipient[envelope.Recipient], envelope)
				}
			}
			// Arrival order is irrelevant; semantic ordering is signed.
			for _, envelopes := range byRecipient {
				sort.Slice(envelopes, func(i, j int) bool {
					return envelopes[i].Custodian > envelopes[j].Custodian
				})
			}
			var ledgerKey [32]byte
			ledgerKey = sha256.Sum256([]byte("phase15-ledger/" + t.Name()))
			ledgers := make(map[string]*formalGLMPhase15ReplayLedger, 2)
			ledgerDirs := make(map[string]string, 2)
			results := make(map[string]formalGLMPhase15FanInResult, 2)
			for _, peer := range plan.Kernel.ComputePeers {
				ledgerDirs[peer] = filepath.Join(t.TempDir(), peer)
				ledger, err := newFormalGLMPhase15DurableReplayLedger(
					ledgerDirs[peer], ledgerKey)
				if err != nil {
					t.Fatal(err)
				}
				ledgers[peer] = ledger
				results[peer], err = formalGLMPhase15FanIn(plan, approvals,
					identities.public, peer, recipientSecret[peer], 0,
					byRecipient[peer], ledger)
				if err != nil {
					t.Fatal(err)
				}
			}
			left, right := results[plan.Kernel.ComputePeers[0]],
				results[plan.Kernel.ComputePeers[1]]
			if err := formalGLMPhase15ValidatePairedFanIn(plan, left, right); err != nil {
				t.Fatal(err)
			}
			for i := range block {
				got := exactGCReferenceReconstruct(left.Shares[i], right.Shares[i],
					plan.RingBits)
				if got.Cmp(block[i]) != 0 {
					t.Fatalf("coordinate %d reconstructed %s, want %s", i, got,
						block[i])
				}
			}
			// Restarting the ledger and retrying byte-identical envelopes is
			// idempotent, not a request-count failure.
			for _, peer := range plan.Kernel.ComputePeers {
				restarted, err := newFormalGLMPhase15DurableReplayLedger(
					ledgerDirs[peer], ledgerKey)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := formalGLMPhase15FanIn(plan, approvals,
					identities.public, peer, recipientSecret[peer], 0,
					byRecipient[peer], restarted); err != nil {
					t.Fatalf("identical durable retry failed: %v", err)
				}
			}
			// A signed reroll for the same semantic slot is a conflict even
			// across restart; accepting it could change the reconstructed input.
			custodian := plan.Kernel.CustodianPeers[0]
			local := make([]*big.Int, len(block))
			for i := range local {
				local[i] = new(big.Int)
				if plan.CoordinateOwners[i%(plan.Kernel.CoefficientCount+3)] == custodian {
					local[i].Set(block[i])
				}
			}
			reroll, err := formalGLMPhase15ProduceBlock(plan, approvals,
				identities.public, custodian, identities.private[custodian],
				recipientPublic, 0, local)
			if err != nil {
				t.Fatal(err)
			}
			peer := plan.Kernel.ComputePeers[0]
			conflicting := append([]formalGLMPhase15SourceEnvelope(nil),
				byRecipient[peer]...)
			for i := range conflicting {
				if conflicting[i].Custodian == custodian {
					conflicting[i] = reroll[0]
				}
			}
			if _, err := formalGLMPhase15FanIn(plan, approvals, identities.public,
				peer, recipientSecret[peer], 0, conflicting, ledgers[peer]); err == nil {
				t.Fatal("conflicting signed replay was accepted")
			}
		})
	}
}

func TestFormalGLMPhase15FanInRejectsTamperOmissionAndPairMixing(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 3, 1, 1, 1, 2)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.CustodianPeers)
	approvals := formalGLMPhase15TestApprovals(t, plan, identities)
	curve := ecdh.X25519()
	secret := make(map[string][]byte, 2)
	public := make(map[string][]byte, 2)
	for _, peer := range plan.Kernel.ComputePeers {
		key, _ := curve.GenerateKey(crand.Reader)
		secret[peer], public[peer] = key.Bytes(), key.PublicKey().Bytes()
	}
	block := formalGLMPhase15TestBlock(plan, formalGLMPhase15TestInput(plan), 0)
	byRecipient := map[string][]formalGLMPhase15SourceEnvelope{
		plan.Kernel.ComputePeers[0]: {}, plan.Kernel.ComputePeers[1]: {},
	}
	for _, custodian := range plan.Kernel.CustodianPeers {
		local := make([]*big.Int, len(block))
		for i := range local {
			local[i] = new(big.Int)
			if plan.CoordinateOwners[i%(plan.Kernel.CoefficientCount+3)] == custodian {
				local[i].Set(block[i])
			}
		}
		envelopes, err := formalGLMPhase15ProduceBlock(plan, approvals,
			identities.public, custodian, identities.private[custodian], public, 0, local)
		if err != nil {
			t.Fatal(err)
		}
		for _, envelope := range envelopes {
			byRecipient[envelope.Recipient] = append(byRecipient[envelope.Recipient], envelope)
		}
	}
	peer := plan.Kernel.ComputePeers[0]
	tampered := append([]formalGLMPhase15SourceEnvelope(nil), byRecipient[peer]...)
	tampered[0].Ciphertext = append([]byte(nil), tampered[0].Ciphertext...)
	tampered[0].Ciphertext[len(tampered[0].Ciphertext)-1] ^= 1
	if _, err := formalGLMPhase15FanIn(plan, approvals, identities.public,
		peer, secret[peer], 0, tampered, newFormalGLMPhase15ReplayLedger()); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if _, err := formalGLMPhase15FanIn(plan, approvals, identities.public,
		peer, secret[peer], 0, byRecipient[peer][:2],
		newFormalGLMPhase15ReplayLedger()); err == nil {
		t.Fatal("incomplete fan-in was accepted")
	}
	left, err := formalGLMPhase15FanIn(plan, approvals, identities.public,
		peer, secret[peer], 0, byRecipient[peer], newFormalGLMPhase15ReplayLedger())
	if err != nil {
		t.Fatal(err)
	}
	rightPeer := plan.Kernel.ComputePeers[1]
	right, err := formalGLMPhase15FanIn(plan, approvals, identities.public,
		rightPeer, secret[rightPeer], 0, byRecipient[rightPeer],
		newFormalGLMPhase15ReplayLedger())
	if err != nil {
		t.Fatal(err)
	}
	right.PairCommitment[plan.Kernel.CustodianPeers[0]] =
		sha256Hex([]byte("mixed pair"))
	if err := formalGLMPhase15ValidatePairedFanIn(plan, left, right); err == nil {
		t.Fatal("mixed source pair was accepted")
	}
}

func TestFormalGLMPhase15FanInRootIsCryptographicallyBoundToTheGCStep(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	attempt := sha256.Sum256([]byte("phase15-root-bound-attempt"))
	master := sha256.Sum256([]byte("phase15-root-bound-master"))
	leftRoot := sha256Hex([]byte("verified fan-in left"))
	rightRoot := sha256Hex([]byte("relay-mixed fan-in right"))
	leftStep := formalGLMPhase15Step{
		Iteration: 0, BlockIndex: 0, SourceRoot: leftRoot}
	rightStep := formalGLMPhase15Step{
		Iteration: 0, BlockIndex: 0, SourceRoot: rightRoot}
	session, err := formalGLMPhase15StepSession(plan, leftStep, attempt, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFormalGLMPhase15StepSession(plan, rightStep, session); err == nil {
		t.Fatal("relay-mixed fan-in root was accepted by the peer context")
	}
	leftPurpose, _ := formalGLMPhase15StepPurpose(plan, leftStep, attempt)
	rightPurpose, _ := formalGLMPhase15StepPurpose(plan, rightStep, attempt)
	if leftPurpose == rightPurpose {
		t.Fatal("different verified fan-ins produced the same secure-record context")
	}
	missing := formalGLMPhase15Step{Iteration: 0, BlockIndex: 0}
	if _, err := formalGLMPhase15StepSession(plan, missing, attempt, master); err == nil {
		t.Fatal("block session without a verified fan-in root was accepted")
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hexString(digest[:])
}

func formalGLMPhase15TestSourceRoot(plan formalGLMPhase15Plan, block int) string {
	return sha256Hex([]byte(plan.RunID + "/verified-source/" +
		string(rune('0'+block))))
}

func TestFormalGLMPhase15StreamedCircuitsMatchCentralOracleForTGreaterThanOne(t *testing.T) {
	for _, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			plan := formalGLMPhase15TestPlan(t, family, 3, 2, 2, 3, 3)
			complete := formalGLMPhase15TestInput(plan)
			want, err := referenceFormalGLMPhase15(plan, complete)
			if err != nil {
				t.Fatal(err)
			}
			rationalWant, err := referenceFormalGLMPhase15Rational(plan, complete)
			if err != nil {
				t.Fatal(err)
			}
			blockCircuit, err := compileFormalGLMPhase15Block(plan)
			if err != nil {
				t.Fatal(err)
			}
			finalCircuit, err := compileFormalGLMPhase15Finalize(plan)
			if err != nil {
				t.Fatal(err)
			}
			rng := rand.New(rand.NewSource(1515))
			p := plan.Kernel.CoefficientCount
			betaG := make([]*big.Int, p)
			betaE := make([]*big.Int, p)
			for j := 0; j < p; j++ {
				betaG[j], betaE[j] = new(big.Int), new(big.Int)
			}
			for iteration := 0; iteration < plan.Iterations; iteration++ {
				gradientG := make([]*big.Int, p)
				gradientE := make([]*big.Int, p)
				for j := 0; j < p; j++ {
					gradientG[j], gradientE[j] = new(big.Int), new(big.Int)
				}
				for block := 0; block < plan.TotalBlocks; block++ {
					secretBlock := formalGLMPhase15TestBlock(plan, complete, block)
					rowG, rowE := exactGCTestSplit(rng, secretBlock, plan.RingBits)
					localG := append(append(append([]*big.Int{}, rowG...), betaG...), gradientG...)
					localE := append(append(append([]*big.Int{}, rowE...), betaE...), gradientE...)
					masks := make([]*big.Int, 2*p)
					for j := range masks {
						masks[j] = exactGCTestRandomResidue(rng, plan.RingBits)
					}
					packed, err := blockCircuit.Compute([]*big.Int{
						exactGCPackChunks(append(append([]*big.Int{}, localG...), masks...),
							plan.ContainerBits),
						exactGCPackChunks(localE, plan.ContainerBits),
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(packed) != 1 {
						t.Fatalf("unexpected block output arity %d", len(packed))
					}
					decoded := formalGLMPhase15Unpack(packed[0], 2*p, plan.RingBits)
					betaG, betaE = append([]*big.Int(nil), masks[:p]...),
						append([]*big.Int(nil), decoded[:p]...)
					gradientG, gradientE = append([]*big.Int(nil), masks[p:]...),
						append([]*big.Int(nil), decoded[p:]...)
				}
				localG := append(append([]*big.Int{}, betaG...), gradientG...)
				localE := append(append([]*big.Int{}, betaE...), gradientE...)
				masks := make([]*big.Int, p)
				for j := range masks {
					masks[j] = exactGCTestRandomResidue(rng, plan.RingBits)
				}
				packed, err := finalCircuit.Compute([]*big.Int{
					exactGCPackChunks(append(append([]*big.Int{}, localG...), masks...),
						plan.ContainerBits),
					exactGCPackChunks(localE, plan.ContainerBits),
				})
				if err != nil {
					t.Fatal(err)
				}
				decoded := formalGLMPhase15Unpack(packed[0], p, plan.RingBits)
				betaG, betaE = masks, decoded
			}
			for j := 0; j < p; j++ {
				got := exactGCReferenceReconstruct(betaG[j], betaE[j], plan.RingBits)
				if got.Cmp(want[j]) != 0 {
					t.Fatalf("coefficient %d streamed=%s oracle=%s", j, got,
						exactGCReferenceSigned(want[j], plan.RingBits))
				}
			}
			totalError := new(big.Rat)
			for j := 0; j < p; j++ {
				lattice := new(big.Rat).SetFrac(
					exactGCReferenceSigned(want[j], plan.RingBits), big.NewInt(256))
				difference := new(big.Rat).Sub(lattice, rationalWant[j])
				if difference.Sign() < 0 {
					difference.Neg(difference)
				}
				totalError.Add(totalError, difference)
			}
			totalError.Mul(totalError, big.NewRat(256, 1))
			rho, ok := new(big.Int).SetString(plan.RhoTotalUpper, 10)
			if !ok || totalError.Cmp(new(big.Rat).SetInt(rho)) > 0 {
				t.Fatalf("T=%d lattice error %s exceeds signed rho %s",
					plan.Iterations, totalError, plan.RhoTotalUpper)
			}
		})
	}
}

func TestFormalGLMPhase15RandomizedT2BoundariesMatchOracle(t *testing.T) {
	for familyIndex, family := range []string{"binomial", "poisson"} {
		t.Run(family, func(t *testing.T) {
			plan := formalGLMPhase15TestPlan(t, family, 3, 2, 2, 3, 2)
			rng := rand.New(rand.NewSource(int64(9100 + familyIndex)))
			weights := []int64{-256, 0, 128, 256, 512}
			numericX := []int64{-512, -256, -17, 0, 256, 512}
			indicators := []int64{-256, 0, 17, 256, 512}
			binomialY := []int64{-256, 0, 17, 256, 512}
			poissonY := []int64{-256, 0, 17, 256, 512, 2304}
			offsets := []int64{-1024, -512, -17, 0, 512, 1024}
			pick := func(values []int64) *big.Int {
				return formalGLMResidue(
					big.NewInt(values[rng.Intn(len(values))]), plan.RingBits)
			}
			for trial := 0; trial < 12; trial++ {
				input := make([]*big.Int, 0,
					plan.TotalCapacity*(plan.Kernel.CoefficientCount+3))
				for row := 0; row < plan.TotalCapacity; row++ {
					input = append(input, pick(weights), pick(numericX), pick(indicators))
					if family == "binomial" {
						input = append(input, pick(binomialY))
					} else {
						input = append(input, pick(poissonY))
					}
					input = append(input, pick(offsets))
				}
				got, err := formalGLMPhase15DirectExecute(plan, input, rng)
				if err != nil {
					t.Fatal(err)
				}
				want, err := referenceFormalGLMPhase15(plan, input)
				if err != nil {
					t.Fatal(err)
				}
				for j := range want {
					if got[j].Cmp(want[j]) != 0 {
						t.Fatalf("trial=%d coefficient=%d streamed=%s oracle=%s",
							trial, j, got[j], want[j])
					}
				}
			}
		})
	}
}

func formalGLMPhase15TestRunNetworkStep(t testing.TB, plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, session exactGCSession,
	garblerInput, evaluatorInput []*big.Int) ([]*big.Int, []*big.Int) {
	t.Helper()
	left, right := net.Pipe()
	_ = left.SetDeadline(time.Now().Add(60 * time.Second))
	_ = right.SetDeadline(time.Now().Add(60 * time.Second))
	type result struct {
		shares []*big.Int
		err    error
	}
	garbler := make(chan result, 1)
	go func() {
		shares, err := formalGLMPhase15RunGarbler(left, plan, step, session,
			garblerInput)
		garbler <- result{shares: shares, err: err}
	}()
	evaluatorShares, evaluatorErr := formalGLMPhase15RunEvaluator(right, plan,
		step, session, evaluatorInput)
	garblerResult := <-garbler
	_ = left.Close()
	_ = right.Close()
	if evaluatorErr != nil || garblerResult.err != nil {
		t.Fatalf("Phase-1.5 network step failed: %v / %v",
			garblerResult.err, evaluatorErr)
	}
	return garblerResult.shares, evaluatorShares
}

func TestFormalGLMPhase15ActualYaoOTKeepsT2StateSealed(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	complete := formalGLMPhase15TestInput(plan)
	want, err := referenceFormalGLMPhase15(plan, complete)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(2121))
	rowG, rowE := exactGCTestSplit(rng, complete, plan.RingBits)
	betaG, betaE := []*big.Int{new(big.Int)}, []*big.Int{new(big.Int)}
	master := sha256.Sum256([]byte("phase15-network-master"))
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		gradientG, gradientE := []*big.Int{new(big.Int)}, []*big.Int{new(big.Int)}
		blockStep := formalGLMPhase15Step{Iteration: iteration, BlockIndex: 0,
			SourceRoot: formalGLMPhase15TestSourceRoot(plan, 0)}
		attempt := sha256.Sum256([]byte("phase15-network-block/" +
			string(rune('0'+iteration))))
		session, err := formalGLMPhase15StepSession(plan, blockStep, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		betaGradientG, betaGradientE := formalGLMPhase15TestRunNetworkStep(t,
			plan, blockStep, session,
			append(append(append([]*big.Int{}, rowG...), betaG...), gradientG...),
			append(append(append([]*big.Int{}, rowE...), betaE...), gradientE...))
		betaG, gradientG = betaGradientG[:1], betaGradientG[1:]
		betaE, gradientE = betaGradientE[:1], betaGradientE[1:]

		finalStep := formalGLMPhase15Step{Iteration: iteration, BlockIndex: -1}
		attempt = sha256.Sum256([]byte("phase15-network-final/" +
			string(rune('0'+iteration))))
		session, err = formalGLMPhase15StepSession(plan, finalStep, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		betaG, betaE = formalGLMPhase15TestRunNetworkStep(t, plan, finalStep,
			session, append(append([]*big.Int{}, betaG...), gradientG...),
			append(append([]*big.Int{}, betaE...), gradientE...))
	}
	got := exactGCReferenceReconstruct(betaG[0], betaE[0], plan.RingBits)
	if got.Cmp(want[0]) != 0 {
		t.Fatalf("actual Yao/OT T=2 result %s != oracle %s", got,
			exactGCReferenceSigned(want[0], plan.RingBits))
	}
}

func TestFormalGLMPhase15CheckpointCrashCommitAndTamper(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.ComputePeers)
	key := sha256.Sum256([]byte("phase15-checkpoint-key"))
	stores := make(map[string]*formalGLMPhase15CheckpointStore, 2)
	dirs := make(map[string]string, 2)
	for _, peer := range plan.Kernel.ComputePeers {
		dirs[peer] = filepath.Join(t.TempDir(), peer)
		store, err := newFormalGLMPhase15CheckpointStore(dirs[peer], key, plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		stores[peer] = store
	}
	leftPeer, rightPeer := plan.Kernel.ComputePeers[0], plan.Kernel.ComputePeers[1]
	step, attempt, err := stores[leftPeer].BeginFreshAttempt()
	if err != nil {
		t.Fatal(err)
	}
	rightStep, err := stores[rightPeer].BeginAttempt(attempt)
	if err != nil || rightStep != step {
		t.Fatalf("peers did not bind the same fixed step: %+v %+v %v", step, rightStep, err)
	}
	step.SourceRoot = formalGLMPhase15TestSourceRoot(plan, 0)
	checkpointMaster := sha256.Sum256([]byte("phase15-checkpoint-master"))
	checkpointSession, err := formalGLMPhase15StepSession(
		plan, step, attempt, checkpointMaster)
	if err != nil {
		t.Fatal(err)
	}
	leftBeta, rightBeta := []*big.Int{big.NewInt(17)}, []*big.Int{big.NewInt(29)}
	leftGradient, rightGradient := []*big.Int{big.NewInt(31)}, []*big.Int{big.NewInt(37)}
	if err := stores[leftPeer].RecordPendingOutput(
		step, checkpointSession, leftBeta, leftGradient); err != nil {
		t.Fatal(err)
	}
	if err := stores[rightPeer].RecordPendingOutput(
		step, checkpointSession, rightBeta, rightGradient); err != nil {
		t.Fatal(err)
	}
	leftReceipt, _ := stores[leftPeer].PendingReceipt(identities.private[leftPeer])
	rightReceipt, _ := stores[rightPeer].PendingReceipt(identities.private[rightPeer])
	receipts := []formalGLMPhase15StepReceipt{rightReceipt, leftReceipt}
	for _, peer := range plan.Kernel.ComputePeers {
		if err := stores[peer].CommitPending(receipts, identities.public); err != nil {
			t.Fatal(err)
		}
	}
	// Restart preserves the committed step and rejects an old barrier.
	for _, peer := range plan.Kernel.ComputePeers {
		restarted, err := newFormalGLMPhase15CheckpointStore(dirs[peer], key, plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		state, err := restarted.Load()
		if err != nil || state.NextStep != 1 || state.Pending != nil {
			t.Fatalf("bad restarted checkpoint: %+v %v", state, err)
		}
		if err := restarted.CommitPending(receipts, identities.public); err == nil {
			t.Fatal("replayed commit barrier advanced the schedule twice")
		}
		stores[peer] = restarted
	}
	// Simulate a crash after only one peer records output.  A fresh attempt
	// replaces both uncommitted states and never reuses the old session id.
	orphanStep, orphanAttempt, err := stores[leftPeer].BeginFreshAttempt()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stores[rightPeer].BeginAttempt(orphanAttempt); err != nil {
		t.Fatal(err)
	}
	orphanSession, err := formalGLMPhase15StepSession(
		plan, orphanStep, orphanAttempt, checkpointMaster)
	if err != nil {
		t.Fatal(err)
	}
	if err := stores[leftPeer].RecordPendingOutput(
		orphanStep, orphanSession, leftBeta, nil); err != nil {
		t.Fatal(err)
	}
	_, freshAttempt, err := stores[leftPeer].BeginFreshAttempt()
	if err != nil {
		t.Fatal(err)
	}
	if freshAttempt == orphanAttempt {
		t.Fatal("crash recovery reused an exact-GC session id")
	}
	if _, err := stores[rightPeer].BeginAttempt(freshAttempt); err != nil {
		t.Fatal(err)
	}

	// Local corruption is authenticated and fails closed.
	path := filepath.Join(dirs[leftPeer], "formal-glm-phase15-state.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)/2] ^= 1
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stores[leftPeer].Load(); err == nil {
		t.Fatal("tampered durable checkpoint was accepted")
	}
}

func formalGLMPhase15TestRunSpoolStep(t *testing.T, plan formalGLMPhase15Plan,
	step formalGLMPhase15Step, session exactGCSession,
	garblerInput, evaluatorInput []*big.Int, garblerDir, evaluatorDir string,
	garblerOffset, evaluatorOffset *int64, pause time.Duration) ([]*big.Int, []*big.Int) {
	t.Helper()
	garblerRW, err := newExactGCSpoolRW(garblerDir, 64<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorRW, err := newExactGCSpoolRW(evaluatorDir, 64<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		role   string
		shares []*big.Int
		err    error
	}
	results := make(chan result, 2)
	go func() {
		shares, err := formalGLMPhase15RunGarbler(garblerRW, plan, step,
			session, garblerInput)
		results <- result{role: "garbler", shares: shares, err: err}
	}()
	go func() {
		shares, err := formalGLMPhase15RunEvaluator(evaluatorRW, plan, step,
			session, evaluatorInput)
		results <- result{role: "evaluator", shares: shares, err: err}
	}()
	// A temporary DSI/relay outage does not fail the workers; the durable
	// spool retains unacknowledged absolute offsets and applies backpressure.
	if pause > 0 {
		time.Sleep(pause)
	}
	var garblerShares, evaluatorShares []*big.Int
	completed := 0
	deadline := time.Now().Add(30 * time.Second)
	for completed < 2 && time.Now().Before(deadline) {
		*garblerOffset = exactGCTestRelaySpool(t, garblerDir, evaluatorDir,
			*garblerOffset)
		*evaluatorOffset = exactGCTestRelaySpool(t, evaluatorDir, garblerDir,
			*evaluatorOffset)
		now := time.Now()
		for _, dir := range []string{garblerDir, evaluatorDir} {
			if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("%s spool worker failed: %v", got.role, got.err)
			}
			if got.role == "garbler" {
				garblerShares = got.shares
			} else {
				evaluatorShares = got.shares
			}
			completed++
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if completed != 2 {
		t.Fatal("Phase-1.5 spool workers did not reconnect and complete")
	}
	if err := garblerRW.Close(); err != nil {
		t.Fatal(err)
	}
	if err := evaluatorRW.Close(); err != nil {
		t.Fatal(err)
	}
	return garblerShares, evaluatorShares
}

func TestFormalGLMPhase15T2OverDurableSpoolReconnectsBetweenSteps(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	complete := formalGLMPhase15TestInput(plan)
	want, err := referenceFormalGLMPhase15(plan, complete)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(5151))
	rowG, rowE := exactGCTestSplit(rng, complete, plan.RingBits)
	betaG, betaE := []*big.Int{new(big.Int)}, []*big.Int{new(big.Int)}
	master := sha256.Sum256([]byte("phase15-spool-master"))
	garblerDir := exactGCTestSpool(t, "phase15-garbler")
	evaluatorDir := exactGCTestSpool(t, "phase15-evaluator")
	garblerOffset, evaluatorOffset := int64(0), int64(0)
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		gradientG, gradientE := []*big.Int{new(big.Int)}, []*big.Int{new(big.Int)}
		blockStep := formalGLMPhase15Step{Iteration: iteration, BlockIndex: 0,
			SourceRoot: formalGLMPhase15TestSourceRoot(plan, 0)}
		attempt := sha256.Sum256([]byte("phase15-spool-block/" +
			string(rune('0'+iteration))))
		session, err := formalGLMPhase15StepSession(plan, blockStep, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		betaGradientG, betaGradientE := formalGLMPhase15TestRunSpoolStep(t,
			plan, blockStep, session,
			append(append(append([]*big.Int{}, rowG...), betaG...), gradientG...),
			append(append(append([]*big.Int{}, rowE...), betaE...), gradientE...),
			garblerDir, evaluatorDir, &garblerOffset, &evaluatorOffset,
			25*time.Millisecond)
		betaG, gradientG = betaGradientG[:1], betaGradientG[1:]
		betaE, gradientE = betaGradientE[:1], betaGradientE[1:]

		finalStep := formalGLMPhase15Step{Iteration: iteration, BlockIndex: -1}
		attempt = sha256.Sum256([]byte("phase15-spool-final/" +
			string(rune('0'+iteration))))
		session, err = formalGLMPhase15StepSession(plan, finalStep, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		betaG, betaE = formalGLMPhase15TestRunSpoolStep(t, plan, finalStep,
			session, append(append([]*big.Int{}, betaG...), gradientG...),
			append(append([]*big.Int{}, betaE...), gradientE...),
			garblerDir, evaluatorDir, &garblerOffset, &evaluatorOffset, 0)
	}
	got := exactGCReferenceReconstruct(betaG[0], betaE[0], plan.RingBits)
	if got.Cmp(want[0]) != 0 {
		t.Fatalf("durable spool T=2 result %s != oracle %s", got, want[0])
	}
	if garblerOffset == 0 || evaluatorOffset == 0 {
		t.Fatal("durable spool did not relay both authenticated directions")
	}
}

func formalGLMPhase15TestRunCheckpointWorkers(t *testing.T,
	leftStore, rightStore *formalGLMPhase15CheckpointStore,
	leftFanIn, rightFanIn *formalGLMPhase15FanInResult,
	identities formalGLMPhase15TestIdentities, session exactGCSession,
	garblerDir, evaluatorDir string, garblerOffset, evaluatorOffset *int64) []formalGLMPhase15StepReceipt {
	t.Helper()
	garblerRW, err := newExactGCSpoolRW(garblerDir, 64<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evaluatorRW, err := newExactGCSpoolRW(evaluatorDir, 64<<20, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		receipt formalGLMPhase15StepReceipt
		err     error
	}
	results := make(chan result, 2)
	go func() {
		receipt, err := leftStore.RunPendingWorkerStep(garblerRW, session,
			leftFanIn, identities.private[leftStore.peer])
		results <- result{receipt: receipt, err: err}
	}()
	go func() {
		receipt, err := rightStore.RunPendingWorkerStep(evaluatorRW, session,
			rightFanIn, identities.private[rightStore.peer])
		results <- result{receipt: receipt, err: err}
	}()
	// Exercise retained, unacknowledged data before the relay returns.
	time.Sleep(20 * time.Millisecond)
	receipts := make([]formalGLMPhase15StepReceipt, 0, 2)
	deadline := time.Now().Add(30 * time.Second)
	for len(receipts) < 2 && time.Now().Before(deadline) {
		*garblerOffset = exactGCTestRelaySpool(t, garblerDir, evaluatorDir,
			*garblerOffset)
		*evaluatorOffset = exactGCTestRelaySpool(t, evaluatorDir, garblerDir,
			*evaluatorOffset)
		now := time.Now()
		for _, dir := range []string{garblerDir, evaluatorDir} {
			if err := os.Chtimes(filepath.Join(dir, "exchange.hb"), now, now); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatal(got.err)
			}
			receipts = append(receipts, got.receipt)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if len(receipts) != 2 {
		t.Fatal("checkpoint workers did not complete after DSI reconnect")
	}
	if err := garblerRW.Close(); err != nil {
		t.Fatal(err)
	}
	if err := evaluatorRW.Close(); err != nil {
		t.Fatal(err)
	}
	return receipts
}

func TestFormalGLMPhase15CheckpointWorkersRunFullT2OverDSISpool(t *testing.T) {
	plan := formalGLMPhase15TestPlan(t, "binomial", 2, 1, 1, 1, 2)
	input := formalGLMPhase15TestInput(plan)
	want, err := referenceFormalGLMPhase15(plan, input)
	if err != nil {
		t.Fatal(err)
	}
	identities := formalGLMPhase15TestIdentitySet(t, plan.Kernel.ComputePeers)
	checkpointKey := sha256.Sum256([]byte("phase15-worker-checkpoint-key"))
	stores := make(map[string]*formalGLMPhase15CheckpointStore, 2)
	for _, peer := range plan.Kernel.ComputePeers {
		store, err := newFormalGLMPhase15CheckpointStore(
			filepath.Join(t.TempDir(), peer), checkpointKey, plan, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Bootstrap(); err != nil {
			t.Fatal(err)
		}
		stores[peer] = store
	}
	rng := rand.New(rand.NewSource(6161))
	leftSource, rightSource := exactGCTestSplit(rng, input, plan.RingBits)
	digest, _ := formalGLMPhase15PlanDigest(plan)
	leftFanIn := &formalGLMPhase15FanInResult{
		PlanSHA256: hexString(digest[:]), Recipient: plan.Kernel.ComputePeers[0],
		BlockIndex: 0, Shares: leftSource,
		FanInRoot: formalGLMPhase15TestSourceRoot(plan, 0), verified: true,
	}
	rightFanIn := &formalGLMPhase15FanInResult{
		PlanSHA256: hexString(digest[:]), Recipient: plan.Kernel.ComputePeers[1],
		BlockIndex: 0, Shares: rightSource,
		FanInRoot: formalGLMPhase15TestSourceRoot(plan, 0), verified: true,
	}
	garblerDir := exactGCTestSpool(t, "phase15-worker-garbler")
	evaluatorDir := exactGCTestSpool(t, "phase15-worker-evaluator")
	garblerOffset, evaluatorOffset := int64(0), int64(0)
	master := sha256.Sum256([]byte("phase15-worker-master"))
	for stepIndex := 0; stepIndex < plan.ScheduleSteps; stepIndex++ {
		step, attempt, err := stores[plan.Kernel.ComputePeers[0]].BeginFreshAttempt()
		if err != nil {
			t.Fatal(err)
		}
		rightStep, err := stores[plan.Kernel.ComputePeers[1]].BeginAttempt(attempt)
		if err != nil || rightStep != step {
			t.Fatalf("worker schedule disagreement: %+v %+v %v", step, rightStep, err)
		}
		var lf, rf *formalGLMPhase15FanInResult
		if step.BlockIndex >= 0 {
			lf, rf = leftFanIn, rightFanIn
			step.SourceRoot = lf.FanInRoot
		}
		session, err := formalGLMPhase15StepSession(plan, step, attempt, master)
		if err != nil {
			t.Fatal(err)
		}
		receipts := formalGLMPhase15TestRunCheckpointWorkers(t,
			stores[plan.Kernel.ComputePeers[0]], stores[plan.Kernel.ComputePeers[1]],
			lf, rf, identities, session, garblerDir, evaluatorDir,
			&garblerOffset, &evaluatorOffset)
		for _, peer := range plan.Kernel.ComputePeers {
			if err := stores[peer].CommitPending(receipts, identities.public); err != nil {
				t.Fatal(err)
			}
		}
	}
	leftState, err := stores[plan.Kernel.ComputePeers[0]].Load()
	if err != nil {
		t.Fatal(err)
	}
	rightState, err := stores[plan.Kernel.ComputePeers[1]].Load()
	if err != nil {
		t.Fatal(err)
	}
	leftBeta, err := formalGLMPhase15DecodeStateValues(leftState.Beta, 1,
		plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	rightBeta, err := formalGLMPhase15DecodeStateValues(rightState.Beta, 1,
		plan.RingBits)
	if err != nil {
		t.Fatal(err)
	}
	got := exactGCReferenceReconstruct(leftBeta[0], rightBeta[0], plan.RingBits)
	planDigest, _ := formalGLMPhase15PlanDigest(plan)
	initialTranscript := formalGLMPhase15InitialTranscript(hexString(planDigest[:]))
	if got.Cmp(want[0]) != 0 || leftState.NextStep != plan.ScheduleSteps ||
		rightState.NextStep != plan.ScheduleSteps ||
		leftState.TranscriptSHA256 != rightState.TranscriptSHA256 ||
		leftState.TranscriptSHA256 == initialTranscript {
		t.Fatalf("checkpoint worker result/state mismatch: got=%s want=%s steps=%d/%d",
			got, want[0], leftState.NextStep, rightState.NextStep)
	}
}

func BenchmarkFormalGLMPhase15BoundedBlockCircuit(b *testing.B) {
	plan := formalGLMPhase15TestPlan(b, "binomial", 3, 2, 2, 1_000_000, 8)
	circ, err := compileFormalGLMPhase15Block(plan)
	if err != nil {
		b.Fatal(err)
	}
	p := plan.Kernel.CoefficientCount
	local := plan.BlockCapacity*(p+3) + 2*p
	garbler := make([]*big.Int, local+2*p)
	evaluator := make([]*big.Int, local)
	for i := range garbler {
		garbler[i] = new(big.Int)
	}
	for i := range evaluator {
		evaluator[i] = new(big.Int)
	}
	g := exactGCPackChunks(garbler, plan.ContainerBits)
	e := exactGCPackChunks(evaluator, plan.ContainerBits)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := circ.Compute([]*big.Int{g, e}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(plan.TotalBlocks), "blocks/iteration")
	b.ReportMetric(float64(plan.ScheduleSteps), "fixed-steps")
	b.ReportMetric(float64(plan.BlockCost.Gates), "gates/block")
	b.ReportMetric(float64(plan.BlockCost.EstimatedWorkingByte), "estimated-bytes/block")
}

func BenchmarkFormalGLMPhase15InProcessBlockYaoOT(b *testing.B) {
	plan := formalGLMPhase15TestPlan(b, "binomial", 3, 2, 2, 1_000_000, 8)
	input := formalGLMPhase15TestBlock(plan, formalGLMPhase15TestInput(
		formalGLMPhase15TestPlan(b, "binomial", 3, 2, 2, 2, 1)), 0)
	// The scientific values above have the same p/fixed-point contract; only
	// the million-row plan controls the public cost and schedule.
	rng := rand.New(rand.NewSource(7171))
	rowG, rowE := exactGCTestSplit(rng, input, plan.RingBits)
	p := plan.Kernel.CoefficientCount
	zero := make([]*big.Int, 2*p)
	for i := range zero {
		zero[i] = new(big.Int)
	}
	garblerInput := append(append([]*big.Int{}, rowG...), zero...)
	evaluatorInput := append(append([]*big.Int{}, rowE...), zero...)
	master := sha256.Sum256([]byte("phase15-benchmark-master"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		attempt := sha256.Sum256([]byte("phase15-benchmark-attempt/" +
			string(rune(i+1))))
		step := formalGLMPhase15Step{Iteration: 0, BlockIndex: 0,
			SourceRoot: formalGLMPhase15TestSourceRoot(plan, 0)}
		session, err := formalGLMPhase15StepSession(plan, step, attempt, master)
		if err != nil {
			b.Fatal(err)
		}
		formalGLMPhase15TestRunNetworkStep(b, plan, step, session,
			garblerInput, evaluatorInput)
	}
	b.ReportMetric(float64(plan.TotalBlocks), "blocks/iteration")
	b.ReportMetric(float64(plan.ScheduleSteps), "fixed-steps")
	b.ReportMetric(float64(plan.BlockCost.Gates), "gates/block")
}
