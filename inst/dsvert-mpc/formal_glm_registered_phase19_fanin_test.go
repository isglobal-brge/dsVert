package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type formalGLMRegisteredPhase19FanInTestFixtureV1 struct {
	loader  formalGLMRegisteredPhase19LoaderTestFixtureV1
	blocks  map[string][]formalGLMRegisteredPhase19PrivateBlockV1
	backend [32]byte
}

var (
	formalGLMRegisteredPhase19FanInK2Once sync.Once
	formalGLMRegisteredPhase19FanInK2     formalGLMRegisteredPhase19FanInTestFixtureV1
	formalGLMRegisteredPhase19FanInK3Once sync.Once
	formalGLMRegisteredPhase19FanInK3     formalGLMRegisteredPhase19FanInTestFixtureV1
	formalGLMRegisteredPhase19FanInK5Once sync.Once
	formalGLMRegisteredPhase19FanInK5     formalGLMRegisteredPhase19FanInTestFixtureV1
)

func formalGLMRegisteredPhase19FanInTestCached(t testing.TB,
	custodians int,
) formalGLMRegisteredPhase19FanInTestFixtureV1 {
	t.Helper()
	var once *sync.Once
	var cached *formalGLMRegisteredPhase19FanInTestFixtureV1
	switch custodians {
	case 2:
		once, cached = &formalGLMRegisteredPhase19FanInK2Once,
			&formalGLMRegisteredPhase19FanInK2
	case 3:
		once, cached = &formalGLMRegisteredPhase19FanInK3Once,
			&formalGLMRegisteredPhase19FanInK3
	case 5:
		once, cached = &formalGLMRegisteredPhase19FanInK5Once,
			&formalGLMRegisteredPhase19FanInK5
	default:
		t.Fatalf("unsupported registered Phase19 fan-in fixture K%d", custodians)
	}
	once.Do(func() {
		loader := formalGLMRegisteredPhase19LoaderTestCached(t, custodians)
		plan := loader.provenance.source.plan
		blocks := make(
			map[string][]formalGLMRegisteredPhase19PrivateBlockV1, 2)
		for _, recipient := range plan.DesignatedComputePeers {
			store := formalGLMRegisteredPhase19LoaderTestStore(
				t, loader,
				formalGLMRegisteredPhase19LoaderTestRoot(
					t, fmt.Sprintf("fanin-K%d-%s", custodians, recipient)),
				recipient, loader.receiptSet.GlobalMaterializationRootSHA256,
				loader.localKeys[recipient])
			formalGLMRegisteredPhase19LoaderTestCommit(
				t, loader, store, recipient, "", -1, nil)
			loaded, err := formalGLMLoadRegisteredPhase19PrivateBlocksV1(
				loader.record, store, loader.recipientSK[recipient])
			store.Close()
			if err != nil {
				t.Fatal(err)
			}
			blocks[recipient] = loaded
		}
		*cached = formalGLMRegisteredPhase19FanInTestFixtureV1{
			loader: loader, blocks: blocks,
			backend: sha256.Sum256([]byte(fmt.Sprintf(
				"registered-phase19/fanin/backend/K%d", custodians))),
		}
	})
	return *cached
}

func formalGLMRegisteredPhase19FanInTestCloneBlocks(
	t testing.TB,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
) []formalGLMRegisteredPhase19PrivateBlockV1 {
	t.Helper()
	cloned := make([]formalGLMRegisteredPhase19PrivateBlockV1, len(blocks))
	for index, block := range blocks {
		cloned[index] = block
		cloned[index].coordinateShares = make([]*big.Int, len(block.coordinateShares))
		for coordinate, value := range block.coordinateShares {
			if value == nil {
				t.Fatal("cached registered Phase19 block has nil coordinate")
			}
			cloned[index].coordinateShares[coordinate] = new(big.Int).Set(value)
		}
		cloned[index].validityShares = append([]byte(nil), block.validityShares...)
	}
	return cloned
}

func formalGLMRegisteredPhase19FanInTestCloneBlockSet(
	t testing.TB,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	totalBlocks, blockIndex int,
) []formalGLMRegisteredPhase19PrivateBlockV1 {
	t.Helper()
	if totalBlocks < 1 || blockIndex < 0 || blockIndex >= totalBlocks ||
		len(blocks)%totalBlocks != 0 {
		t.Fatal("invalid source-major fixture for private block set")
	}
	sources := len(blocks) / totalBlocks
	selected := make([]formalGLMRegisteredPhase19PrivateBlockV1, sources)
	for sourceIndex := range selected {
		selected[sourceIndex] = blocks[sourceIndex*totalBlocks+blockIndex]
		selected[sourceIndex].coordinateShares = make(
			[]*big.Int, len(selected[sourceIndex].coordinateShares))
		for coordinate, value := range blocks[sourceIndex*totalBlocks+blockIndex].coordinateShares {
			if value == nil {
				formalGLMRegisteredPhase19ClearPrivateBlocksV1(selected)
				t.Fatal("cached registered Phase19 block has nil coordinate")
			}
			selected[sourceIndex].coordinateShares[coordinate] = new(big.Int).Set(value)
		}
		selected[sourceIndex].validityShares = append(
			[]byte(nil), selected[sourceIndex].validityShares...)
	}
	return selected
}

func formalGLMRegisteredPhase19FanInTestRuntime(t testing.TB,
	fixture formalGLMRegisteredPhase19FanInTestFixtureV1,
) *formalGLMRegisteredPhase19EphemeralRuntimeV1 {
	t.Helper()
	runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		fixture.loader.record, fixture.loader.provenance.source.contract,
		fixture.loader.provenance.source.inputs.identities.public,
		fixture.backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return runtime
}

func formalGLMRegisteredPhase19FanInTestLegacy(t testing.TB,
	runtime *formalGLMRegisteredPhase19EphemeralRuntimeV1,
	blocks []formalGLMRegisteredPhase19PrivateBlockV1,
	recipient string,
	blockIndex int,
) formalGLMPhase19FanInResult {
	t.Helper()
	plan := runtime.legacyPlan
	verified := make([]formalGLMPhase19VerifiedSourceBlock, 0,
		len(plan.Kernel.CustodianPeers))
	for sourceIndex := range plan.Kernel.CustodianPeers {
		block := blocks[sourceIndex*plan.TotalBlocks+blockIndex]
		sealed, err := formalGLMPhase19SealSourceBlock(
			plan, runtime.context, block.source, recipient, blockIndex,
			block.coordinateShares, block.validityShares,
			block.alignmentGateShare, block.alignmentConsensusShare,
			block.pairCommitmentSHA256, block.blockCommitmentSHA256,
			runtime.backendKey)
		if err != nil {
			t.Fatal(err)
		}
		verified = append(verified, sealed)
	}
	defer formalGLMRegisteredPhase19ClearVerifiedBlocksV1(verified)
	result, err := formalGLMPhase19FanIn(
		plan, runtime.context, recipient, blockIndex, verified,
		newFormalGLMPhase19ReplayLedger(), runtime.backendKey)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func formalGLMRegisteredPhase19FanInTestJSON(t testing.TB,
	result formalGLMRegisteredPhase19FanInResultV1,
) []byte {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		"capsule", "run_id", "pre_execution", "preexecution", "path",
		"secret", "backend", "coordinate", "validity", "consensus",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("registered fan-in JSON exposed %q: %s", forbidden, encoded)
		}
	}
	return encoded
}

func TestFormalGLMRegisteredPhase19FanInK2K5LegacyParity(t *testing.T) {
	for _, custodians := range []int{2, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase19FanInTestCached(t, custodians)
			plan := fixture.loader.provenance.source.plan
			runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
			aliases := []string{
				runtime.runAlias, runtime.artifactAlias, runtime.capsuleAlias,
				runtime.preExecutionAlias,
			}
			seen := make(map[string]bool, len(aliases))
			for _, alias := range aliases {
				if !formalGLMIsSHA256(alias) || alias == runtime.semanticRootSHA256 ||
					seen[alias] {
					t.Fatal("ephemeral aliases are not distinct and domain-separated")
				}
				seen[alias] = true
			}
			if encoded, err := json.Marshal(runtime); err != nil || string(encoded) != "{}" {
				t.Fatalf("ephemeral runtime became serializable: %s / %v", encoded, err)
			}
			blocksToCheck := []int{plan.TotalBlocks - 1}
			if custodians == 2 {
				blocksToCheck = []int{0, plan.TotalBlocks - 1}
			}
			recipient := plan.DesignatedComputePeers[0]
			for _, blockIndex := range blocksToCheck {
				blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
					t, fixture.blocks[recipient])
				result, err := formalGLMRegisteredPhase19FanInBlockV1(
					runtime, blocks, recipient, blockIndex)
				if err != nil {
					t.Fatal(err)
				}
				if err := formalGLMRegisteredPhase19ValidateFanInResultV1(
					runtime, result); err != nil {
					t.Fatal(err)
				}
				wantRows, err := formalGLMPhase19RowsInBlock(
					runtime.legacyPlan, blockIndex)
				if err != nil || result.Version !=
					formalGLMRegisteredPhase19FanInResultVersionV1 ||
					result.SemanticRootSHA256 !=
						fixture.loader.record.Binding.SemanticRootSHA256 ||
					result.ReceiptSetSHA256 !=
						fixture.loader.record.Binding.ReceiptSetSHA256 ||
					result.Recipient != recipient || result.BlockIndex != blockIndex ||
					result.RowsInBlock != wantRows || result.OpeningsPerformed != 0 ||
					result.ProductionReady {
					t.Fatal("registered fan-in wrapper lost its exact binding")
				}
				formalGLMRegisteredPhase19FanInTestJSON(t, result)
				want := formalGLMRegisteredPhase19FanInTestLegacy(
					t, runtime, blocks, recipient, blockIndex)
				if !reflect.DeepEqual(result.fanIn, want) {
					t.Fatal("registered adapter diverged from exact legacy fan-in")
				}
				formalGLMPhase19RuntimeZeroFanIn(&want)
				formalGLMRegisteredPhase19ClearFanInResultV1(&result)
				formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19FanInPrivateBlockSetK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalGLMRegisteredPhase19FanInTestCached(t, custodians)
			plan := fixture.loader.provenance.source.plan
			recipient := plan.DesignatedComputePeers[0]
			runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
			blockIndices := []int{plan.TotalBlocks - 1}
			if custodians == 2 {
				blockIndices = []int{0, plan.TotalBlocks - 1}
			}
			for _, blockIndex := range blockIndices {
				legacyBlocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
					t, fixture.blocks[recipient])
				boundedBlocks := formalGLMRegisteredPhase19FanInTestCloneBlockSet(
					t, fixture.blocks[recipient], plan.TotalBlocks, blockIndex)
				if len(boundedBlocks) != custodians {
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
					t.Fatalf("bounded fan-in received %d blocks, want K=%d", len(boundedBlocks), custodians)
				}
				want, err := formalGLMRegisteredPhase19FanInBlockV1(
					runtime, legacyBlocks, recipient, blockIndex)
				if err != nil {
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
					t.Fatal(err)
				}
				got, err := formalGLMRegisteredPhase19FanInPrivateBlockSetV1(
					runtime, boundedBlocks, recipient, blockIndex)
				if err != nil {
					formalGLMRegisteredPhase19ClearFanInResultV1(&want)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
					t.Fatal(err)
				}
				if !reflect.DeepEqual(want, got) {
					formalGLMRegisteredPhase19ClearFanInResultV1(&want)
					formalGLMRegisteredPhase19ClearFanInResultV1(&got)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
					t.Fatal("bounded fan-in differs from source-major adapter")
				}
				if _, err := formalGLMRegisteredPhase19FanInPrivateBlockSetV1(
					runtime, boundedBlocks[:len(boundedBlocks)-1], recipient, blockIndex); err == nil {
					formalGLMRegisteredPhase19ClearFanInResultV1(&want)
					formalGLMRegisteredPhase19ClearFanInResultV1(&got)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
					formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
					t.Fatal("incomplete bounded private block set was accepted")
				}
				formalGLMRegisteredPhase19ClearFanInResultV1(&want)
				formalGLMRegisteredPhase19ClearFanInResultV1(&got)
				formalGLMRegisteredPhase19ClearPrivateBlocksV1(legacyBlocks)
				formalGLMRegisteredPhase19ClearPrivateBlocksV1(boundedBlocks)
			}
		})
	}
}

func TestFormalGLMRegisteredPhase19FanInRejectsBindingsShapeAndBackend(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	plan := fixture.loader.provenance.source.plan
	recipient := plan.DesignatedComputePeers[0]
	lastBlock := plan.TotalBlocks - 1
	for _, test := range []struct {
		name       string
		blockIndex int
		mutate     func([]formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1
	}{
		{
			name: "missing", blockIndex: 0,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				return blocks[:len(blocks)-1]
			},
		},
		{
			name: "source-major-reorder", blockIndex: 0,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				blocks[0], blocks[plan.TotalBlocks] =
					blocks[plan.TotalBlocks], blocks[0]
				return blocks
			},
		},
		{
			name: "cross-binding", blockIndex: 0,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				blocks[0].semanticRootSHA256 = strings.Repeat("a", 64)
				return blocks
			},
		},
		{
			name: "commitment-tamper", blockIndex: 0,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				blocks[0].blockCommitmentSHA256 = strings.Repeat("b", 64)
				return blocks
			},
		},
		{
			name: "final-rows", blockIndex: lastBlock,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				blocks[lastBlock].rowsInBlock++
				return blocks
			},
		},
		{
			name: "final-fixed-shape", blockIndex: lastBlock,
			mutate: func(blocks []formalGLMRegisteredPhase19PrivateBlockV1) []formalGLMRegisteredPhase19PrivateBlockV1 {
				blocks[lastBlock].slotsInBlock--
				return blocks
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
			blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
				t, fixture.blocks[recipient])
			defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
			blocks = test.mutate(blocks)
			if result, err := formalGLMRegisteredPhase19FanInBlockV1(
				runtime, blocks, recipient, test.blockIndex); err == nil {
				formalGLMRegisteredPhase19ClearFanInResultV1(&result)
				t.Fatal("invalid registered private block set reached legacy fan-in")
			}
		})
	}

	t.Run("invalid-block", func(t *testing.T) {
		runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
		blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
			t, fixture.blocks[recipient])
		defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
		if _, err := formalGLMRegisteredPhase19FanInBlockV1(
			runtime, blocks, recipient, plan.TotalBlocks); err == nil {
			t.Fatal("out-of-range registered block accepted")
		}
	})
	t.Run("outsider", func(t *testing.T) {
		runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
		blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
			t, fixture.blocks[recipient])
		defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
		if _, err := formalGLMRegisteredPhase19FanInBlockV1(
			runtime, blocks, "outsider", 0); err == nil {
			t.Fatal("outsider recipient accepted")
		}
	})
	t.Run("zero-backend", func(t *testing.T) {
		if runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
			fixture.loader.record, fixture.loader.provenance.source.contract,
			fixture.loader.provenance.source.inputs.identities.public,
			[32]byte{}); err == nil {
			runtime.Close()
			t.Fatal("zero backend accepted")
		}
	})
	t.Run("changed-backend", func(t *testing.T) {
		runtime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
		runtime.backendKey = sha256.Sum256([]byte("wrong registered backend"))
		blocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
			t, fixture.blocks[recipient])
		defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(blocks)
		if _, err := formalGLMRegisteredPhase19FanInBlockV1(
			runtime, blocks, recipient, 0); err == nil {
			t.Fatal("runtime backend mutation bypassed its ephemeral seal")
		}
	})
}

func TestFormalGLMRegisteredPhase19RuntimeRejectsRecordPlanAndRoots(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	contract := fixture.loader.provenance.source.contract
	pins := fixture.loader.provenance.source.inputs.identities.public
	record := fixture.loader.record
	for _, test := range []struct {
		name     string
		record   formalGLMRegisteredPhase19BindingRecordV1
		contract formalGLMSourceContractV1
	}{
		{
			name: "semantic-root", record: func() formalGLMRegisteredPhase19BindingRecordV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, record)
				changed.Binding.SemanticRootSHA256 = strings.Repeat("c", 64)
				return changed
			}(), contract: contract,
		},
		{
			name: "receipt-root", record: func() formalGLMRegisteredPhase19BindingRecordV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, record)
				changed.ReceiptSet.GlobalMaterializationRootSHA256 = strings.Repeat("d", 64)
				return changed
			}(), contract: contract,
		},
		{
			name: "receipt-set", record: func() formalGLMRegisteredPhase19BindingRecordV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, record)
				changed.ReceiptSet.ReceiptSetSHA256 = strings.Repeat("e", 64)
				return changed
			}(), contract: contract,
		},
		{
			name: "receipt-signature", record: func() formalGLMRegisteredPhase19BindingRecordV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, record)
				changed.ReceiptSet.Receipts[0].Signature[0] ^= 0x01
				return changed
			}(), contract: contract,
		},
		{
			name: "plan-hash", record: record,
			contract: func() formalGLMSourceContractV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, contract)
				changed.Core.RegisteredExecutionPlan.PlanSHA256 = strings.Repeat("f", 64)
				return changed
			}(),
		},
		{
			name: "plan-geometry", record: record,
			contract: func() formalGLMSourceContractV1 {
				changed := formalGLMRegisteredPhase18ProvenanceTestClone(t, contract)
				changed.Core.RegisteredExecutionPlan.BlockCapacity++
				return changed
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
				test.record, test.contract, pins, fixture.backend); err == nil {
				runtime.Close()
				t.Fatal("invalid registered runtime evidence accepted")
			}
		})
	}
	t.Run("cross-K-binding", func(t *testing.T) {
		other := formalGLMRegisteredPhase19FanInTestCached(t, 5)
		if runtime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
			other.loader.record, contract, pins, fixture.backend); err == nil {
			runtime.Close()
			t.Fatal("cross-contract binding and plan were combined")
		}
	})
}

func TestFormalGLMRegisteredPhase19FanInAttemptRunInvariantAndBackendBound(
	t *testing.T,
) {
	fixture := formalGLMRegisteredPhase19FanInTestCached(t, 2)
	plan := fixture.loader.provenance.source.plan
	recipient := plan.DesignatedComputePeers[1]
	leftRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	rightRuntime := formalGLMRegisteredPhase19FanInTestRuntime(t, fixture)
	leftBlocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
		t, fixture.blocks[recipient])
	rightBlocks := formalGLMRegisteredPhase19FanInTestCloneBlocks(
		t, fixture.blocks[recipient])
	defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(leftBlocks)
	defer formalGLMRegisteredPhase19ClearPrivateBlocksV1(rightBlocks)
	left, err := formalGLMRegisteredPhase19FanInBlockV1(
		leftRuntime, leftBlocks, recipient, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&left)
	right, err := formalGLMRegisteredPhase19FanInBlockV1(
		rightRuntime, rightBlocks, recipient, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer formalGLMRegisteredPhase19ClearFanInResultV1(&right)
	leftJSON := formalGLMRegisteredPhase19FanInTestJSON(t, left)
	rightJSON := formalGLMRegisteredPhase19FanInTestJSON(t, right)
	leftHash, leftErr := formalGLMRegisteredPhase19FanInResultSHA256V1(left)
	rightHash, rightErr := formalGLMRegisteredPhase19FanInResultSHA256V1(right)
	if leftErr != nil || rightErr != nil || !reflect.DeepEqual(left, right) ||
		string(leftJSON) != string(rightJSON) || leftHash != rightHash {
		t.Fatalf("attempt/run split registered fan-in: %v/%v", leftErr, rightErr)
	}
	for _, operationalID := range []string{
		fmt.Sprintf("%x", sha256.Sum256([]byte("attempt-A"))),
		fmt.Sprintf("%x", sha256.Sum256([]byte("attempt-B"))),
		fmt.Sprintf("%x", sha256.Sum256([]byte("run-A"))),
		fmt.Sprintf("%x", sha256.Sum256([]byte("run-B"))),
	} {
		if strings.Contains(string(leftJSON), operationalID) {
			t.Fatal("operational attempt/run identifier entered registered wrapper")
		}
	}

	otherBackend := sha256.Sum256([]byte("other registered Phase19 backend"))
	otherRuntime, err := newFormalGLMRegisteredPhase19EphemeralRuntimeV1(
		fixture.loader.record, fixture.loader.provenance.source.contract,
		fixture.loader.provenance.source.inputs.identities.public, otherBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer otherRuntime.Close()
	if err := formalGLMRegisteredPhase19ValidateFanInResultV1(
		otherRuntime, left); err == nil {
		t.Fatal("registered wrapper verified under a different backend")
	}
}
