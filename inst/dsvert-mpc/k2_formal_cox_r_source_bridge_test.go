package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const formalCoxRSourceBridgeFixtureScript = `
source("../../R/mpcUtils.R")
source("../../R/dsiRelay.R")
source("../../R/dpPolicyDS.R")
source("../../R/psiProtocol.R")
source("../../R/psiPaddedProtocolDS.R")
source("../../R/dpAlignedDatasetRegistry.R")
source("../../R/dpDatasetDescriptor.R")
source("../../R/formalCoxCapsuleInternal.R")
source("../../R/formalCoxRing128Materializer.R")
source("../../R/formalCoxServerSource.R")
source("../../tests/testthat/helper-padded-dp-binding.R")
k <- as.integer(commandArgs(trailingOnly = TRUE)[[1L]])
keys <- stats::setNames(
  replicate(k, openssl::ed25519_keygen(), simplify = FALSE),
  paste0("site", seq_len(k)))
pins <- lapply(keys, function(key) {
  base64_to_base64url(jsonlite::base64_enc(as.list(as.list(key)$pubkey)$data))
})
unsigned <- .dsvert_formal_cox_schema_compile(
  artifact_sha256 = paste(rep("1", 64L), collapse = ""),
  logical_snapshot_id = paste0("r_source_bridge_k", k),
  peer_pinset = pins, outcome_owner = "site1",
  covariate_owners = c(x = "site2"), capacity = 5L,
  time_grid_ticks = 0:3, x_lower = c(x = -0.125),
  x_upper = c(x = 0.125), covariate_l2_bound = 0.125,
  beta_l2_bound = 0.125, minimum_at_risk_per_event = 1L,
  iterations = 1L, step_numerator = 1L, step_denominator = 16L,
  ridge_numerator = 1L, ridge_denominator = 100L,
  epsilon_numerator = 8L, epsilon_denominator = 1L,
  delta_numerator = 1L, delta_denominator = 1000L,
  frac_bits = 8L)
message <- .dsvert_formal_cox_schema_message(unsigned)
signatures <- lapply(keys, function(key) base64_to_base64url(gsub(
  "[\\r\\n[:space:]]", "",
  jsonlite::base64_enc(openssl::ed25519_sign(message, key)))))
schema <- .dsvert_formal_cox_schema_seal(unsigned, signatures)
valid <- c(TRUE, TRUE, TRUE, FALSE, TRUE)
source_rows <- function(peer) {
  if (identical(peer, "site1")) {
    return(data.frame(valid = valid, stop_tick = c(1L, 2L, 3L, 1L, 2L),
                      status = c(1, 0, 1, 0, 1)))
  }
  if (identical(peer, "site2")) {
    return(data.frame(valid = valid, x = c(-0.125, 0.125, 0, 0, 0.125)))
  }
  data.frame(valid = valid)
}
blocks <- lapply(names(pins), function(peer) {
  source_values <- source_rows(peer)
  rows <- source_values
  rows$patient_id <- sprintf("patient-%03d", seq_len(nrow(rows)))
  binding <- .dsvert_test_padded_dp_binding(
    rows, "patient_id", paste0("cox-source-", peer), "v1", pins)
  source_environment <- new.env(parent = emptyenv())
  assign("cox_local", binding$data, envir = source_environment)
  lockBinding("cox_local", source_environment)
  previous_options <- options(
    dsvert.peer_name = peer,
    dsvert.formal_cox.source_specs = stats::setNames(list(list(
      source_name = peer,
      schema_sha256 = schema$schema_sha256,
      logical_snapshot_id = schema$unsigned$logical_snapshot_id,
      dataset = binding$descriptor,
      data_name = "cox_local",
      patient_column = "patient_id",
      block_capacity = 2L,
      columns = as.list(stats::setNames(
        names(rows)[names(rows) != "patient_id"],
        names(rows)[names(rows) != "patient_id"])))), peer))
  on.exit(options(previous_options), add = TRUE)
  context <- .dsvert_formal_cox_server_source_open(
    schema, source_environment)
  observed <- lapply(0:2, function(index) {
    .dsvert_formal_cox_server_source_block(context, index)
  })
  expected <- lapply(0:2, function(index) {
    .dsvert_formal_cox_source_block_decimal_lines(
      schema, peer, source_values, index, 2L)
  })
  if (!identical(observed, expected)) {
    stop("Configured Cox source blocks differ from the pinned snapshot.")
  }
  observed
})
names(blocks) <- names(pins)
seeds <- lapply(keys, function(key) {
  base64_to_base64url(jsonlite::base64_enc(as.list(key)$data))
})
output <- list(
  schema_json = .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(schema)),
  seeds = seeds, blocks = blocks)
cat(jsonlite::toJSON(output, auto_unbox = TRUE, null = "null"))
`

type formalCoxRSourceBridgeFixture struct {
	SchemaJSON string                `json:"schema_json"`
	Seeds      map[string]string     `json:"seeds"`
	Blocks     map[string][][]string `json:"blocks"`
}

type formalCoxRSourceBridgeFixtureCacheEntry struct {
	once    sync.Once
	encoded []byte
	err     error
	loads   int
}

var formalCoxRSourceBridgeFixtureCache = map[int]*formalCoxRSourceBridgeFixtureCacheEntry{
	2: {},
	3: {},
	5: {},
}

func formalCoxRSourceBridgeFixtureRun(custodians int) ([]byte, error) {
	command := exec.Command("Rscript", "--vanilla", "-e",
		formalCoxRSourceBridgeFixtureScript, fmt.Sprint(custodians))
	command.Env = append(os.Environ(), "R_TESTS=")
	encoded, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w\n%s", err, encoded)
	}
	return encoded, nil
}

func (entry *formalCoxRSourceBridgeFixtureCacheEntry) load(
	custodians int,
) ([]byte, error) {
	entry.once.Do(func() {
		entry.loads++
		entry.encoded, entry.err = formalCoxRSourceBridgeFixtureRun(custodians)
	})
	if entry.err != nil {
		return nil, entry.err
	}
	return append([]byte(nil), entry.encoded...), nil
}

func formalCoxRSourceBridgeFixtureFor(t testing.TB,
	custodians int) formalCoxRSourceBridgeFixture {

	t.Helper()
	if _, err := exec.LookPath("Rscript"); err != nil {
		t.Skip("Rscript is required for the R-to-Go Cox source bridge test")
	}
	entry := formalCoxRSourceBridgeFixtureCache[custodians]
	var encoded []byte
	var err error
	if entry == nil {
		encoded, err = formalCoxRSourceBridgeFixtureRun(custodians)
	} else {
		encoded, err = entry.load(custodians)
	}
	if err != nil {
		t.Fatalf("R source bridge fixture K=%d: %v\n%s", custodians, err, encoded)
	}
	defer clear(encoded)
	var fixture formalCoxRSourceBridgeFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil ||
		!json.Valid([]byte(fixture.SchemaJSON)) || len(fixture.Seeds) != custodians ||
		len(fixture.Blocks) != custodians {
		t.Fatalf("invalid R source bridge fixture K=%d: %v", custodians, err)
	}
	return fixture
}

func TestFormalCoxRSourceBridgeFixtureCacheReturnsIndependentCopies(t *testing.T) {
	if _, err := exec.LookPath("Rscript"); err != nil {
		t.Skip("Rscript is required for the R-to-Go Cox source bridge test")
	}
	entry := &formalCoxRSourceBridgeFixtureCacheEntry{}
	first, err := entry.load(2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := entry.load(2)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	defer clear(second)
	if entry.loads != 1 || len(first) == 0 || len(second) == 0 {
		t.Fatalf("fixture cache loads=%d, first=%d, second=%d", entry.loads,
			len(first), len(second))
	}
	first[0] ^= 1
	var fixture formalCoxRSourceBridgeFixture
	if err := json.Unmarshal(second, &fixture); err != nil ||
		len(fixture.Seeds) != 2 || len(fixture.Blocks) != 2 {
		t.Fatalf("fixture cache returned aliased or invalid JSON: %v", err)
	}
	fixture.Seeds["site1"] = "tampered"
	third, err := entry.load(2)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(third)
	var replay formalCoxRSourceBridgeFixture
	if err := json.Unmarshal(third, &replay); err != nil ||
		replay.Seeds["site1"] == "tampered" {
		t.Fatalf("fixture cache retained caller mutation: %v", err)
	}
}

func formalCoxRSourceBridgePins(t testing.TB,
	raw json.RawMessage) map[string]ed25519.PublicKey {

	t.Helper()
	schema, _, err := formalCoxSchemaDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	pins := make(map[string]ed25519.PublicKey, len(schema.Unsigned.PeerPinset))
	for peer, encoded := range schema.Unsigned.PeerPinset {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			t.Fatalf("invalid R pin for %s", peer)
		}
		pins[peer] = ed25519.PublicKey(decoded)
	}
	return pins
}

func formalCoxRSourceBridgePrivateKeys(t testing.TB,
	seeds map[string]string) map[string]ed25519.PrivateKey {

	t.Helper()
	private := make(map[string]ed25519.PrivateKey, len(seeds))
	for peer, encoded := range seeds {
		seed, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("invalid R signing seed for %s", peer)
		}
		private[peer] = ed25519.NewKeyFromSeed(seed)
		clear(seed)
	}
	return private
}

func formalCoxRSourceBridgeExpected(t testing.TB, lines []string,
	coordinateCount, ringBits int) []*big.Int {

	t.Helper()
	if len(lines) > coordinateCount {
		t.Fatalf("R source line count %d exceeds %d", len(lines), coordinateCount)
	}
	values := make([]*big.Int, coordinateCount)
	for index := range values {
		values[index] = new(big.Int)
		if index >= len(lines) {
			continue
		}
		value, err := formalCoxCanonicalSigned(lines[index], "R source decimal")
		if err != nil {
			t.Fatal(err)
		}
		values[index] = formalCoxResidue(value, ringBits)
	}
	return values
}

func formalCoxRSourceBridgeReferenceRows(t testing.TB,
	plan formalCoxBlockwisePlan, blocks map[string][][]string,
) []*big.Int {
	t.Helper()
	rows := make([]*big.Int, plan.TotalCapacity*plan.RowWidth)
	for index := range rows {
		rows[index] = new(big.Int)
	}
	modulus := exactGCModulus(plan.RingBits)
	for block := 0; block < plan.TotalBlocks; block++ {
		rowCount := formalCoxBlockwiseSourceRowsInBlock(plan, block)
		for _, source := range plan.Policy.CustodianPeers {
			sourceBlocks, ok := blocks[source]
			if !ok || len(sourceBlocks) != plan.TotalBlocks {
				t.Fatalf("reference source %s has an invalid block schedule", source)
			}
			values := formalCoxRSourceBridgeExpected(t, sourceBlocks[block],
				plan.BlockCapacity*plan.RowWidth, plan.RingBits)
			for index := 0; index < rowCount*plan.RowWidth; index++ {
				row := block*plan.BlockCapacity*plan.RowWidth + index
				rows[row].Add(rows[row], values[index])
				rows[row].Mod(rows[row], modulus)
			}
			exactGCZeroBigInts(values)
		}
	}
	return rows
}

func formalCoxRSourceBridgeNoiseContract(t testing.TB,
	plan formalCoxBlockwisePlan, pins map[string]ed25519.PublicKey,
	private map[string]ed25519.PrivateKey,
) (formalCoxBlockwiseSamplerContract,
	[]formalCoxBlockwiseSamplerAuthorization) {
	t.Helper()
	artifact, artifactID, err := formalCoxBlockwiseBuildStickyArtifact(plan, pins)
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string][32]byte, len(artifact.NoiseAuthorities))
	commitments := make([]formalCoxBlockwiseSamplerCommitment,
		len(artifact.NoiseAuthorities))
	for index, authority := range artifact.NoiseAuthorities {
		roots[authority.PeerName] = sha256.Sum256([]byte(
			"formal-cox-r-source-bridge/noise-root/" + authority.PeerName))
		seed, commitment, deriveErr := formalCoxBlockwiseDeriveSamplerSeed(
			roots[authority.PeerName], artifact, artifactID, authority.Role)
		clear(seed[:])
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		commitments[index] = commitment
	}
	contract, err := formalCoxBlockwiseBuildSamplerContract(
		artifact, artifactID, commitments, pins)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]jointDPBiomedicalGaussianSignature,
		len(artifact.CustodianPeers))
	for index, peer := range artifact.CustodianPeers {
		signatures[index], err = formalCoxBlockwiseSignSamplerContract(
			contract, peer, private[peer], pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	contract, err = formalCoxBlockwiseSealSamplerContract(contract, signatures, pins)
	if err != nil {
		t.Fatal(err)
	}
	authorizations := make([]formalCoxBlockwiseSamplerAuthorization,
		len(artifact.NoiseAuthorities))
	for index, authority := range artifact.NoiseAuthorities {
		storageKey := sha256.Sum256([]byte(
			"formal-cox-r-source-bridge/noise-store/" + authority.PeerName))
		store, storeErr := newFormalCoxBlockwiseSamplerGuardStore(
			filepath.Join(t.TempDir(), authority.Role), authority.PeerName,
			storageKey, pins)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		predecessors := authorizations[:index]
		authorizations[index], _, err = store.AuthorizeOnce(
			contract, roots[authority.PeerName], private[authority.PeerName],
			predecessors)
		closeErr := store.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("R source noise authorization %s: %v / close=%v",
				authority.Role, err, closeErr)
		}
	}
	return contract, authorizations
}

func formalCoxRSourceBridgeStageZeroNoise(t testing.TB,
	plan formalCoxBlockwisePlan, session *formalCoxBlockwiseSourceSession,
	pins map[string]ed25519.PublicKey, private map[string]ed25519.PrivateKey,
	stores map[string]*formalCoxBlockwiseSourceStore,
) []*big.Int {
	t.Helper()
	contract, authorizations := formalCoxRSourceBridgeNoiseContract(
		t, plan, pins, private)
	noise := make([]*big.Int, 0,
		plan.Iterations*plan.Policy.CovariateCount)
	for iteration := 0; iteration < plan.Iterations; iteration++ {
		step := formalCoxBlockwiseSourceTestStep(
			t, plan, formalCoxBlockwiseStepUpdate, iteration)
		values := make(map[string][]*big.Int, 2)
		validity := make(map[string]bool, 2)
		for recipientIndex, recipient := range plan.Policy.ComputePeers {
			values[recipient] = make([]*big.Int, plan.Policy.CovariateCount)
			for index := range values[recipient] {
				values[recipient][index] = new(big.Int)
			}
			// The two compute roles carry XOR shares of the public execution
			// validity bit.  These two values reconstruct to true.
			validity[recipient] = recipientIndex == 1
		}
		envelopes := make(map[string][]byte, len(plan.Policy.ComputePeers))
		ordered := make([][]byte, len(plan.Policy.ComputePeers))
		for index, recipient := range plan.Policy.ComputePeers {
			valid := validity[recipient]
			envelopes[recipient] = formalCoxBlockwiseSourceTestSeal(
				t, session, private, recipient, recipient, step,
				values[recipient], &valid)
			ordered[index] = envelopes[recipient]
		}
		barrier, err := formalCoxBlockwiseNewGuardedNoiseBarrier(
			session, step, ordered, contract, authorizations)
		if err != nil {
			t.Fatal(err)
		}
		approvals := make([]formalCoxBlockwiseNoiseApproval,
			len(plan.Policy.ComputePeers))
		for index, signer := range plan.Policy.ComputePeers {
			approvals[index], err = formalCoxBlockwiseSignNoiseBarrier(
				session, barrier, ordered, signer, private[signer])
			if err != nil {
				t.Fatal(err)
			}
		}
		encodedBarrier, err := formalCoxBlockwiseFinalizeGuardedNoiseBarrier(
			session, contract, authorizations, barrier, approvals)
		if err != nil {
			t.Fatal(err)
		}
		for _, recipient := range plan.Policy.ComputePeers {
			if _, err := stores[recipient].Accept(envelopes[recipient], encodedBarrier); err != nil {
				t.Fatalf("zero-noise recipient=%s iteration=%d: %v",
					recipient, iteration, err)
			}
		}
		for range plan.Policy.CovariateCount {
			noise = append(noise, new(big.Int))
		}
		for _, recipient := range plan.Policy.ComputePeers {
			exactGCZeroBigInts(values[recipient])
			clear(envelopes[recipient])
		}
		clear(encodedBarrier)
	}
	return noise
}

func formalCoxRSourceBridgeAssertFullSchedule(t testing.TB,
	fixture *formalCoxBlockwiseSourceBridgeTestFixture,
	rows, noise []*big.Int,
) {
	t.Helper()
	// This reconstruction exists only inside the test process. Production keeps
	// both sealed outputs private until the separately guarded release path.
	sealed := formalCoxBlockwiseSourceBridgeTestRunFullScheduleSealed(
		t, fixture)
	defer func() {
		for index := range sealed {
			exactGCZeroBigInts(sealed[index].CoefficientShares)
		}
	}()
	noiseValidity := make([]bool, fixture.plan.Iterations)
	for index := range noiseValidity {
		noiseValidity[index] = true
	}
	want, wantValid, err := referenceFormalCoxBlockwiseSchedule(
		fixture.plan, rows, noise, noiseValidity)
	if err != nil {
		t.Fatal(err)
	}
	defer exactGCZeroBigInts(want)
	gotValid := sealed[0].ValidityShare != sealed[1].ValidityShare
	if !wantValid || !gotValid {
		t.Fatalf("configured R Cox schedule is not valid: got=%v want=%v",
			gotValid, wantValid)
	}
	parsed, err := parseFormalCoxBlockwisePolicy(fixture.plan.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for index := range want {
		got := exactGCReferenceReconstruct(
			sealed[0].CoefficientShares[index],
			sealed[1].CoefficientShares[index], fixture.plan.RingBits)
		if got.Cmp(want[index]) != 0 {
			t.Fatalf("configured R Cox beta[%d]=%s, want independent oracle %s",
				index, got, want[index])
		}
		gotSigned := exactGCReferenceSigned(got, fixture.plan.RingBits)
		if gotSigned.Sign() == 0 {
			continue
		}
		if new(big.Int).Abs(gotSigned).Cmp(parsed.betaNorm) > 0 {
			t.Fatalf("configured R Cox beta[%d]=%s exceeds its signed bound",
				index, gotSigned)
		}
	}
}

func TestFormalCoxRSourceBlocksFeedEncryptedProducerK2K3K5(t *testing.T) {
	for _, custodians := range []int{2, 3, 5} {
		t.Run(fmt.Sprintf("K%d", custodians), func(t *testing.T) {
			fixture := formalCoxRSourceBridgeFixtureFor(t, custodians)
			rawSchema := json.RawMessage(fixture.SchemaJSON)
			compiled, err := formalCoxCompileSignedRSchema(rawSchema)
			if err != nil {
				t.Fatal(err)
			}
			runID := sha256.Sum256([]byte("formal-cox-r-source-bridge/" +
				fmt.Sprint(custodians)))
			plan, err := buildFormalCoxBlockwisePlan(compiled.Policy, 2,
				hex.EncodeToString(runID[:]))
			if err != nil || plan.BlockCapacity != 2 || plan.TotalBlocks != 3 {
				t.Fatalf("unexpected R-derived block plan: %+v %v", plan, err)
			}
			pins := formalCoxRSourceBridgePins(t, rawSchema)
			private := formalCoxRSourceBridgePrivateKeys(t, fixture.Seeds)
			for peer, key := range private {
				if !bytes.Equal(key.Public().(ed25519.PublicKey), pins[peer]) {
					t.Fatalf("R signing key does not match pin for %s", peer)
				}
			}
			context, err := newFormalCoxBlockwiseSourceContext(plan, pins)
			if err != nil {
				t.Fatal(err)
			}
			transportPublic := make(map[string][]byte, 2)
			transportPrivate := make(map[string][]byte, 2)
			for _, recipient := range plan.Policy.ComputePeers {
				seed := sha256.Sum256([]byte("formal-cox-r-source-x25519/" + recipient))
				key, err := ecdh.X25519().NewPrivateKey(seed[:])
				if err != nil {
					t.Fatal(err)
				}
				transportPrivate[recipient] = append([]byte(nil), key.Bytes()...)
				transportPublic[recipient] = append([]byte(nil), key.PublicKey().Bytes()...)
			}
			tickets := make([]formalCoxBlockwiseSourceRecipientTicket, 2)
			for index, recipient := range plan.Policy.ComputePeers {
				tickets[index], err = context.signRecipientTicket(
					recipient, transportPublic[recipient], private[recipient])
				if err != nil {
					t.Fatal(err)
				}
			}
			session, err := context.bindRecipientManifest(tickets)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			for _, directory := range []string{"producer", "recipient", "worker"} {
				if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			producers := make(map[string]*formalCoxBlockwiseSourceProducer,
				len(plan.Policy.CustodianPeers))
			storeDirs := make(map[string]string, len(plan.Policy.ComputePeers))
			storeKeys := make(map[string][32]byte, len(plan.Policy.ComputePeers))
			workerDirs := make(map[string]string, len(plan.Policy.ComputePeers))
			workerKeys := make(map[string][32]byte, len(plan.Policy.ComputePeers))
			stores := make(map[string]*formalCoxBlockwiseSourceStore,
				len(plan.Policy.ComputePeers))
			for _, recipient := range plan.Policy.ComputePeers {
				storeDirs[recipient] = filepath.Join(root, "recipient", recipient)
				storeKeys[recipient] = sha256.Sum256([]byte(
					"formal-cox-r-source-bridge/store/" + recipient))
				workerDirs[recipient] = filepath.Join(root, "worker", recipient)
				workerKeys[recipient] = sha256.Sum256([]byte(
					"formal-cox-r-source-bridge/worker/" + recipient))
				stores[recipient], err = newFormalCoxBlockwiseSourceStore(
					storeDirs[recipient], storeKeys[recipient], session, recipient,
					transportPrivate[recipient])
				if err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				for _, store := range stores {
					_ = store.Close()
				}
				for _, producer := range producers {
					_ = producer.Close()
				}
			}()
			for _, source := range plan.Policy.CustodianPeers {
				blocks, ok := fixture.Blocks[source]
				if !ok || len(blocks) != plan.TotalBlocks {
					t.Fatalf("R source blocks for %s have wrong shape", source)
				}
				key := sha256.Sum256([]byte(
					"formal-cox-r-source-bridge/producer/" + source))
				producer, err := newFormalCoxBlockwiseSourceProducer(
					filepath.Join(root, "producer", source), key,
					session, source, private[source])
				if err != nil {
					t.Fatal(err)
				}
				producers[source] = producer
			}
			for block := 0; block < plan.TotalBlocks; block++ {
				for _, source := range plan.Policy.CustodianPeers {
					lines := fixture.Blocks[source][block]
					producer := producers[source]
					binding, err := producer.BlockBinding(block)
					if err != nil {
						t.Fatal(err)
					}
					input := []byte(strings.Join(lines, "\n") + "\n")
					result, err := producer.ProduceBlock(binding, bytes.NewReader(input))
					if err != nil || result.Replayed {
						t.Fatalf("source=%s block=%d replay=%v err=%v", source,
							block, result.Replayed, err)
					}
					opened := formalCoxBlockwiseSourceProducerTestOpen(
						t, producer, session, transportPrivate, block)
					want := formalCoxRSourceBridgeExpected(t, lines,
						plan.BlockCapacity*plan.RowWidth, plan.RingBits)
					modulus := exactGCModulus(plan.RingBits)
					for index := range want {
						got := new(big.Int).Add(
							opened[plan.Policy.ComputePeers[0]][index],
							opened[plan.Policy.ComputePeers[1]][index])
						got.Mod(got, modulus)
						if got.Cmp(want[index]) != 0 {
							t.Fatalf("source=%s block=%d coordinate=%d: got %s want %s",
								source, block, index, got, want[index])
						}
					}
					exactGCZeroBigInts(opened[plan.Policy.ComputePeers[0]])
					exactGCZeroBigInts(opened[plan.Policy.ComputePeers[1]])
					exactGCZeroBigInts(want)
					for _, recipient := range plan.Policy.ComputePeers {
						delivery, err := producer.Delivery(block, recipient)
						if err != nil || delivery.ReceiptSHA256 != result.ReceiptSHA256 {
							t.Fatalf("R source delivery source=%s block=%d recipient=%s: %v",
								source, block, recipient, err)
						}
						encoded, err := delivery.Encode(session)
						if err != nil {
							t.Fatal(err)
						}
						replayed, err := stores[recipient].AcceptDelivery(encoded)
						clear(encoded)
						if err != nil || replayed {
							t.Fatalf("R source delivery accept source=%s block=%d recipient=%s replay=%v err=%v",
								source, block, recipient, replayed, err)
						}
					}
				}
			}
			referenceRows := formalCoxRSourceBridgeReferenceRows(
				t, plan, fixture.Blocks)
			defer exactGCZeroBigInts(referenceRows)
			referenceNoise := formalCoxRSourceBridgeStageZeroNoise(
				t, plan, session, pins, private, stores)
			defer exactGCZeroBigInts(referenceNoise)
			for _, store := range stores {
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			bridgeFixture := &formalCoxBlockwiseSourceBridgeTestFixture{
				plan: plan, pins: pins, signing: private, session: session,
				transportSK: transportPrivate, sourceDir: storeDirs,
				workerDir: workerDirs, sourceKey: storeKeys, workerKey: workerKeys,
			}
			bridges, err := formalCoxBlockwiseSourceBridgeTestOpen(t, bridgeFixture)
			if err != nil {
				t.Fatal(err)
			}
			defer formalCoxBlockwiseSourceBridgeTestClose(bridges)
			for block := 0; block < plan.TotalBlocks; block++ {
				step := formalCoxBlockwiseSourceTestStep(
					t, plan, formalCoxBlockwiseStepBlock, block)
				roots := make([]string, len(bridges))
				for index, bridge := range bridges {
					roots[index], err = bridge.PublicInputRoot(step)
					if err != nil {
						t.Fatalf("R source public root block=%d peer=%d: %v",
							block, index, err)
					}
				}
				if _, err := formalCoxBlockwiseMatchPublicInputRoots(plan, step, roots); err != nil {
					t.Fatalf("R source block=%d delivery root mismatch: %v", block, err)
				}
			}
			formalCoxBlockwiseSourceBridgeTestClose(bridges)
			formalCoxRSourceBridgeAssertFullSchedule(
				t, bridgeFixture, referenceRows, referenceNoise)
			for _, key := range private {
				clear(key)
			}
			for _, key := range transportPrivate {
				clear(key)
			}
		})
	}
}
