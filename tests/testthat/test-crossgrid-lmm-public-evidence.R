test_that("cold LMM evidence reads only authenticated public terminal identities", {
  f <- .lmm_handoff_fixture()
  con <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  DBI::dbExecute(con, paste("CREATE TABLE source_cross_grid_records (capsule_id TEXT, analysis_id TEXT,",
    "batch_index INTEGER, record_json TEXT NOT NULL, row_mac TEXT NOT NULL, PRIMARY KEY(capsule_id,analysis_id,batch_index))"))
  record <- list(version = "lmm-staged-terminal-binding-v1", capsule_id = f$transport$capsule_id,
    analysis_id = "grouped", batch = -1L,
    semantic_key = .dsvert_dp_glm_grid_cross_key(f$manifest, f$artifact, f$transport),
    artifact_sha256 = .dsvert_joint_dp_hash(f$artifact), source_contract_sha256 = f$source_hash,
    purpose = paste0("grouped-lmm-staged-v1/", strrep("a", 64)),
    stage_receipt = strrep("b", 64), stage_plan_digest = strrep("c", 64))
  .dsvert_dp_glm_grid_cross_save(con, f$secret, record, -1L)
  local_mocked_bindings(
    .dsvert_dp_lmm_cross_signed_schema = function(...) f$schema,
    .dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con),
    .dsvert_dp_lmm_cross_public = function(binding, policy, phase, extra = list()) {
      c(binding, list(phase = phase), extra)
    },
    .dsvert_dp_synopsis_publication_v1 = function(...) list(artifact_key = strrep("e", 64),
      release_receipt = list(artifact_key = strrep("e", 64), execution_id = strrep("f", 64),
        source_contract_sha256 = f$source_hash, final_vector_root = strrep("1", 64),
        result_set_sha256 = strrep("2", 64))),
    .dsvert_dp_lmm_cross_load_handoff = function(...) stop("private source read"),
    .dsvert_dp_lmm_cross_record = function(...) stop("private terminal read"))
  evidence <- function(artifact_key = strrep("e", 64)) .dsvert_dp_lmm_cross_evidence(
    f$policy, f$secret, f$manifest, f$transport, "grouped", strrep("3", 64), artifact_key)
  value <- evidence()
  expect_identical(value$phase, "published")
  expect_identical(value$semantic_key, record$semantic_key)
  expect_identical(value$stage$stage_plan_digest, record$stage_plan_digest)
  expect_identical(value$stage_receipt, record$stage_receipt)
  expect_identical(value$contract_hash, f$source_hash)
  expect_identical(value$final_vector_root, strrep("1", 64))
  expect_error(evidence(strrep("4", 64)))
  expect_false(any(c("share", "validity_share", "worker_input") %in% names(value)))
  expect_null(.dsvert_dp_lmm_cross_compaction_evidence(con, f$secret, f$manifest, f$transport))
  hidden <- record; hidden$share <- "private"
  DBI::dbExecute(con, "DELETE FROM source_cross_grid_records")
  .dsvert_dp_glm_grid_cross_save(con, f$secret, hidden, -1L)
  expect_error(.dsvert_dp_lmm_cross_compaction_evidence(con, f$secret, f$manifest, f$transport))
  DBI::dbExecute(con, "DELETE FROM source_cross_grid_records")
  .dsvert_dp_glm_grid_cross_save(con, f$secret, record, -1L)
  changed <- record; changed$semantic_key <- strrep("d", 64)
  expect_error(.dsvert_dp_glm_grid_cross_save(con, f$secret, changed, -1L))
  DBI::dbExecute(con, "DELETE FROM source_cross_grid_records")
  .dsvert_dp_glm_grid_cross_save(con, f$secret, changed, -1L)
  expect_error(evidence())
  DBI::dbExecute(con, "DELETE FROM source_cross_grid_records")
  .dsvert_dp_glm_grid_cross_save(con, f$secret, record, -1L)
  DBI::dbExecute(con, "UPDATE source_cross_grid_records SET row_mac = 'tampered'")
  expect_error(evidence())
})

test_that("published LMM evidence verifies compilation without source claims or a session", {
  f <- .lmm_handoff_fixture()
  artifact <- list(artifact_key = strrep("a", 64),
    semantic = list(source_claim_set_sha256 = strrep("b", 64)))
  compilation <- list(artifact = artifact, receipts = list(peer_a = "signed-a", peer_b = "signed-b"))
  publication <- list(artifact = artifact, artifact_key = artifact$artifact_key,
    compile_receipts = compilation$receipts)
  local_mocked_bindings(
    .dsvert_dp_synopsis_remote_manifest_v1 = function(...) list(
      policy = f$policy, secret = f$secret, manifest = f$manifest),
    .dsvert_dp_synopsis_remote_compilation_v1 = function(...) compilation,
    .dsvert_dp_synopsis_publication_v1 = function(...) publication,
    .dsvert_dp_synopsis_source_contract_from_hashes_v1 = function(policy, manifest, key, claims) {
      expect_identical(key, artifact$artifact_key)
      expect_identical(claims, artifact$semantic$source_claim_set_sha256)
      f$transport
    },
    .dsvert_dp_lmm_cross_evidence = function(policy, secret, manifest, contract, ...) {
      expect_identical(contract, f$transport)
      "authenticated published evidence"
    },
    .dsvert_dp_synopsis_source_transport_context_v1 = function(...) stop("fresh source claims read"),
    .S = function(...) stop("live session read"))
  invoke <- function() dsvertDPSynopsisGLMGridCrossDS(strrep("c", 64),
    "unused claims", "authenticated compilation", "grouped",
    "00000000-0000-4000-8000-000000000000", "evidence")
  expect_identical(invoke(), "authenticated published evidence")
  compilation$receipts$peer_a <- "swapped"
  expect_error(invoke())
})
