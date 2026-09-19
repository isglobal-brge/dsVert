.lmm_staged_result_fixture <- function(count = 3L) {
  state <- list(operation_id = paste0("op_", strrep("a", 32)), operation = "grouped-lmm-staged-v1",
    purpose = paste0("grouped-lmm-staged-v1/", strrep("b", 64)), source_producer = "dp.lmm-grid-cross.staged-v1",
    ring_bits = 128L, frac_bits = 0L, vector_len = count, context_hash = strrep("c", 64))
  result <- list(version = "dsvert-exact-gc-result-v1", kind = "grouped-lmm-staged-ring128-share-v1",
    ring_bits = 128L, vector_len = count, share = gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L * count))),
    validity_share = jsonlite::base64_enc(raw(ceiling(count / 8))), context_hash = state$context_hash,
    stage_receipt = strrep("d", 64), stage_plan_digest = strrep("e", 64))
  list(state = state, result = result)
}

test_that("staged LMM result retains private candidate validity and committed identities", {
  f <- .lmm_staged_result_fixture(10L)
  f$result$validity_share <- jsonlite::base64_enc(as.raw(c(170, 2)))
  value <- .exact_gc_validate_result(f$state, f$result)
  expect_identical(value$validity_share, f$result$validity_share)
  expect_identical(value$stage_receipt, f$result$stage_receipt)
  expect_identical(value$stage_plan_digest, f$result$stage_plan_digest)
  for (field in c("stage_receipt", "stage_plan_digest")) {
    changed <- f$result; changed[[field]] <- strrep("0", 64)
    expect_error(.exact_gc_validate_result(f$state, changed), "terminal identity")
    changed[[field]] <- NULL
    expect_error(.exact_gc_validate_result(f$state, changed), "context")
  }
  changed <- f$result; changed$validity_share <- jsonlite::base64_enc(as.raw(c(170, 4)))
  expect_error(.exact_gc_validate_result(f$state, changed), "Non-canonical")
  changed$validity_share <- jsonlite::base64_enc(as.raw(1))
  expect_error(.exact_gc_validate_result(f$state, changed))
  changed <- f$result; changed$share <- jsonlite::base64_enc(raw(16L))
  expect_error(.exact_gc_validate_result(f$state, changed))
})

test_that("staged LMM lifecycle persists replayable candidate validity into DP source", {
  f <- .lmm_handoff_fixture()
  expect_length(.dsvert_dp_lmm_cross_artifacts(f$manifest), 1L)
  unrelated <- f$manifest
  unrelated$workload$families$gaussian_models$artifacts$grouped$version <- "same-owner-lmm-v1"
  expect_length(.dsvert_dp_lmm_cross_artifacts(unrelated), 0L)
  output <- .lmm_staged_result_fixture(as.integer(f$artifact$coordinate_count))
  output$result$share <- jsonlite::base64_enc(as.raw(seq_len(16L * f$artifact$coordinate_count)))
  output$result$validity_share <- jsonlite::base64_enc(as.raw(5))
  stage <- c(output$state[c("operation_id", "operation", "purpose", "vector_len")], list(
    source_key = paste0("exact_gc_in_", strrep("a", 32)), output_key = paste0("exact_gc_out_", strrep("a", 32)),
    stage_plan_digest = output$result$stage_plan_digest))
  binding <- list(analysis_id = "grouped", artifact = f$artifact, contract = f$transport,
    contract_hash = f$source_hash, semantic_key = .dsvert_dp_glm_grid_cross_key(f$manifest, f$artifact, f$transport),
    peer_binding_digest = f$ss$.exact_gc_peer_binding_digest, stage = stage, worker_input = "opaque-native-input")
  binding$admission <- list(request = list(manifest_sha256 = "bound"), policy = f$policy,
    secret = f$secret, contract_hash = binding$contract_hash, artifact_sha256 = .dsvert_joint_dp_hash(f$artifact))
  f$ss$.dp_lmm_grid_cross <- list(grouped = binding)
  con <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  DBI::dbExecute(con, paste("CREATE TABLE source_cross_grid_records (capsule_id TEXT, analysis_id TEXT,",
    "batch_index INTEGER, record_json TEXT NOT NULL, row_mac TEXT NOT NULL, PRIMARY KEY(capsule_id,analysis_id,batch_index))"))
  value <- .exact_gc_validate_result(output$state, output$result)
  calls <- list()
  local_mocked_bindings(
    .dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con),
    .dsvert_dp_lmm_cross_public = function(binding, policy, phase, extra = list()) c(list(phase = phase), extra),
    .exact_gc_consume_output = function(...) value,
    .exact_gc_init_impl = function(...) { calls[[length(calls) + 1L]] <<- list(...); "started" })
  prepared <- .dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")
  expect_false(prepared$persisted)
  input <- f$ss$.exact_gc_inputs[[stage$source_key]]
  expect_identical(input$share, "")
  expect_identical(input$grouped_lmm, binding$worker_input)
  expect_identical(input$allowed_spec$output_kind, "grouped-lmm-staged-ring128-share-v1")
  expect_identical(.dsvert_dp_lmm_cross_start(f$policy, f$ss, "grouped", "test-session"), "started")
  expect_identical(calls[[1L]][[7L]], "grouped-lmm-staged-v1")
  .dsvert_dp_lmm_cross_store(f$policy, f$secret, f$ss, "grouped")
  expect_true(.dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")$persisted)
  complete <- .dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped")
  expect_identical(.dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped"), complete)
  record <- .dsvert_dp_lmm_cross_record(con, f$secret, f$manifest, f$artifact, f$transport)
  expect_identical(record$validity_share, value$validity_share)
  expect_identical(record$stage_receipt, value$stage_receipt)
  public <- .dsvert_dp_lmm_cross_sampler_binding(f$policy, f$secret, f$manifest, f$transport)
  expect_identical(public, record[c("stage_receipt", "stage_plan_digest")])
  public_row <- .dsvert_dp_glm_grid_cross_load(con, f$secret, f$transport$capsule_id, "grouped", -1L)
  expect_false(any(c("share", "validity_share") %in% names(public_row)))
  chunk <- list(offset = 0L, count = 4L)
  source <- .dsvert_dp_lmm_cross_inject(con, f$secret, f$manifest, f$transport, chunk, raw(64L), f$policy)
  expect_identical(as.raw(source)[seq.int(17L, 64L)], jsonlite::base64_dec(value$share))
  metadata <- attr(source, "dsvert_staged_source")
  expect_identical(as.integer(rawToBits(jsonlite::base64_dec(metadata$validity_share)))[1:4], c(1L, 1L, 0L, 1L))
  expect_identical(metadata$stage_receipt, record$stage_receipt)
  sliced <- .dsvert_dp_lmm_cross_inject(con, f$secret, f$manifest, f$transport,
    list(offset = 2L, count = 2L), raw(32L), f$policy)
  expect_identical(as.integer(rawToBits(jsonlite::base64_dec(attr(sliced, "dsvert_staged_source")$validity_share)))[1:2], c(0L, 1L))
  changed <- f$manifest; changed$workload$capsule_mechanism$source_context_hash <- strrep("0", 64)
  expect_error(.dsvert_dp_lmm_cross_record(con, f$secret, changed, f$artifact, f$transport))
  value$stage_plan_digest <- strrep("f", 64)
  expect_error(.dsvert_dp_lmm_cross_store(f$policy, f$secret, f$ss, "grouped"))
  expect_error(.dsvert_dp_lmm_cross_dispatch(f$ss, "grouped", "session",
    list(manifest_sha256 = "changed"), "prepare", 0L))
  expect_error(.dsvert_dp_lmm_cross_dispatch(f$ss, "grouped", "session",
    binding$admission$request, "prepare", 1L))
  DBI::dbExecute(con, "UPDATE source_cross_grid_records SET row_mac = 'tampered' WHERE batch_index=0")
  expect_error(.dsvert_dp_lmm_cross_record(con, f$secret, f$manifest, f$artifact, f$transport))
})
