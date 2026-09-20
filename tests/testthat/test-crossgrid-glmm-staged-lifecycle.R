test_that("GLMM admission preserves integer outcomes and the complete variance grid", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .lmm_handoff_fixture(owners, "binomial_glmm")
    admitted <- .dsvert_dp_glm_grid_profile_admit(f$contract, f$policy, f$schema)
    expect_equal(admitted$artifact$coordinate_count, 4)
    expect_identical(.dsvert_dp_capsule_gaussian_spec(f$policy, "grouped",
      list(grouped = list(version = "binomial_glmm_grid_cross_v1", dataset = "cohort",
        contract = f$contract)))$kind, "lmm_grid_cross")
    spec <- admitted$spec
    variables <- c(unlist(spec$predictor_order), spec$outcome$reference, spec$grouping$reference)
    values <- setNames(lapply(seq_along(variables), function(i)
      as.raw(rep(i * 16 + seq_len(8L), each = 16L))), variables)
    validities <- lapply(values, function(value) as.raw(255L - as.integer(value)))
    handoff <- .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy, f$schema,
      f$source_hash, values, validities, f$ss, f$transport$capsule_id)
    expect_named(handoff, c("plan", "numeric", "outcome", "metadata"))
    expect_identical(handoff$plan$version, "dsvert-glmm-staged-source-handoff-v1")
    expect_identical(handoff$plan$VarianceGrid, list("0", "16384"))
    expect_identical(handoff$plan$profile_sha256, spec$numeric_contract$certificate_sha256)
    expect_identical(jsonlite::base64_dec(handoff$outcome$Share), values[[spec$outcome$reference]])
    expect_length(jsonlite::base64_dec(handoff$numeric$Share), length(spec$predictor_order) * 8L * 16L)
    outcome <- f$layout$blocks[[paste("grouped", spec$outcome$reference, "value", sep = "::")]]
    expect_equal(outcome$fraction_bits, 0)
    expect_equal(outcome$maximum, 1)
    expect_identical(f$artifact$source_coordinate_scaling,
      "all_coordinates_already_on_common_numeric_lattice_v1")
    sidecar <- .dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, f$manifest,
      f$transport, f$schema, "grouped", f$producer)
    expect_identical(sidecar$version, "dsvert-glmm-owner-route-source-v1")
    changed <- sidecar
    changed$version <- "dsvert-lmm-owner-route-source-v1"
    expect_error(.dsvert_dp_lmm_cross_route_handoff(changed, f$policy, f$secret,
      f$manifest, f$transport, f$schema, "grouped", f$producer))
    changed <- f$contract
    changed$spec$numeric_contract$certificate_sha256 <- strrep("0", 64)
    expect_error(.dsvert_dp_glm_grid_profile_admit(f$sign(changed), f$policy, f$schema))
  }
})

test_that("GLMM durable terminal records retain private validity and reject LMM swaps", {
  f <- .lmm_handoff_fixture(family = "binomial_glmm")
  count <- as.integer(f$artifact$coordinate_count)
  stage <- list(operation_id = paste0("op_", strrep("a", 32)),
    source_key = paste0("exact_gc_in_", strrep("a", 32)),
    output_key = paste0("exact_gc_out_", strrep("a", 32)),
    operation = "grouped-glmm-staged-v1", purpose = paste0("grouped-glmm-staged-v1/", strrep("b", 64)),
    vector_len = count, stage_plan_digest = strrep("e", 64))
  state <- c(stage, list(source_producer = "dp.glmm-grid-cross.staged-v1",
    ring_bits = 128L, frac_bits = 0L, context_hash = strrep("c", 64)))
  result <- list(version = "dsvert-exact-gc-result-v1", kind = "grouped-glmm-staged-ring128-share-v1",
    ring_bits = 128L, vector_len = count, share = gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L * count))),
    validity_share = jsonlite::base64_enc(as.raw(5)), context_hash = state$context_hash,
    stage_receipt = strrep("d", 64), stage_plan_digest = stage$stage_plan_digest)
  value <- .exact_gc_validate_result(state, result)
  expect_identical(value$validity_share, result$validity_share)
  swapped <- result
  swapped$kind <- "grouped-lmm-staged-ring128-share-v1"
  expect_error(.exact_gc_validate_result(state, swapped), "kind")
  binding <- list(analysis_id = "grouped", artifact = f$artifact, contract = f$transport,
    contract_hash = f$source_hash, semantic_key = .dsvert_dp_glm_grid_cross_key(f$manifest, f$artifact, f$transport),
    peer_binding_digest = f$ss$.exact_gc_peer_binding_digest, stage = stage, worker_input = "opaque-native-input")
  f$ss$.dp_lmm_grid_cross <- list(grouped = binding)
  con <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  DBI::dbExecute(con, paste("CREATE TABLE source_cross_grid_records (capsule_id TEXT, analysis_id TEXT,",
    "batch_index INTEGER, record_json TEXT NOT NULL, row_mac TEXT NOT NULL, PRIMARY KEY(capsule_id,analysis_id,batch_index))"))
  local_mocked_bindings(
    .dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con),
    .dsvert_dp_lmm_cross_public = function(binding, policy, phase, extra = list()) c(list(phase = phase), extra),
    .exact_gc_consume_output = function(...) value)
  expect_false(.dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")$persisted)
  input <- f$ss$.exact_gc_inputs[[stage$source_key]]
  expect_identical(input$grouped_glmm, binding$worker_input)
  expect_null(input$grouped_lmm)
  expect_identical(input$allowed_spec$output_kind, "grouped-glmm-staged-ring128-share-v1")
  .dsvert_dp_lmm_cross_store(f$policy, f$secret, f$ss, "grouped")
  expect_true(.dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")$persisted)
  first <- .dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped")
  expect_identical(.dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped"), first)
  record <- .dsvert_dp_lmm_cross_record(con, f$secret, f$manifest, f$artifact, f$transport)
  expect_identical(record$version, "glmm-staged-complete-result-v1")
  expect_identical(record$validity_share, result$validity_share)
  public <- .dsvert_dp_lmm_cross_public_record(f$policy, f$secret, f$manifest, f$transport)
  expect_identical(public$version, "glmm-staged-terminal-binding-v1")
  expect_false(any(c("share", "validity_share") %in% names(public)))
  changed <- public
  changed$version <- "lmm-staged-terminal-binding-v1"
  expect_error(.dsvert_dp_lmm_cross_public_record_validate(changed, f$manifest, f$artifact, f$transport))
  chunk <- list(offset = 0, count = f$artifact$coordinate_count + 1L)
  injected <- .dsvert_dp_lmm_cross_inject(con, f$secret, f$manifest, f$transport,
    chunk, raw(chunk$count * 16L), f$policy)
  expect_identical(attr(injected, "dsvert_staged_source")$stage_plan_digest, stage$stage_plan_digest)
  expect_identical(attr(injected, "dsvert_staged_source")$stage_receipt, result$stage_receipt)
})
