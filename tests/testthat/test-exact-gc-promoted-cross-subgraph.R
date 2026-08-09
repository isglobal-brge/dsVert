test_that("the real production guard admits only the promoted cross subgraph", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)

  promoted <- c(
    "exactGCVecmulClaimInputsDS", "exactGCVecmulStartDS",
    "exactGCVecmulValidityDS", "exactGCVecmulValidityReceiveDS",
    "exactGCVecmulCommitDS", "exactGCCleanupDS")
  for (consortium_size in 2:5) {
    for (endpoint in promoted) {
      expect_invisible(.dsvert_test_production_gate(endpoint))
    }
  }

  blocked <- c(
    "exactGCVecmulBindInputsDS", "exactGCGLMSoftplusPrepareDS",
    "mpcCleanupDS")
  for (endpoint in blocked) {
    expect_error(
      .dsvert_test_production_gate(endpoint),
      "single disclosure-safe profile", fixed = TRUE)
  }
})

test_that("production vecmul authority requires a live cross producer manifest", {
  testthat::local_mocked_bindings(
    .exact_gc_vecmul_compatibility_test_mode = function() FALSE,
    .package = "dsVert")

  handle <- paste0("A", strrep("a", 42L))
  categorical_purpose <- paste0(
    "dp.categorical-cross.", strrep("b", 20L), ".cell-products")
  gaussian_purpose <- paste0(
    "dp.gaussian-cross.", strrep("c", 20L), ".validity-0001")
  stage <- list(
    producer = "dp.categorical-cross.v1",
    purpose = categorical_purpose,
    manifest_handle = handle)
  expect_invisible(.exact_gc_vecmul_require_promoted_stage(stage))
  expect_invisible(.exact_gc_vecmul_require_promoted_stage(list(
    producer = "dp.gaussian-cross.v1", purpose = gaussian_purpose,
    manifest_handle = handle)))

  rejected <- list(
    within(stage, producer <- "legacy.remote-slot-bind.v2"),
    within(stage, producer <- "glm.binomial-softplus.v1"),
    within(stage, purpose <- paste0(categorical_purpose, ".extra")),
    within(stage, manifest_handle <- NULL),
    list(
      producer = "dp.gaussian-cross.v1",
      purpose = paste0(
        "dp.gaussian-cross.", strrep("c", 20L), ".validity-1"),
      manifest_handle = handle))
  for (candidate in rejected) {
    expect_error(
      .exact_gc_vecmul_require_promoted_stage(candidate),
      "not promoted", fixed = TRUE)
  }

  manifest <- list(
    producer = stage$producer, purpose = stage$purpose,
    total_n = 12L, ring_bits = 128L, frac_bits = 8L,
    x_key = "cross_x", y_key = "cross_y", output_key = "cross_z",
    context_hash = strrep("d", 64L), plan_id = strrep("e", 64L))
  record <- list(
    status = "prepared", producer = manifest$producer,
    purpose = manifest$purpose, manifest_handle = handle,
    total_n = manifest$total_n, ring_bits = manifest$ring_bits,
    frac_bits = manifest$frac_bits, x_key = manifest$x_key,
    y_key = manifest$y_key, output_key = manifest$output_key,
    minted = list(
      manifest_handle = handle, context_hash = manifest$context_hash,
      plan_id = manifest$plan_id))
  ss <- new.env(parent = emptyenv())
  ss$.dp_categorical_cross_stage <- record
  expect_invisible(.exact_gc_vecmul_require_promoted_manifest(
    ss, manifest, handle))

  ss$.dp_categorical_cross_stage$status <- "preparing"
  expect_error(.exact_gc_vecmul_require_promoted_manifest(
    ss, manifest, handle), "producer capability is invalid", fixed = TRUE)
  ss$.dp_categorical_cross_stage <- record
  ss$.dp_categorical_cross_stage$minted$plan_id <- strrep("f", 64L)
  expect_error(.exact_gc_vecmul_require_promoted_manifest(
    ss, manifest, handle), "producer capability is invalid", fixed = TRUE)

  batch <- "op_11111111111111111111111111111111"
  policy_id <- strrep("1", 64L)
  plan_id <- strrep("2", 64L)
  operation <- .exact_gc_checked_mul_chunk_operation(
    batch, 1L, 1L, policy_id, plan_id)
  contract_ss <- new.env(parent = emptyenv())
  contract_ss$.exact_gc_vecmul_input_stages <- list()
  contract_ss$.exact_gc_vecmul_input_stages[[batch]] <- list(
    producer = "legacy.remote-slot-bind.v2",
    purpose = .DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE,
    manifest_handle = NULL, total_n = 1L, policy_id = policy_id,
    plan = list(
      plan_id = plan_id, max_chunk = 16L, ring_bits = 128L,
      frac_bits = 8L))
  expect_error(.exact_gc_checked_mul_contract(
    contract_ss, batch, operation, 1L, 1L, 1L, 1L,
    policy_id, plan_id), "not promoted", fixed = TRUE)
})

test_that("purpose-bound cleanup deletes only its signed exact session", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)

  storage <- new.env(parent = emptyenv())
  expected_signature <- strrep("A", 86L)
  testthat::local_mocked_bindings(
    .get_identity_keypair = function() list(
      identity_pk = "test-public-key", identity_sk = "test-secret-key"),
    .dsvert_relay_sign_message = function(message, secret_key) {
      expected_signature
    },
    .dsvert_relay_verify_message = function(message, public_key, signature) {
      identical(signature, expected_signature)
    },
    .session_storage = function() storage,
    .package = "dsVert")

  session_a <- "11111111-1111-4111-8111-111111111111"
  session_b <- "22222222-2222-4222-8222-222222222222"
  make_session <- function(digest_character) {
    value <- new.env(parent = emptyenv())
    value$.exact_gc_peer_binding_digest <- strrep(digest_character, 64L)
    value
  }
  storage[[session_a]] <- make_session("a")
  storage[[session_b]] <- make_session("b")
  capability_a <- .exact_gc_cleanup_capability_create(
    storage[[session_a]], session_a,
    .DSVERT_EXACT_GC_CROSS_CLEANUP_PURPOSE)
  capability_b <- .exact_gc_cleanup_capability_create(
    storage[[session_b]], session_b,
    .DSVERT_EXACT_GC_CROSS_CLEANUP_PURPOSE)

  expect_error(
    exactGCCleanupDS(session_b, .dsvert_dsi_text_encode(capability_a)),
    "capability-bound cleanup failed", fixed = TRUE)
  expect_true(exists(session_a, envir = storage, inherits = FALSE))
  expect_true(exists(session_b, envir = storage, inherits = FALSE))

  first <- exactGCCleanupDS(
    session_a, .dsvert_dsi_text_encode(capability_a))
  expect_identical(first$state, "cleaned")
  expect_false(exists(session_a, envir = storage, inherits = FALSE))
  replay <- exactGCCleanupDS(
    session_a, .dsvert_dsi_text_encode(capability_a))
  expect_identical(replay$state, "already_cleaned")
  expect_true(exists(session_b, envir = storage, inherits = FALSE))

  decoded <- jsonlite::fromJSON(capability_b, simplifyVector = FALSE)
  decoded$signature <- strrep("B", 86L)
  tampered <- .dsvert_dp_canonical_json(decoded)
  expect_error(
    exactGCCleanupDS(session_b, .dsvert_dsi_text_encode(tampered)),
    "capability-bound cleanup failed", fixed = TRUE)
  expect_true(exists(session_b, envir = storage, inherits = FALSE))

  second <- exactGCCleanupDS(
    session_b, .dsvert_dsi_text_encode(capability_b))
  expect_identical(second$state, "cleaned")
  expect_false(exists(session_b, envir = storage, inherits = FALSE))

  session_c <- "33333333-3333-4333-8333-333333333333"
  expect_error(.exact_gc_cleanup_capability_create(
    make_session("c"), session_c, "analyst-selected-purpose"),
    "purpose is unavailable", fixed = TRUE)
})
