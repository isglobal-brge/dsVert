.phase19_fake_x25519 <- function(byte, counter = NULL) {
  if (!is.null(counter)) counter$value <- counter$value + 1L
  raw <- as.raw(rep(as.integer(byte) %% 256L, 32L))
  value <- gsub("[\r\n]", "", jsonlite::base64_enc(raw))
  list(public_key = value, secret_key = value)
}

.phase19_fake_derive <- function(command, input) {
  stopifnot(identical(command, "exact-gc-derive-master"))
  if (!identical(input$local_secret, input$local_public)) {
    stop("test X25519 keypair mismatch", call. = FALSE)
  }
  list(
    master_key = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(7L, 32L)))),
    context_hash = digest::digest(
      input$session_id, algo = "sha256", serialize = FALSE))
}

test_that("Phase-1.9 recipient X25519 bootstrap is persistent and automatic", {
  root <- tempfile("formal-glm-phase19-recipient-")
  dir.create(root, mode = "0700")
  counter <- new.env(parent = emptyenv())
  counter$value <- 0L
  byte <- 11L
  keygen <- function(command, input) {
    expect_identical(command, "transport-keygen")
    expect_identical(input, list())
    value <- .phase19_fake_x25519(byte, counter)
    byte <<- byte + 1L
    value
  }

  first <- .dsvert_formal_glm_phase19_init_recipient_key(
    root, keygen = keygen, derive = .phase19_fake_derive)
  second <- .dsvert_formal_glm_phase19_init_recipient_key(
    root, keygen = keygen, derive = .phase19_fake_derive)
  expect_identical(first, second)
  expect_identical(counter$value, 1L)
  path <- .dsvert_formal_glm_phase19_recipient_key_path(root)
  expect_true(file.exists(path))
  expect_identical(bitwAnd(as.integer(file.info(path)$mode), 63L), 0L)

  unlink(path)
  rotated <- .dsvert_formal_glm_phase19_init_recipient_key(
    root, keygen = keygen, derive = .phase19_fake_derive)
  expect_false(identical(rotated$key_id, first$key_id))
  expect_identical(counter$value, 2L)

  writeLines("{}", path, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  expect_error(
    .dsvert_formal_glm_phase19_init_recipient_key(
      root, keygen = keygen, derive = .phase19_fake_derive),
    class = "dsvert_formal_glm_phase18_error")
  expect_identical(counter$value, 2L)
})

.phase19_private_result_fixture <- function(k = 2L) {
  h <- function(letter) strrep(letter, 64L)
  state <- new.env(parent = emptyenv())
  state$vector_len <- 2L
  state$formal_plan_sha256 <- h("b")
  state$formal_kernel_spec_sha256 <- h("c")
  state$formal_runtime_root_sha256 <- h("c")
  state$formal_semantic_root_sha256 <- h("6")
  state$formal_recipient <- "peer_a"
  state$worker_heartbeat_session <- h("d")
  state$formal_pre_execution_sha256 <- h("e")
  state$formal_global_materialization_root <- h("f")
  state$formal_run_id <- h("1")
  state$formal_pinset_sha256 <- h("2")
  state$formal_compute_peers <- c("peer_a", "peer_b")
  state$formal_custodian_count <- as.integer(k)
  state$formal_capsule_sha256 <- h("7")
  state$formal_snapshot_sha256 <- h("5")
  state$formal_garbler_peer_name <- "peer_a"
  state$formal_garbler_peer_id <- paste0("dsv1_", h("a"))
  state$formal_evaluator_peer_name <- "peer_b"
  state$formal_evaluator_peer_id <- paste0("dsv1_", h("b"))
  state$formal_adjacency <- "add_remove"
  state$formal_source_ring_bits <- 128L
  state$formal_source_frac_bits <- 8L
  state$formal_final_step_index <- 3L
  context <- h("a")
  receipt_signature <- gsub("[\r\n]", "", jsonlite::base64_enc(
    as.raw(rep(17L, 64L))))
  final_receipts <- lapply(state$formal_compute_peers, function(peer) list(
    version = .DSVERT_FORMAL_GLM_PHASE19_RECEIPT_VERSION,
    plan_sha256 = state$formal_plan_sha256,
    peer = peer, step_index = state$formal_final_step_index,
    attempt_id = h("6"), state_sha256 = h(if (peer == "peer_a") "8" else "9"),
    transcript_sha256 = h("4"), signature = receipt_signature))
  final_receipt_pair_sha256 <-
    .dsvert_formal_glm_phase19_receipt_pair_sha256(final_receipts, state)
  certificate <- list(
    version = .DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_VERSION,
    kind = .DSVERT_FORMAL_GLM_PHASE16_CERTIFICATE_KIND,
    status = "machine_proven", norm = "l2",
    selected_proof = .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF,
    selected_bound_steps = "8",
    policy_sha256 = state$formal_kernel_spec_sha256,
    phase15_plan_sha256 = state$formal_plan_sha256,
    theorem_sha256 = h("6"), adjacency = state$formal_adjacency,
    coordinate_count = 2L, source_frac_bits = 8L,
    output_lattice_bits = 8L,
    quantization_shift = 0L,
    quantization = paste0(
      "clip_box_then_coordinatewise_signed_floor_then_",
      "public_translation_v1"),
    shifted_upper_bounds = list("20", "20"),
    universal_coordinate_bounds = list("20", "20"),
    universal_l2_squared = "800", universal_bound_steps = "29",
    recurrence_quantized_bounds = list("5", "5"),
    recurrence_l2_squared = "50", recurrence_bound_steps = "8",
    quantization_inequality = paste0(
      "abs(floor(x/d)-floor(y/d))<=ceil(abs(x-y)/d)_",
      "per_coordinate_v1"),
    selection = "minimum_of_machine_proven_positive_integer_l2_bounds_v1")
  certificate_sha256 <- .dsvert_formal_glm_phase19_prefixed_json_sha256(
    "dsVert/joint-dp/machine-proven-integer-lattice-l2-certificate/v1|",
    certificate)
  sensitivity <- function(proof, bound) list(
    version = "dsvert-formal-glm-phase15-dp-sensitivity-v1",
    status = "machine_proven", proof = proof, bound_steps = bound,
    theorem_sha256 = h("6"))
  bridge <- list(
    version = .DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_VERSION,
    phase15_plan_sha256 = state$formal_plan_sha256,
    final_receipt_pair_sha256 = final_receipt_pair_sha256,
    execution_transcript_sha256 = h("4"), snapshot_sha256 = h("5"),
    pinset_sha256 = state$formal_pinset_sha256,
    garbler_peer_name = state$formal_garbler_peer_name,
    garbler_peer_id = state$formal_garbler_peer_id,
    evaluator_peer_name = state$formal_evaluator_peer_name,
    evaluator_peer_id = state$formal_evaluator_peer_id,
    role_selection = "lexicographic_pinned_cryptographic_peer_id_v1",
    adjacency = "add_remove",
    source_ring_bits = 128L, source_frac_bits = 8L,
    output_ring_bits = 128L, output_lattice_bits = 8L,
    quantization_shift = 0L, coordinate_count = 2L,
    shifted_upper_bounds = list("20", "20"),
    universal_sensitivity = sensitivity(
      .DSVERT_FORMAL_GLM_PHASE16_UNIVERSAL_PROOF, "29"),
    tight_sensitivity = sensitivity(
      .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF, "8"),
    selected_sensitivity_steps = "8",
    selected_sensitivity_proof =
      .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF,
    selected_sensitivity_certificate = certificate,
    selected_sensitivity_certificate_sha256 = certificate_sha256,
    sensitivity_selection = "minimum_of_machine_proven_bounds_only_v1",
    quantization =
      "signed_floor_then_public_box_translation_inside_exact_gc_v1",
    intermediate_output =
      "sealed_nonnegative_ring128_additive_shares_only_v1",
    authenticated_opening =
      "blocked_until_common_glm_release_capsule_e2e_v1",
    production_ready = FALSE)
  token <- list(
    version = .DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_VERSION,
    context_sha256 = context, capsule_sha256 = state$formal_capsule_sha256,
    phase15_plan_sha256 = state$formal_plan_sha256,
    pre_execution_token_sha256 = state$formal_pre_execution_sha256,
    run_id = state$formal_run_id,
    pinset_sha256 = state$formal_pinset_sha256,
    global_materialization_root =
      state$formal_global_materialization_root,
    fan_in_transcript_sha256 = h("8"),
    block_commitment_root_sha256 = h("9"),
    block_receipt_root_sha256 = h("0"), accumulator_root = h("a"),
    execution_receipt_pair_sha256 = h("b"),
    final_receipt_set_seal = h("c"), checkpoint_evidence_seal = h("d"),
    phase15_execution_transcript_sha256 = h("4"),
    final_checkpoint_transcript_sha256 = h("4"),
    worker_transcript_sha256 = h("1"), post_execution_root_sha256 = h("2"),
    token_sha256 = "", custodian_count = as.integer(k),
    compute_peers = as.list(state$formal_compute_peers),
    fan_in_executed = TRUE, exact_all_k_validity_inside_gc = TRUE,
    consensus_compared_inside_gc = TRUE, full_tuple_mask_inside_gc = TRUE,
    execution_valid_sealed = TRUE, execution_validity_opened = FALSE,
    patient_dependent_digests_exposed = FALSE,
    protected_data_e2e_verified = FALSE, opening_authorized = FALSE,
    openings_performed = 0L,
    dp_release_status = .DSVERT_FORMAL_GLM_PHASE19_DP_STATUS,
    remaining_blockers = as.list(.DSVERT_FORMAL_GLM_PHASE19_BLOCKERS),
    production_ready = FALSE)
  token$token_sha256 <- .dsvert_formal_glm_phase19_prefixed_json_sha256(
    .DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_DOMAIN, token)
  pair <- list(
    version = .DSVERT_FORMAL_GLM_PHASE19_EXECUTION_PAIR_VERSION,
    context_sha256 = context, accumulator_root = h("a"),
    garbler_receipt_sha256 = h("4"), evaluator_receipt_sha256 = h("5"),
    execution_receipt_pair_sha256 = h("b"),
    execution_valid_sealed = TRUE, execution_validity_opened = FALSE,
    openings_performed = 0L, production_ready = FALSE)
  result <- list(
    version = .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_VERSION,
    kind = .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_KIND,
    context_sha256 = context, plan_sha256 = state$formal_plan_sha256,
    semantic_root_sha256 = state$formal_semantic_root_sha256,
    schedule_root_sha256 = state$formal_runtime_root_sha256,
    peer = state$formal_recipient,
    attempt_id = state$worker_heartbeat_session,
    final_receipts = final_receipts,
    dp_bridge = bridge,
    dp_share = gsub("[\r\n]", "", jsonlite::base64_enc(raw(32L))),
    post_execution_token = token, post_execution_token_seal = h("4"),
    execution_receipt_pair = pair, execution_receipt_pair_seal = h("5"),
    handoff_sha256 = h("3"), handoff_bytes = 128L,
    handoff_replayed = FALSE,
    execution_valid_sealed = TRUE, execution_validity_opened = FALSE,
    openings_performed = 0L, production_ready = FALSE)
  list(state = state, result = result)
}

test_that("Phase-1.9 private result cannot become a generic exact-GC output", {
  expect_true(
    "registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1" %in%
      .DSVERT_FORMAL_GLM_PHASE19_BLOCKERS)
  expect_false(
    "runtime_wiring_phase18_durable_inbox_to_phase19_verified_block_v2" %in%
      .DSVERT_FORMAL_GLM_PHASE19_BLOCKERS)
  for (k in c(2L, 3L, 4L, 5L)) {
    k_fixture <- .phase19_private_result_fixture(k)
    expect_invisible(.dsvert_formal_glm_phase19_validate_result(
      k_fixture$state, k_fixture$result))
    replayed <- k_fixture$result
    replayed$handoff_replayed <- TRUE
    expect_invisible(.dsvert_formal_glm_phase19_validate_result(
      k_fixture$state, replayed))
    expect_false(.dsvert_formal_glm_phase19_phase15_binding(
      k_fixture$state, k_fixture$result)$production_ready)
  }
  fixture <- .phase19_private_result_fixture()
  expect_invisible(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, fixture$result))
  phase15 <- .dsvert_formal_glm_phase19_phase15_binding(
    fixture$state, fixture$result)
  expect_identical(phase15$plan_sha256,
                   fixture$result$dp_bridge$phase15_plan_sha256)
  expect_identical(phase15$final_receipt_pair_sha256,
                   fixture$result$dp_bridge$final_receipt_pair_sha256)
  expect_identical(phase15$execution_transcript_sha256,
                   fixture$result$dp_bridge$execution_transcript_sha256)
  expect_identical(phase15$opening,
                   "none_sealed_bridge_shares_only_v1")
  expect_false(phase15$production_ready)
  release_error <- tryCatch(
    .dsvert_formal_glm_phase15_dp_release_compile(phase15),
    error = identity)
  expect_s3_class(release_error, "dsvert_formal_glm_dp_release_unavailable")
  expect_identical(release_error$openings_performed, 0L)
  expect_false(release_error$production_ready)
  tampered <- fixture$result
  tampered$execution_validity_opened <- TRUE
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, tampered), "Invalid private")
  disclosed <- fixture$result
  disclosed$beta <- list("1", "2")
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, disclosed), "Invalid private")
  changed_receipt <- fixture$result
  changed_receipt$final_receipts[[1L]]$transcript_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, changed_receipt), "different executions")
  changed_certificate <- fixture$result
  changed_certificate$dp_bridge$selected_sensitivity_certificate$
    recurrence_quantized_bounds[[1L]] <- "6"
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, changed_certificate), "certificate digest changed")
  changed_token <- fixture$result
  changed_token$post_execution_token$phase15_execution_transcript_sha256 <-
    strrep("e", 64L)
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, changed_token), "post-execution token")
  changed_blocker <- fixture$result
  changed_blocker$post_execution_token$remaining_blockers <- list("ready")
  expect_error(.dsvert_formal_glm_phase19_validate_result(
    fixture$state, changed_blocker), "post-execution token")

  ss <- new.env(parent = emptyenv())
  spool <- tempfile("formal-glm-phase19-result-")
  dir.create(spool, mode = "0700")
  fixture$state$spool <- spool
  fixture$state$operation_id <- "op_0123456789abcdef0123456789abcdef"
  fixture$state$formal_semantic_root_sha256 <- strrep("6", 64L)
  handoff_dir <- file.path(spool, "phase20-handoff")
  handoff_slot_dir <- file.path(handoff_dir, "records-v1", "aa", "bb")
  dir.create(handoff_slot_dir, recursive = TRUE, mode = "0700")
  Sys.chmod(c(handoff_dir, file.path(handoff_dir, "records-v1"),
              file.path(handoff_dir, "records-v1", "aa"),
              handoff_slot_dir), mode = "0700")
  handoff_path <- file.path(
    handoff_slot_dir, paste0("slot-", strrep("a", 64L), ".bin"))
  handoff_bytes <- as.raw(rep(19L, 128L))
  writeBin(handoff_bytes, handoff_path)
  Sys.chmod(handoff_path, mode = "0600")
  fixture$result$handoff_sha256 <- digest::digest(
    file = handoff_path, algo = "sha256", serialize = FALSE)
  fixture$result$handoff_bytes <- length(handoff_bytes)
  fixture$state$formal_handoff_dir <- handoff_dir
  wrong_handoff <- fixture$result
  wrong_handoff$handoff_sha256 <- strrep("0", 64L)
  expect_error(.dsvert_formal_glm_phase20_handoff_handle(
    fixture$state, wrong_handoff), "changed while it was authenticated")
  hardlink <- paste0(handoff_path, ".hardlink")
  expect_true(file.link(handoff_path, hardlink))
  expect_error(.dsvert_formal_glm_phase20_handoff_handle(
    fixture$state, fixture$result), "single link")
  unlink(hardlink)
  fixture$state$status <- "running"
  .exact_gc_private_file(file.path(spool, "result.json"), charToRaw(
    as.character(jsonlite::toJSON(
      fixture$result, auto_unbox = TRUE, null = "null"))))
  expect_identical(
    .dsvert_formal_glm_phase19_finish(ss, fixture$state), "complete")
  expect_false(file.exists(file.path(spool, "result.json")))
  expect_null(ss$.exact_gc_outputs)
  stored <- ss$.formal_glm_phase19_outputs[[fixture$state$operation_id]]
  expect_false(is.null(stored))
  expect_false(stored$releasable)
  expect_false(stored$phase16_release_available)
  expect_identical(stored$handoff$sha256,
                   fixture$result$handoff_sha256)
  expect_identical(stored$handoff$bytes, 128L)
  expect_null(stored$result)
  expect_null(stored$result_json)
  expect_identical(
    .dsvert_resource_registry$external[[stored$handoff$resource_owner]]$bytes,
    128)
  expect_identical(stored$phase16_release_blocker,
                   .DSVERT_FORMAL_GLM_PHASE15_DP_BLOCKER)
  expect_identical(stored$openings_performed, 0L)
  expect_identical(stored$phase15_binding, phase15)
  .dsvert_formal_glm_phase19_drop_output(ss, fixture$state$operation_id)
  expect_null(ss$.formal_glm_phase19_outputs[[fixture$state$operation_id]])
  original <- paste0(stored$handoff$path, ".original")
  replacement <- paste0(stored$handoff$path, ".replacement")
  writeBin(handoff_bytes, replacement)
  Sys.chmod(replacement, mode = "0600")
  expect_true(file.rename(stored$handoff$path, original))
  expect_true(file.rename(replacement, stored$handoff$path))
  expect_error(.dsvert_formal_glm_phase20_cleanup_handoff(
    stored$handoff), "identity")
  unlink(stored$handoff$path)
  expect_true(file.rename(original, stored$handoff$path))
  expect_invisible(.dsvert_formal_glm_phase20_cleanup_handoff(
    stored$handoff))
  expect_false(file.exists(stored$handoff$path))
  expect_null(.dsvert_resource_registry$external[[
    stored$handoff$resource_owner]])

  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  aggregate <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  exports <- sub("^export\\((.*)\\)$", "\\1", grep(
    "^export\\(", readLines(.dsvert_test_package_file("NAMESPACE")),
    value = TRUE))
  expect_false(any(grepl("formalGLMPhase19", c(aggregate, exports),
                         fixed = TRUE)))
})

test_that("Phase-1.9 private-store bound is exact and is not a query quota", {
  plan <- list(
    kernel = list(coefficient_count = 4L),
    block_capacity = 1L, container_bits = 128L, total_blocks = 10L)
  expect_identical(
    .dsvert_formal_glm_phase19_block_store_bytes(plan), 2130)
  plan$total_blocks <- 1000000
  expect_identical(
    .dsvert_formal_glm_phase19_block_store_bytes(plan), 213000000)
  plan$kernel$coefficient_count <- 5L
  expect_error(
    .dsvert_formal_glm_phase19_block_store_bytes(plan),
    class = "dsvert_formal_glm_phase18_error")
})
