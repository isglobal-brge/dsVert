.count_analysis_identity_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.count_analysis_config <- function(k = 3L, id_column = "patient_id") {
  peers <- paste0("site_", seq_len(k))
  pins <- stats::setNames(vapply(
    seq_along(peers), .count_analysis_identity_pk, character(1L)), peers)
  list(
    version = "dsvert-dp-count-config-v1",
    domain = "study-domain",
    cohort_id = "cohort-v1",
    dataset_id = "cohort-table",
    dataset_version = "v1",
    privacy_unit_column = id_column,
    alignment_purpose = "patient-record-alignment-v1",
    max_records_per_unit = 1,
    overflow_policy = "reject_operation",
    privacy = list(epsilon = 1, delta = 1e-6),
    calibration = list(implementation_delta = 1e-9),
    peer_pins = pins,
    backend_build_sha256 = strrep("a", 64L),
    transport_chunk_coordinates = 4096)
}

.count_analysis_plan <- function(
    epsilon, delta, sensitivity_steps, coordinate_count,
    bernoulli_bits, max_steps) {
  list(
    version = "dsvert-joint-dp-laplace-plan-v2",
    sampler = "hkdf-sha256-aes128ctr-two-geometric-tv-v2",
    bernoulli_bits = as.integer(bernoulli_bits),
    stop_numerator = "51",
    max_geometric_steps = 76L,
    sensitivity_steps = as.character(sensitivity_steps),
    coordinate_count = as.integer(coordinate_count),
    epsilon_effective_upper_numerator = "1",
    epsilon_effective_upper_denominator = "1",
    implementation_delta_numerator = "1",
    implementation_delta_denominator = "1000000000",
    implementation_delta_bound = "1/1000000000",
    accounting = "exact-rational finite sampler certificate",
    bernoulli_trials = 608L,
    aes_blocks = 38L,
    capability_available = FALSE,
    unavailable_reason = "worker promotion is a separate milestone")
}

.count_analysis_token <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.count_analysis_psi_contract <- function(config, run_index = 1L) {
  source <- list(
    alignment_purpose = config$alignment_purpose,
    dataset_id = config$dataset_id,
    dataset_version = config$dataset_version,
    id_column = config$privacy_unit_column)
  source$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(source), algo = "sha256", serialize = FALSE))
  peers <- sort(names(config$peer_pins), method = "radix")
  run_hash <- function(label) digest::digest(
    paste0(label, "|", run_index), algo = "sha256", serialize = FALSE)
  c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = run_hash("contract"),
    attestation_id = paste0("attest_", run_hash("attestation")),
    policy_id = paste0("policy_", run_hash("policy"))), source, list(
    pinset_id = .psi_padded_pinset_id(as.list(config$peer_pins)),
    capacity = 64L,
    relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = peers,
    reference_peer = peers[[1L]],
    compute_peers = peers[1:2]))
}

.count_analysis_aligned <- function(
    ids, config, token_index = 1L, run_index = 1L,
    private_offset = 0L) {
  data <- data.frame(
    privacy_unit_id = ids,
    private_value = private_offset + seq_along(ids),
    stringsAsFactors = FALSE)
  names(data)[[1L]] <- config$privacy_unit_column
  .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(
      data, config$privacy_unit_column,
      .count_analysis_token(token_index)),
    .count_analysis_psi_contract(config, run_index))
}

.count_analysis_signature <- function(message, identity_pk) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(identity_pk), object = message,
    algo = "sha512", serialize = FALSE, raw = TRUE))
}

.count_analysis_signer <- function(message, peer_name, identity_pk) {
  .count_analysis_signature(message, identity_pk)
}

.count_analysis_verifier <- function(
    message, identity_pk, signature, peer_name) {
  identical(signature, .count_analysis_signature(message, identity_pk))
}

.count_analysis_receipts <- function(
    config, ids = c("p1", "p2", "p3"), token_index = 1L,
    run_index = 1L, private_offset = 0L,
    planner = .count_analysis_plan) {
  data <- .count_analysis_aligned(
    ids, config, token_index = token_index, run_index = run_index,
    private_offset = private_offset)
  receipts <- lapply(seq_along(config$peer_pins), function(index) {
    peer <- names(config$peer_pins)[[index]]
    identity_seed <- as.raw(rep(index + 20L, 32L))
    identity_pk <- unname(config$peer_pins[[peer]])
    draft <- testthat::with_mocked_bindings(
      .dsvert_dp_count_local_draft_v1(
        data, config, peer, .planner = planner),
      .get_identity_seed = function() jsonlite::base64_enc(identity_seed),
      .get_identity_keypair = function() list(identity_pk = identity_pk),
      .package = "dsVert")
    .dsvert_dp_count_sign_receipt_v1(
      draft, .signer = .count_analysis_signer)
  })
  stats::setNames(receipts, names(config$peer_pins))
}

.count_analysis_resign <- function(receipt) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  .dsvert_dp_count_sign_receipt_v1(
    unsigned, .signer = .count_analysis_signer)
}

test_that("Count config is closed and stateless", {
  config <- .count_analysis_config(3L)
  validated <- .dsvert_dp_count_config_validate_v1(config)
  expect_identical(names(validated), sort(names(config), method = "radix"))
  expect_identical(length(validated$peer_pins), 3L)

  extra <- config
  extra$unexpected_state <- 10
  expect_error(
    .dsvert_dp_count_config_validate_v1(extra), "Count configuration")

  invalid_delta <- config
  invalid_delta$calibration$implementation_delta <-
    invalid_delta$privacy$delta * 2
  expect_error(
    .dsvert_dp_count_config_validate_v1(invalid_delta),
    "implementation delta")

  duplicate_pin <- config
  duplicate_pin$peer_pins[[2L]] <- duplicate_pin$peer_pins[[1L]]
  expect_error(
    .dsvert_dp_count_config_validate_v1(duplicate_pin), "peer pins")

  product_formals <- names(formals(.dsvert_dp_count_local_draft_v1))
  expect_false(any(grepl("key|secret", product_formals, ignore.case = TRUE)))
})

test_that("Count drafts use validated PSI membership, not run randomness", {
  config <- .count_analysis_config(3L)
  members <- c(
    "patient-member-alpha-unique", "patient-member-beta-unique",
    "patient-member-gamma-unique")
  first <- .count_analysis_receipts(
    config, ids = members, token_index = 1L, run_index = 1L)
  restart <- .count_analysis_receipts(
    config, ids = members, token_index = 1L, run_index = 1L)
  rerun <- .count_analysis_receipts(
    config, ids = members, token_index = 2L, run_index = 2L,
    private_offset = 100L)
  first_contract <- .dsvert_dp_count_compile_v1(
    first, config, .verifier = .count_analysis_verifier)
  restart_contract <- .dsvert_dp_count_compile_v1(
    restart, config, .verifier = .count_analysis_verifier)
  rerun_contract <- .dsvert_dp_count_compile_v1(
    rerun, config, .verifier = .count_analysis_verifier)

  expect_false(identical(first[[1L]]$psi_run_sha256,
                         rerun[[1L]]$psi_run_sha256))
  expect_identical(first[[1L]]$snapshot_commitment,
                   restart[[1L]]$snapshot_commitment)
  expect_identical(first_contract, restart_contract)
  expect_identical(first[[1L]]$snapshot_commitment,
                   rerun[[1L]]$snapshot_commitment)
  expect_identical(first_contract$artifact_key, rerun_contract$artifact_key)
  expect_identical(first_contract, rerun_contract)

  renamed_config <- .count_analysis_config(3L, "subject_id")
  renamed <- .count_analysis_receipts(
    renamed_config, ids = members, token_index = 4L, run_index = 4L)
  renamed_contract <- .dsvert_dp_count_compile_v1(
    renamed, renamed_config, .verifier = .count_analysis_verifier)
  expect_false(identical(first[[1L]]$config_sha256,
                         renamed[[1L]]$config_sha256))
  expect_identical(first_contract$artifact_key,
                   renamed_contract$artifact_key)
  expect_identical(first_contract$semantic, renamed_contract$semantic)

  changed <- .count_analysis_receipts(
    config, ids = c(members[1:2], "patient-member-delta-unique"),
    token_index = 3L, run_index = 3L)
  changed_contract <- .dsvert_dp_count_compile_v1(
    changed, config, .verifier = .count_analysis_verifier)
  expect_false(identical(first_contract$artifact_key,
                         changed_contract$artifact_key))

  leaked <- .dsvert_dp_canonical_json(first)
  expect_false(any(vapply(
    members, grepl, logical(1L), x = leaked, fixed = TRUE)))

  unattested <- data.frame(patient_id = c("p1", "p2"))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_local_draft_v1(
      unattested, config, "site_1", .planner = .count_analysis_plan),
    .get_identity_seed = function() jsonlite::base64_enc(
      as.raw(rep(21L, 32L))),
    .get_identity_keypair = function() list(
      identity_pk = unname(config$peer_pins[["site_1"]])),
    .package = "dsVert"), "PSI-aligned|attestation")
})

test_that("Count receipts require exact signatures, K and PSI consensus", {
  config <- .count_analysis_config(3L)
  receipts <- .count_analysis_receipts(config)
  expect_silent(lapply(receipts, .dsvert_dp_count_receipt_verify_v1,
                       config = config,
                       .verifier = .count_analysis_verifier))

  tampered <- receipts
  tampered[[1L]]$snapshot_commitment <- strrep("f", 64L)
  expect_error(.dsvert_dp_count_compile_v1(
    tampered, config, .verifier = .count_analysis_verifier), "signature")

  expect_error(.dsvert_dp_count_compile_v1(
    receipts[-1L], config, .verifier = .count_analysis_verifier),
    "exactly one signed receipt")

  duplicate <- receipts
  duplicate[[2L]] <- duplicate[[1L]]
  expect_error(.dsvert_dp_count_compile_v1(
    duplicate, config, .verifier = .count_analysis_verifier),
    "receipt coverage")

  wrong_pin <- receipts
  wrong_pin[[1L]]$peer_identity_pk <- config$peer_pins[[2L]]
  wrong_pin[[1L]] <- .count_analysis_resign(wrong_pin[[1L]])
  expect_error(.dsvert_dp_count_compile_v1(
    wrong_pin, config, .verifier = .count_analysis_verifier), "pinned")

  different_run <- receipts
  other_run <- .count_analysis_receipts(
    config, token_index = 7L, run_index = 7L)
  different_run[[3L]] <- other_run[[3L]]
  expect_error(.dsvert_dp_count_compile_v1(
    different_run, config, .verifier = .count_analysis_verifier),
    "PSI run")
})

test_that("Count planner receives implementation delta and proves exact bounds", {
  config <- .count_analysis_config(2L)
  calls <- list()
  planner <- function(epsilon, delta, sensitivity_steps, coordinate_count,
                      bernoulli_bits, max_steps) {
    calls[[length(calls) + 1L]] <<- list(
      epsilon = epsilon, delta = delta,
      sensitivity_steps = sensitivity_steps,
      coordinate_count = coordinate_count,
      bernoulli_bits = bernoulli_bits, max_steps = max_steps)
    .count_analysis_plan(
      epsilon, delta, sensitivity_steps, coordinate_count,
      bernoulli_bits, max_steps)
  }
  receipts <- .count_analysis_receipts(config, planner = planner)
  expect_length(calls, 2L)
  expect_true(all(vapply(calls, function(call) {
    identical(call$delta,
              .dsvert_dp_count_decimal_text(
                config$calibration$implementation_delta)) &&
      !identical(call$delta,
                 .dsvert_dp_count_decimal_text(config$privacy$delta))
  }, logical(1L))))
  contract <- .dsvert_dp_count_compile_v1(
    receipts, config, .verifier = .count_analysis_verifier)
  certificate <- contract$semantic$analysis$effective_arguments$sampler_plan
  expect_identical(certificate$implementation_delta_numerator, "1")
  expect_identical(certificate$implementation_delta_denominator,
                   "1000000000")

  excessive <- function(...) {
    plan <- .count_analysis_plan(...)
    plan$implementation_delta_numerator <- "2"
    plan$implementation_delta_bound <- "2/1000000000"
    plan
  }
  data <- .count_analysis_aligned(c("p1", "p2"), config)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_local_draft_v1(
      data, config, "site_1", .planner = excessive),
    .get_identity_seed = function() jsonlite::base64_enc(
      as.raw(rep(21L, 32L))),
    .get_identity_keypair = function() list(
      identity_pk = unname(config$peer_pins[["site_1"]])),
    .package = "dsVert"), "implementation delta certificate")
})

test_that("Count contracts have one vertical count for K=2,3,5", {
  for (k in c(2L, 3L, 5L)) {
    config <- .count_analysis_config(k)
    receipts <- .count_analysis_receipts(config)
    contract <- .dsvert_dp_count_compile_v1(
      receipts, config, .verifier = .count_analysis_verifier)
    expect_identical(
      contract, .dsvert_dp_analysis_contract_validate_v1(contract))
    expect_identical(contract$semantic$public_shape, list(count = 1))
    expect_identical(
      contract$semantic$analysis$effective_arguments$statistic,
      "aligned_privacy_unit_count")
    expect_identical(
      contract$semantic$analysis$effective_arguments$owner_combination,
      "vertical_membership_once_v1")
    expected_authorities <- sort(
      unname(config$peer_pins), method = "radix")[1:2]
    expect_identical(
      unlist(contract$semantic$noise_authorities, use.names = FALSE),
      unname(expected_authorities))
    expect_identical(length(contract$semantic$owner_snapshots), k)
  }
})
