.count_analysis_identity_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.count_analysis_config <- function(
    k = 3L, id_column = "patient_id", count_upper_bound = 10L) {
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
    count_upper_bound = count_upper_bound,
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

.count_analysis_psi_contract <- function(
    config, run_index = 1L, capacity_bucket = 64L) {
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
    capacity = as.integer(capacity_bucket),
    relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = peers,
    reference_peer = peers[[1L]],
    compute_peers = peers[1:2]))
}

.count_analysis_aligned <- function(
    ids, config, token_index = 1L, run_index = 1L,
    private_offset = 0L, capacity_bucket = 64L) {
  data <- data.frame(
    privacy_unit_id = ids,
    private_value = private_offset + seq_along(ids),
    stringsAsFactors = FALSE)
  names(data)[[1L]] <- config$privacy_unit_column
  .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(
      data, config$privacy_unit_column,
      .count_analysis_token(token_index)),
    .count_analysis_psi_contract(
      config, run_index, capacity_bucket = capacity_bucket))
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
    capacity_bucket = 64L, planner = .count_analysis_plan) {
  data <- .count_analysis_aligned(
    ids, config, token_index = token_index, run_index = run_index,
    private_offset = private_offset, capacity_bucket = capacity_bucket)
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

.count_analysis_authorize <- function(
    ss, session_id, config, receipts, identity_pk,
    planner = .count_analysis_plan) {
  testthat::with_mocked_bindings(
    .dsvert_dp_count_authorize_session_v1(
      ss, session_id, config, receipts,
      .verifier = .count_analysis_verifier, .planner = planner),
    .get_identity_keypair = function() list(identity_pk = identity_pk),
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert")
}

.count_compile_runtime_manifest <- function() {
  list(
    schema_version = 1L,
    protocol_version = "dsvert-mpc-runtime-v1",
    runtime_version = "1.1.0",
    api_version = "1.1.0",
    capabilities = list(exact_gc = list(
      available = TRUE,
      capability_id = "exact_gc_v1",
      protocol_version = "dsvert-exact-gc-worker-v4",
      commands = c(
        "joint-dp-laplace-plan-v2",
        "joint-dp-laplace-worker-contract-v2",
        "exact-gc-worker"),
      operations = c("count-guard", "clamp-count", "joint-dp-laplace-v2"),
      core_operations = c(
        "compare-signed", "count-guard", "clamp-count",
        "joint-dp-laplace-v2"))))
}

.count_compile_source_descriptor <- function(config) {
  list(
    id = config$dataset_id,
    version = config$dataset_version,
    id_col = config$privacy_unit_column,
    purpose = config$alignment_purpose,
    snapshot_sha256 = strrep("b", 64L))
}

.count_compile_server_options <- function(
    config, peer_name, source_name = "custodian_source") {
  trusted <- config$peer_pins[names(config$peer_pins) != peer_name]
  list(
    dsvert.peer_name = peer_name,
    dsvert.trusted_peers = trusted,
    dsvert.psi.authorized_sources = stats::setNames(
      list(.count_compile_source_descriptor(config)), source_name),
    dsvert.dp.domain = config$domain,
    dsvert.dp.cohort_id = config$cohort_id,
    dsvert.dp.unit_capacity = config$count_upper_bound,
    dsvert.dp.epsilon = config$privacy$epsilon,
    dsvert.dp.delta = config$privacy$delta,
    dsvert.dp.implementation_delta =
      config$calibration$implementation_delta)
}

.count_compile_endpoint <- function(
    data, config, peer_name, data_name = "D", signer_state = NULL,
    server_options = .count_compile_server_options(config, peer_name)) {
  assign(data_name, data, envir = environment())
  withr::local_options(server_options)
  peer_index <- match(peer_name, names(config$peer_pins))
  identity <- list(
    identity_pk = unname(config$peer_pins[[peer_name]]),
    identity_sk = paste0("test-secret-", peer_name))
  testthat::with_mocked_bindings(
    dsvertDPCountCompileDS(data_name),
    .get_identity_keypair = function() identity,
    .get_identity_seed = function() jsonlite::base64_enc(
      as.raw(rep(peer_index + 40L, 32L))),
    .dsvert_mpc_require_capabilities = function(capabilities) {
      expect_identical(capabilities, "exact_gc")
      .count_compile_runtime_manifest()
    },
    .dsvert_joint_dp_laplace_plan_v2 = .count_analysis_plan,
    .dsvert_relay_sign_message = function(message, identity_sk) {
      expect_identical(identity_sk, identity$identity_sk)
      if (!is.null(signer_state)) {
        signer_state$calls <- signer_state$calls + 1L
      }
      .count_analysis_signature(message, identity_sk)
    },
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .dsvert_dp_alignment_registry_commit = function(...) {
      stop("registry commit must not be called")
    },
    .dsvert_dp_alignment_registry_resolve_templates = function(...) {
      stop("registry resolve must not be called")
    },
    .dsvert_dp_noise_root = function(...) stop("noise root must not be called"),
    .package = "dsVert")
}

.count_fixed_compile_endpoint <- function(
    data, config, peer_name, fixed_cohort_size = nrow(data),
    data_name = "D", signer_state = NULL, server_options = NULL) {
  if (is.null(server_options)) {
    server_options <- .count_compile_server_options(config, peer_name)
    server_options$dsvert.dp.adjacency <- "replace_one_fixed_cohort"
    server_options$dsvert.dp.unit_capacity <- fixed_cohort_size
    server_options$dsvert.dp.fixed_cohort_size <- fixed_cohort_size
  }
  assign(data_name, data, envir = environment())
  withr::local_options(server_options)
  identity <- list(
    identity_pk = unname(config$peer_pins[[peer_name]]),
    identity_sk = paste0("test-secret-", peer_name))
  testthat::with_mocked_bindings(
    dsvertDPCountCompileDS(data_name),
    .get_identity_keypair = function() identity,
    .dsvert_relay_sign_message = function(message, identity_sk) {
      expect_identical(identity_sk, identity$identity_sk)
      if (!is.null(signer_state)) signer_state$calls <- signer_state$calls + 1L
      .count_analysis_signature(message, identity_sk)
    },
    .get_identity_seed = function() stop("identity seed must not be read"),
    .dsvert_mpc_require_capabilities = function(...) {
      stop("MPC capabilities must not be read")
    },
    .dsvert_joint_dp_laplace_plan_v2 = function(...) {
      stop("planner must not be called")
    },
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .dsvert_dp_alignment_registry_commit = function(...) {
      stop("registry commit must not be called")
    },
    .dsvert_dp_alignment_registry_resolve_templates = function(...) {
      stop("registry resolve must not be called")
    },
    .dsvert_dp_noise_root = function(...) stop("noise root must not be called"),
    .package = "dsVert")
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

  invalid_bound <- config
  invalid_bound$count_upper_bound <- 0
  expect_error(
    .dsvert_dp_count_config_validate_v1(invalid_bound), "upper bound")
  invalid_bound$count_upper_bound <- 1000001
  expect_error(
    .dsvert_dp_count_config_validate_v1(invalid_bound), "upper bound")
  invalid_bound$count_upper_bound <- 2.5
  expect_error(
    .dsvert_dp_count_config_validate_v1(invalid_bound), "upper bound")

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

  larger_bucket <- .count_analysis_receipts(
    config, ids = members, token_index = 1L, run_index = 1L,
    capacity_bucket = 128L)
  larger_bucket_contract <- .dsvert_dp_count_compile_v1(
    larger_bucket, config, .verifier = .count_analysis_verifier)
  expect_false(identical(first[[1L]]$psi_run_sha256,
                         larger_bucket[[1L]]$psi_run_sha256))
  expect_identical(first_contract$artifact_key,
                   larger_bucket_contract$artifact_key)
  expect_identical(first_contract$semantic, larger_bucket_contract$semantic)

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

  wider_config <- .count_analysis_config(3L, count_upper_bound = 11L)
  wider <- .count_analysis_receipts(
    wider_config, ids = members, token_index = 1L, run_index = 1L)
  wider_contract <- .dsvert_dp_count_compile_v1(
    wider, wider_config, .verifier = .count_analysis_verifier)
  expect_false(identical(first_contract$artifact_key,
                         wider_contract$artifact_key))
  expect_identical(
    wider_contract$semantic$analysis$effective_arguments$count_bounds,
    list(lower = 0, upper = 11))

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

  bounded <- .count_analysis_config(3L, count_upper_bound = 2L)
  expect_error(
    .count_analysis_receipts(bounded, ids = c("p1", "p2", "p3")),
    "upper bound")
  capacity_limited <- .count_analysis_config(
    3L, count_upper_bound = 100L)
  expect_error(.count_analysis_receipts(
    capacity_limited, ids = paste0("p", seq_len(65L)),
    capacity_bucket = 64L), "capacity bucket")

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
    expect_identical(
      contract$semantic$analysis$effective_arguments$count_bounds,
      list(lower = 0, upper = 10))
    expected_authorities <- sort(
      unname(config$peer_pins), method = "radix")[1:2]
    expect_identical(
      unlist(contract$semantic$noise_authorities, use.names = FALSE),
      unname(expected_authorities))
    expect_identical(length(contract$semantic$owner_snapshots), k)
  }
})

test_that("Count authorization is server-held, canonical and K-generic", {
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  for (k in c(2L, 3L, 5L)) {
    config <- .count_analysis_config(k)
    receipts <- .count_analysis_receipts(config)
    contract <- .dsvert_dp_count_compile_v1(
      receipts, config, .verifier = .count_analysis_verifier)
    authority <- unlist(
      contract$semantic$noise_authorities, use.names = FALSE)[[1L]]
    ss <- new.env(parent = emptyenv())
    authorization <- .count_analysis_authorize(
      ss, session_id, config, receipts, authority)

    expect_identical(ss$.dp_count_authorization, authorization)
    expect_identical(authorization$artifact_key, contract$artifact_key)
    expect_identical(authorization$contract, contract)
    expect_identical(
      authorization$receipt_peers,
      as.list(sort(names(config$peer_pins), method = "radix")))
    expect_identical(
      authorization$worker_static$allocated_delta,
      .dsvert_dp_count_decimal_text(
        config$calibration$implementation_delta))
    expect_false(identical(
      authorization$worker_static$allocated_delta,
      .dsvert_dp_count_decimal_text(config$privacy$delta)))
    expect_identical(
      authorization$worker_static$transcript_hash,
      authorization$analysis_binding_sha256)
    expect_false(any(grepl(
      "seed|secret|private", names(unlist(authorization)),
      ignore.case = TRUE)))

    validated <- testthat::with_mocked_bindings(
      .dsvert_dp_count_session_authorization_validate_v1(
        ss, session_id, contract$artifact_key),
      .get_identity_keypair = function() list(identity_pk = authority),
      .package = "dsVert")
    expect_identical(validated, authorization)
    expect_identical(.count_analysis_authorize(
      ss, session_id, config, rev(receipts), authority), authorization)
  }

  config <- .count_analysis_config(3L)
  receipts <- .count_analysis_receipts(config)
  contract <- .dsvert_dp_count_compile_v1(
    receipts, config, .verifier = .count_analysis_verifier)
  authorities <- unlist(
    contract$semantic$noise_authorities, use.names = FALSE)
  second <- new.env(parent = emptyenv())
  expect_silent(.count_analysis_authorize(
    second, session_id, config, receipts, authorities[[2L]]))

  aliases <- config
  names(aliases$peer_pins) <- paste0("renamed_", seq_along(
    aliases$peer_pins))
  aliased_receipts <- .count_analysis_receipts(aliases)
  aliased_contract <- .dsvert_dp_count_compile_v1(
    aliased_receipts, aliases, .verifier = .count_analysis_verifier)
  expect_false(identical(
    .dsvert_dp_count_config_hash_v1(config),
    .dsvert_dp_count_config_hash_v1(aliases)))
  expect_identical(aliased_contract$artifact_key, contract$artifact_key)
  expect_identical(
    .dsvert_dp_count_worker_static_v1(
      aliased_contract, .planner = .count_analysis_plan),
    .dsvert_dp_count_worker_static_v1(
      contract, .planner = .count_analysis_plan))

  maximum <- .count_analysis_config(2L, count_upper_bound = 1000000L)
  maximum_contract <- .dsvert_dp_count_compile_v1(
    .count_analysis_receipts(maximum), maximum,
    .verifier = .count_analysis_verifier)
  expect_identical(.dsvert_dp_count_worker_static_v1(
    maximum_contract, .planner = .count_analysis_plan)$encoded_upper,
    "1000000")
})

test_that("Count authorization fails closed without partial session state", {
  session_id <- "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
  config <- .count_analysis_config(3L)
  receipts <- .count_analysis_receipts(config)
  contract <- .dsvert_dp_count_compile_v1(
    receipts, config, .verifier = .count_analysis_verifier)
  authorities <- unlist(
    contract$semantic$noise_authorities, use.names = FALSE)
  base_receipts <- receipts
  base_config <- config
  authorize_error <- function(receipts = base_receipts, config = base_config,
                              identity_pk = authorities[[1L]],
                              planner = .count_analysis_plan) {
    ss <- new.env(parent = emptyenv())
    error <- tryCatch({
      .count_analysis_authorize(
        ss, session_id, config, receipts, identity_pk, planner)
      NULL
    }, error = identity)
    expect_s3_class(error, "error")
    expect_null(ss$.dp_count_authorization)
    conditionMessage(error)
  }

  expect_match(authorize_error(receipts = receipts[-1L]),
               "exactly one signed receipt")
  bad_signature <- receipts
  bad_signature[[1L]]$signature <- strrep("x", 86L)
  expect_match(authorize_error(receipts = bad_signature), "signature")
  changed_config <- config
  changed_config$count_upper_bound <- 11
  expect_match(authorize_error(config = changed_config),
               "different configuration")
  invalid_bound <- config
  invalid_bound$count_upper_bound <- 0
  expect_match(authorize_error(config = invalid_bound), "upper bound")
  mismatched_plan <- function(...) {
    plan <- .count_analysis_plan(...)
    plan$stop_numerator <- "52"
    plan
  }
  expect_match(authorize_error(planner = mismatched_plan), "planner")
  non_authority <- setdiff(
    unname(config$peer_pins), authorities)[[1L]]
  expect_match(authorize_error(identity_pk = non_authority),
               "noise authority")

  late <- new.env(parent = emptyenv())
  late$.exact_gc_peer_binding_digest <- strrep("a", 64L)
  expect_error(.count_analysis_authorize(
    late, session_id, config, receipts, authorities[[1L]]),
    "must precede exact-gc peer binding")
  expect_null(late$.dp_count_authorization)

  ss <- new.env(parent = emptyenv())
  installed <- .count_analysis_authorize(
    ss, session_id, config, receipts, authorities[[1L]])
  other_run <- .count_analysis_receipts(
    config, token_index = 8L, run_index = 8L)
  expect_error(.count_analysis_authorize(
    ss, session_id, config, other_run, authorities[[1L]]),
    "Conflicting Count session authorization")
  expect_identical(ss$.dp_count_authorization, installed)

  ss$.dp_count_authorization$worker_static$encoded_upper <- "11"
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_session_authorization_validate_v1(
      ss, session_id, contract$artifact_key),
    .get_identity_keypair = function() list(
      identity_pk = authorities[[1L]]),
    .package = "dsVert"), "authorization")
})

test_that("server-authoritative Count compile envelopes agree for K=2,3,5", {
  expect_identical(names(formals(dsvertDPCountCompileDS)), "data_name")

  for (k in c(2L, 3L, 5L)) {
    config <- .count_analysis_config(k, count_upper_bound = 17L)
    data <- .count_analysis_aligned(c("p1", "p2", "p3"), config)
    signer_states <- lapply(seq_len(k), function(index) {
      state <- new.env(parent = emptyenv())
      state$calls <- 0L
      state
    })
    envelopes <- lapply(seq_len(k), function(index) {
      .count_compile_endpoint(
        data, config, names(config$peer_pins)[[index]],
        data_name = paste0("analyst_alias_", index),
        signer_state = signer_states[[index]])
    })

    expect_true(all(vapply(envelopes, function(value) {
      identical(names(value), c("mode", "payload", "version")) &&
        identical(value$version, "dsvert-dp-count-compile-envelope-v1") &&
        identical(value$mode, "add_remove_dp") &&
        identical(names(value$payload), c("config", "receipt"))
    }, logical(1L))))
    expect_true(all(vapply(
      envelopes[-1L], function(value) identical(value$payload$config,
                                                 envelopes[[1L]]$payload$config),
      logical(1L))))
    expect_true(all(vapply(signer_states, function(state) {
      identical(state$calls, 1L)
    }, logical(1L))))
    expected_hash <- .dsvert_dp_count_config_hash_v1(
      envelopes[[1L]]$payload$config)
    expect_true(all(vapply(envelopes, function(value) {
      identical(value$payload$receipt$config_sha256, expected_hash)
    }, logical(1L))))

    receipts <- lapply(envelopes, function(value) value$payload$receipt)
    contract <- .dsvert_dp_count_compile_v1(
      receipts, envelopes[[1L]]$payload$config,
      .verifier = function(...) TRUE)
    expect_identical(contract$semantic$public_shape, list(count = 1))
    expect_length(contract$semantic$owner_snapshots, k)

    tampered <- envelopes[[1L]]$payload$config
    tampered$privacy$epsilon <- tampered$privacy$epsilon + 1
    expect_error(
      .dsvert_dp_count_receipt_verify_v1(
        envelopes[[1L]]$payload$receipt, tampered,
        .verifier = function(...) TRUE),
      "different configuration")
  }
})

test_that("fixed-cohort Count Compile is exact, signed and K-generic", {
  for (k in c(2L, 3L, 5L)) {
    config <- .count_analysis_config(k, count_upper_bound = 3L)
    data <- .count_analysis_aligned(c("p1", "p2", "p3"), config)
    signer_states <- lapply(seq_len(k), function(index) {
      state <- new.env(parent = emptyenv())
      state$calls <- 0L
      state
    })
    envelopes <- lapply(seq_len(k), function(index) {
      .count_fixed_compile_endpoint(
        data, config, names(config$peer_pins)[[index]],
        data_name = paste0("fixed_alias_", index),
        signer_state = signer_states[[index]])
    })

    expect_true(all(vapply(envelopes, function(value) {
      identical(names(value), c("mode", "payload", "version")) &&
        identical(value$version, "dsvert-dp-count-compile-envelope-v1") &&
        identical(value$mode, "fixed_cohort_public") &&
        identical(names(value$payload), c("declaration", "receipt"))
    }, logical(1L))))
    declaration <- envelopes[[1L]]$payload$declaration
    expect_identical(names(declaration), c(
      "adjacency", "alignment_purpose", "cohort_id", "dataset_id",
      "dataset_version", "domain", "fixed_cohort_size", "peer_pins",
      "privacy_unit_column", "version"))
    expect_identical(
      declaration$version, "dsvert-fixed-cohort-count-declaration-v1")
    expect_identical(declaration$adjacency, "replace_one_fixed_cohort")
    expect_identical(declaration$fixed_cohort_size, 3)
    expect_identical(declaration$peer_pins, as.list(config$peer_pins))
    expect_true(all(vapply(envelopes[-1L], function(value) {
      identical(value$payload$declaration, declaration)
    }, logical(1L))))
    expect_true(all(vapply(signer_states, function(state) {
      identical(state$calls, 1L)
    }, logical(1L))))

    expected_declaration_sha256 <- .dsvert_dp_count_hash_v1(
      "dsVert/dp-count/fixed-cohort-declaration/v1|", declaration)
    receipts <- lapply(envelopes, function(value) value$payload$receipt)
    expect_true(all(vapply(receipts, function(receipt) {
      identical(names(receipt), c(
        "declaration_sha256", "peer_identity_pk", "peer_name",
        "psi_run_sha256", "signature", "version")) &&
        identical(receipt$version,
                  "dsvert-fixed-cohort-count-receipt-v1") &&
        identical(receipt$declaration_sha256,
                  expected_declaration_sha256)
    }, logical(1L))))
    expect_setequal(
      vapply(receipts, `[[`, character(1L), "peer_name"),
      names(config$peer_pins))
    expect_length(unique(vapply(
      receipts, `[[`, character(1L), "psi_run_sha256")), 1L)
    for (index in seq_len(k)) {
      receipt <- receipts[[index]]
      unsigned <- receipt[setdiff(names(receipt), "signature")]
      expect_true(.count_analysis_verifier(
        .dsvert_dp_count_fixed_receipt_message_v1(unsigned),
        paste0("test-secret-", receipt$peer_name), receipt$signature,
        receipt$peer_name))
    }

    tampered <- receipts[[1L]]
    tampered$psi_run_sha256 <- strrep("f", 64L)
    expect_false(.count_analysis_verifier(
      .dsvert_dp_count_fixed_receipt_message_v1(
        tampered[setdiff(names(tampered), "signature")]),
      paste0("test-secret-", tampered$peer_name), tampered$signature,
      tampered$peer_name))
  }
})

test_that("fixed-cohort Compile rejects invalid contracts without DP state", {
  config <- .count_analysis_config(3L, count_upper_bound = 3L)
  data <- .count_analysis_aligned(c("p1", "p2", "p3"), config)
  peer <- names(config$peer_pins)[[1L]]

  expect_error(.count_fixed_compile_endpoint(
    data[-1L, , drop = FALSE], config, peer, fixed_cohort_size = 3L),
    "alignment manifest row count|fixed cohort size")

  tampered_alignment <- data
  manifest <- attr(
    tampered_alignment, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  manifest$hash <- strrep("f", 64L)
  attr(tampered_alignment, .PSI_ALIGNMENT_ATTRIBUTE) <- manifest
  expect_error(.count_fixed_compile_endpoint(
    tampered_alignment, config, peer),
    "alignment manifest authentication")

  options <- .count_compile_server_options(config, peer)
  options$dsvert.dp.adjacency <- "replace_one_fixed_cohort"
  options$dsvert.dp.unit_capacity <- 3L
  options$dsvert.dp.fixed_cohort_size <- 2L
  expect_error(.count_fixed_compile_endpoint(
    data, config, peer, server_options = options),
    "fixed cohort size must equal")

  options$dsvert.dp.adjacency <- "unsupported"
  expect_error(.count_fixed_compile_endpoint(
    data, config, peer, server_options = options), "adjacency")

  incomplete_pins <- .count_compile_server_options(config, peer)
  incomplete_pins$dsvert.dp.adjacency <- "replace_one_fixed_cohort"
  incomplete_pins$dsvert.dp.unit_capacity <- 3L
  incomplete_pins$dsvert.dp.fixed_cohort_size <- 3L
  incomplete_pins$dsvert.trusted_peers <-
    incomplete_pins$dsvert.trusted_peers[-1L]
  expect_error(.count_fixed_compile_endpoint(
    data, config, peer, server_options = incomplete_pins),
    "configured federation")

  add <- .count_compile_endpoint(data, config, peer)
  fixed <- .count_fixed_compile_endpoint(data, config, peer)
  expect_identical(add$mode, "add_remove_dp")
  expect_identical(fixed$mode, "fixed_cohort_public")
  expect_false(identical(add$mode, fixed$mode))
  expect_error(.dsvert_dp_count_compile_envelope_v1(
    "fixed_cohort_public", add$payload), "compile envelope")
})

test_that("Count Compile rejects invalid direct mode before source access", {
  makeActiveBinding("D", function(value) {
    stop("protected source must not be accessed", call. = FALSE)
  }, environment())
  on.exit(rm("D", envir = environment()), add = TRUE)
  testthat::local_mocked_bindings(
    .get_identity_keypair = function() {
      stop("identity must not be accessed", call. = FALSE)
    },
    .package = "dsVert")

  withr::local_options(list(dsvert.dp.adjacency = "unsupported"))
  expect_error(dsvertDPCountCompileDS("D"), "adjacency")

  withr::local_options(list(
    dsvert.dp.adjacency = "replace_one_fixed_cohort",
    dsvert.dp.unit_capacity = 3L,
    dsvert.dp.fixed_cohort_size = 2L))
  expect_error(dsvertDPCountCompileDS("D"), "fixed cohort size must equal")

  withr::local_options(list(
    dsvert.dp.adjacency = "add_remove_patient",
    dsvert.dp.fixed_cohort_size = 3L))
  expect_error(dsvertDPCountCompileDS("D"), "must be absent")
})

test_that("Count server config uses only direct per-analysis options", {
  config <- .count_analysis_config(3L)
  attestation <- .psi_padded_validate_persistent_attestation(
    .count_analysis_aligned(c("p1", "p2"), config))
  peer <- names(config$peer_pins)[[1L]]
  server_options <- .count_compile_server_options(config, peer)
  server_options$dsvert.dp.unit_capacity <- NULL
  server_options$dsvert.psi.max_input_ids <- 4321L
  server_options$dsvert.dp.epsilon <- NULL
  server_options$dsvert.dp.delta <- NULL
  server_options$dsvert.dp.implementation_delta <- NULL
  server_options$default.dsvert.dp.epsilon <- 1
  server_options$default.dsvert.dp.delta <- 1e-6
  server_options$default.dsvert.dp.implementation_delta <- 1e-9
  server_options$dsvert.dp.total_epsilon <- 99
  server_options$dsvert.dp.total_delta <- 0.25
  server_options$dsvert.dp.lifetime_max_distinct_capsules <- 2L
  withr::local_options(server_options)

  loaded <- testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = function(...) {
      .count_compile_runtime_manifest()
    },
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert")
  expect_identical(loaded$count_upper_bound, 4321)
  expect_identical(loaded$privacy, list(delta = 1e-6, epsilon = 1))
  expect_identical(
    loaded$calibration, list(implementation_delta = 1e-9))
  expect_identical(loaded$max_records_per_unit, 1)
  expect_identical(loaded$overflow_policy, "reject_operation")

  withr::local_options(list(dsvert.dp.epsilon = 8))
  expect_silent(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = function(...) {
      .count_compile_runtime_manifest()
    },
    .package = "dsVert"))
  withr::local_options(list(dsvert.dp.epsilon = 8 + 1e-12))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = function(...) {
      .count_compile_runtime_manifest()
    },
    .package = "dsVert"), "privacy parameters")

  withr::local_options(list(
    dsvert.dp.unit_capacity = 23L,
    dsvert.psi.max_input_ids = 999L,
    dsvert.dp.epsilon = 0.5,
    dsvert.dp.delta = 2e-6,
    dsvert.dp.implementation_delta = 2e-9))
  overridden <- testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = function(...) {
      .count_compile_runtime_manifest()
    },
    .package = "dsVert")
  expect_identical(overridden$count_upper_bound, 23)
  expect_identical(overridden$privacy, list(delta = 2e-6, epsilon = 0.5))
  expect_identical(
    overridden$calibration, list(implementation_delta = 2e-9))

  withr::local_options(list(dsvert.dp.unit_capacity = 1000001L))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = function(...) {
      .count_compile_runtime_manifest()
    },
    .package = "dsVert"), "upper bound")
})

test_that("Count source authorization matches attested semantics exactly", {
  config <- .count_analysis_config(3L)
  data <- .count_analysis_aligned(c("p1", "p2"), config)
  attestation <- .psi_padded_validate_persistent_attestation(data)
  peer <- names(config$peer_pins)[[1L]]
  server_options <- .count_compile_server_options(config, peer)
  withr::local_options(server_options)
  runtime <- function(...) .count_compile_runtime_manifest()

  expect_silent(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = runtime,
    .package = "dsVert"))

  mismatched <- .count_compile_source_descriptor(config)
  mismatched$purpose <- "different-purpose"
  withr::local_options(list(
    dsvert.psi.authorized_sources = list(other = mismatched)))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = runtime,
    .package = "dsVert"), "source authorization")

  descriptor <- .count_compile_source_descriptor(config)
  withr::local_options(list(dsvert.psi.authorized_sources = list(
    first = descriptor, second = descriptor)))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      attestation, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = runtime,
    .package = "dsVert"), "source authorization")

  altered <- attestation
  altered$source_binding_id <- paste0("source_", strrep("f", 64L))
  withr::local_options(server_options)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_server_config_v1(
      altered, peer, unname(config$peer_pins[[peer]])),
    .dsvert_mpc_require_capabilities = runtime,
    .package = "dsVert"), "source authorization")
})

test_that("Count compile endpoint has no policy, database or registry path", {
  source <- paste(
    deparse(body(.dsvert_dp_count_server_config_v1)),
    deparse(body(dsvertDPCountCompileDS)), collapse = "\n")
  forbidden <- c(
    ".dsvert_dp_policy", "DBI::", "RSQLite::",
    ".dsvert_dp_alignment_registry_", ".dsvert_dp_noise_root")
  for (token in forbidden) {
    expect_false(grepl(token, source, fixed = TRUE), info = token)
  }

  fixed_source <- paste(
    deparse(body(.dsvert_dp_count_fixed_capacity_v1)),
    deparse(body(.dsvert_dp_count_fixed_compile_v1)),
    deparse(body(.dsvert_dp_count_fixed_receipt_message_v1)),
    collapse = "\n")
  fixed_forbidden <- c(
    ".dsvert_dp_policy", "DBI::", "RSQLite::", "ledger", "budget",
    ".dsvert_dp_alignment_registry_", ".dsvert_dp_noise_root",
    ".get_identity_seed", ".dsvert_mpc_require_capabilities",
    ".dsvert_joint_dp_laplace_plan_v2")
  for (token in fixed_forbidden) {
    expect_false(grepl(token, fixed_source, fixed = TRUE), info = token)
  }
})
