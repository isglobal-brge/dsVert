.joint_convolution_test_state <- function() {
  key <- as.raw(seq_len(32L))
  policy <- list(
    peer_name = "peer_a", domain = "convolution-study",
    cohort_id = "cohort-v1",
    noise_root = list(
      protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
      provider_id = "fixture-hmac-provider",
      epoch = 1, key_id = "convolution-key-a",
      hmac = function(message) digest::hmac(
        key, message, algo = "sha256", serialize = FALSE)))
  source <- .dsvert_joint_dp_convolution_source_contract(
    producer = "count.vector.v1", purpose = "joint_count_release",
    source_context_hash = strrep("1", 64L),
    capsule_release_id = strrep("6", 64L),
    ring_bits = 128L, frac_bits = 0L,
    statistic_lower_bounds = c("0", "0"),
    statistic_upper_bounds = c("1000", "1000"),
    producer_attestation_hash = strrep("2", 64L))
  mechanism <- list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = source$producer, purpose = source$purpose,
    source_context_hash = source$source_context_hash,
    mechanism = "granular-laplace-int64",
    mechanism_version = .DSVERT_JOINT_DP_CONVOLUTION_MECHANISM_VERSION,
    sampler = .DSVERT_JOINT_DP_CONVOLUTION_SAMPLER,
    sensitivity_norm = "l1", sensitivity = 2,
    coordinate_count = 2L, uses_delta = TRUE,
    clipping_hash = .dsvert_joint_dp_convolution_source_binding_hash(source),
    ring_bits = 128L, frac_bits = 0L)
  query_id <- source$capsule_release_id
  mechanism_hash <- .dsvert_joint_dp_hash(mechanism)
  seed <- .dsvert_dp_noise_seed(
    policy, query_id, 7,
    paste0("joint-mpc/", mechanism_hash), 0.5, 5e-7, 2)
  seed_commitment <- digest::digest(paste0(
    "dsVert/joint-dp/private-seed-commitment/v1|", seed),
    algo = "sha256", serialize = FALSE)
  context <- list(
    peer_name = "peer_a",
    pins = c(peer_a = strrep("A", 43L), peer_b = strrep("B", 43L)))
  record <- list(
    query_id = query_id, allocation_index = "7", epsilon = "5e-01",
    delta = "5e-07", sensitivity = 2,
    common_query = list(mechanism = mechanism),
    own_prepare = list(
      capsule_id = query_id,
      mechanism_hash = mechanism_hash,
      seed_commitment = seed_commitment))
  list(
    policy = policy, source = source, mechanism = mechanism,
    state = list(context = context, record = record), seed = seed)
}

.joint_convolution_fake_sampler <- function(captured = NULL) {
  force(captured)
  function(input) {
    if (!is.null(captured)) captured$input <- input
    count <- length(input$additive_shares)
    list(
      version = input$version,
      backend = "independent_full_global_draw_convolution",
      capability_available = FALSE,
      payload_delivery_available = FALSE,
      unavailable_reason = .DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE,
      peer_name = input$peer_name,
      peer_identity_pk = input$peer_identity_pk,
      query_id = input$query_id,
      capsule_release_id = input$capsule_release_id,
      allocation_index = input$allocation_index,
      source_contract_hash = input$source_contract_hash,
      mask_contract_hash = input$mask_contract_hash,
      ring_bits = input$ring_bits, frac_bits = input$frac_bits,
      coordinate_count = count,
      noised_shares = unlist(input$additive_shares, use.names = FALSE),
      mechanism = input$mechanism,
      sampler = if (identical(
        input$mechanism, "granular_laplace_int64")) {
        "deterministic_two_sided_geometric"
      } else "deterministic_symmetric_binomial",
      randomness = "HMAC-SHA256/ChaCha20",
      capsule_epsilon = input$capsule_epsilon,
      capsule_delta = input$capsule_delta,
      delta_impl_sampler = if (identical(
        input$mechanism, "granular_laplace_int64")) 2^-100 else
          count * 2^-40,
      delta_mechanism = if (identical(
        input$mechanism, "granular_laplace_int64")) 0 else
          input$capsule_delta - count * 2^-40,
      delta_total = if (identical(
        input$mechanism, "granular_laplace_int64")) 2^-100 else
          input$capsule_delta,
      full_capsule_parameters_per_peer = TRUE,
      epsilon_divided_by_peer_count = FALSE,
      designated_noise_peer_count = 2L,
      mask_protocol = .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL,
      mask_conditional_min_entropy_bits = input$ring_bits,
      mask_contract_validation =
        "producer_attested_precondition; translation_preserves_uniformity",
      noise_lower_bound_per_peer = "-9223372036854775808",
      noise_upper_bound_per_peer = "9223372036854775807",
      preclip_lower_bounds = rep("-18446744073709551616", count),
      preclip_upper_bounds = rep("18446744073709552614", count),
      release_lower_bounds = unlist(
        input$release_lower_bounds, use.names = FALSE),
      release_upper_bounds = unlist(
        input$release_upper_bounds, use.names = FALSE),
      single_draw_marginal_95_abs = rep("6", count),
      convolution_marginal_95_abs = rep("16", count),
      convolution_simultaneous_95_abs = rep("20", count),
      accuracy_accounting =
        "two_draw_union_bound; each component uses half the failure probability",
      nominal_variance_multiplier = 2,
      nominal_rmse_multiplier = sqrt(2),
      threat_model =
        "pinned_semi_honest_noncolluding; malicious_noise_contribution_not_covered",
      convolution_privacy_argument =
        "under pinned semi-honest non-colluding execution, one hidden complete-capsule mechanism remains (epsilon,delta_total)-DP after independent additive post-processing; delta_total explicitly includes sampler approximation/support loss and never exceeds capsule_delta",
      opening_contract =
        "inside one joint finalizer: sum exactly two purpose-bound raw-noised shares, signed-decode, apply exactly one source-bound fixed saturation, and reveal only that result",
      utility_preferred_backend = "exact_gc_one_joint_noise_sample")
  }
}

test_that("convolution source requires a full-ring uniform mask contract", {
  fixture <- .joint_convolution_test_state()
  source <- fixture$source
  expect_equal(source$ring_bits, 128L)
  expect_identical(source$capsule_release_id, strrep("6", 64L))
  expect_equal(source$mask$conditional_min_entropy_bits, 128L)
  expect_identical(source$mask$independent_of_statistic, TRUE)
  expect_identical(source$mask$reuse,
                   "forbidden_across_coordinates_snapshots_and_purposes")
  expect_identical(
    .dsvert_joint_dp_convolution_validate_source(
      source, fixture$mechanism), source)

  expect_error(.dsvert_joint_dp_convolution_source_contract(
    source$producer, source$purpose, source$source_context_hash,
    source$capsule_release_id, 127L, 0L, c("0"), c("1"),
    strrep("2", 64L)),
    "mask attestation|source identity")
  weak <- source
  weak$mask$conditional_min_entropy_bits <- 127L
  expect_error(.dsvert_joint_dp_convolution_validate_source(
    weak, fixture$mechanism), "source contract")
  rebound <- fixture$mechanism
  rebound$clipping_hash <- strrep("f", 64L)
  expect_error(.dsvert_joint_dp_convolution_validate_source(
    source, rebound), "not bound")

  count_source <- .dsvert_joint_dp_convolution_source_contract(
    producer = "count.scalar.v1", purpose = "bounded_count",
    source_context_hash = strrep("4", 64L),
    capsule_release_id = strrep("7", 64L),
    ring_bits = 128L, frac_bits = 0L,
    statistic_lower_bounds = "0", statistic_upper_bounds = "100",
    producer_attestation_hash = strrep("5", 64L),
    release_lower_bounds = "0", release_upper_bounds = "100")
  expect_identical(unlist(count_source$release_lower_bounds), "0")
  expect_identical(unlist(count_source$release_upper_bounds), "100")
})

test_that("capsule retries reuse one allocation, sticky seed and full epsilon", {
  fixture <- .joint_convolution_test_state()
  captured <- new.env(parent = emptyenv())
  open_calls <- 0L
  allocation_attempts <- 0L
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) {
      open_calls <<- open_calls + 1L
      fixture$state
    },
    .dsvert_joint_dp_proposal = function(...) {
      allocation_attempts <<- allocation_attempts + 1L
      stop("capsule retry attempted a new allocation", call. = FALSE)
    },
    .package = "dsVert")

  first <- .dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(local = TRUE), list(peer = TRUE), fixture$source,
    c("17", "23"), .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler(captured))
  second <- .dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(local = TRUE), list(peer = TRUE), fixture$source,
    c("17", "23"), .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler())
  expect_identical(first, second)
  expect_identical(open_calls, 2L)
  expect_identical(allocation_attempts, 0L)
  expect_identical(first$allocation_index,
                   fixture$state$record$allocation_index)
  expect_identical(first$capsule_release_id,
                   fixture$source$capsule_release_id)
  expect_identical(captured$input$seed, fixture$seed)
  expect_identical(captured$input$capsule_release_id,
                   fixture$source$capsule_release_id)
  expect_identical(captured$input$query_id,
                   captured$input$capsule_release_id)
  expect_identical(captured$input$capsule_epsilon, 0.5)
  expect_identical(captured$input$capsule_delta, 5e-7)
  expect_identical(unlist(captured$input$epsilons), c(0.5, 0.5))
  expect_identical(unlist(captured$input$sensitivities), c(2L, 2L))
  expect_identical(first$delta_impl_sampler, 2^-100)
  expect_identical(first$delta_mechanism, 0)
  expect_identical(first$delta_total, first$delta_impl_sampler)
  expect_lte(first$delta_total, captured$input$capsule_delta)
  expect_false(first$epsilon_divided_by_peer_count)
  expect_false(first$capability_available)
  expect_false(first$payload_delivery_available)
  expect_false(any(c("seed", "noise_values", "statistic_values") %in%
                   names(first)))

  broken <- fixture
  broken$state$record$own_prepare$seed_commitment <- strrep("0", 64L)
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) broken$state,
    .package = "dsVert")
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    broken$policy, list(), list(), broken$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler()),
    "does not match the durable allocation")
})

test_that("fallback rejects missing or underfunded delta before seed derivation", {
  fixture <- .joint_convolution_test_state()
  seed_touched <- FALSE
  zero <- fixture$state
  zero$record$delta <- "0e+00"
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) zero,
    .dsvert_dp_noise_seed = function(...) {
      seed_touched <<- TRUE
      stop("seed derivation must not run", call. = FALSE)
    },
    .package = "dsVert")
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler()),
    "not representable")
  expect_false(seed_touched)

  underfunded <- fixture$state
  underfunded$record$delta <- format(
    2^-101, scientific = TRUE, digits = 17)
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) underfunded,
    .package = "dsVert")
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler()),
    "does not cover the sampler implementation delta")
  expect_false(seed_touched)
})

test_that("fallback rejects an operation identity distinct from its capsule", {
  fixture <- .joint_convolution_test_state()
  mismatched <- fixture$state
  mismatched$record$query_id <- strrep("9", 64L)
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) mismatched,
    .package = "dsVert")
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler()),
    "not the authorized capsule")

  mismatched <- fixture$state
  mismatched$record$own_prepare$capsule_id <- strrep("8", 64L)
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) mismatched,
    .package = "dsVert")
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)),
    .sampler = .joint_convolution_fake_sampler()),
    "not the authorized capsule")
})

test_that("fallback rejects misleading capability or privacy metadata", {
  fixture <- .joint_convolution_test_state()
  testthat::local_mocked_bindings(
    .dsvert_joint_dp_backend_open_record_v2 = function(...) fixture$state,
    .package = "dsVert")
  dishonest <- function(input) {
    result <- .joint_convolution_fake_sampler()(input)
    result$epsilon_divided_by_peer_count <- TRUE
    result$capability_available <- TRUE
    result
  }
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)), .sampler = dishonest),
    "invalid contract")

  falsely_pure <- function(input) {
    result <- .joint_convolution_fake_sampler()(input)
    result$delta_impl_sampler <- 0
    result$delta_total <- 0
    result
  }
  expect_error(.dsvert_joint_dp_convolution_share_provisional(
    fixture$policy, list(), list(), fixture$source, c("17", "23"),
    .secret = as.raw(seq_len(32L)), .sampler = falsely_pure),
    "invalid contract")
})

test_that("joint mechanism accepts only the explicit fallback sampler id", {
  fixture <- .joint_convolution_test_state()
  pins <- c(
    peer_a = gsub("=+$", "", chartr("+/", "-_",
      jsonlite::base64_enc(as.raw(seq_len(32L))))),
    peer_b = gsub("=+$", "", chartr("+/", "-_",
      jsonlite::base64_enc(as.raw(32L + seq_len(32L))))))
  policy <- c(fixture$policy, list(
    peer_pinset = pins,
    peer_pinset_sha256 = digest::digest(
      .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
      serialize = FALSE),
    peer_count = 2L, designated_noise_peers = names(pins),
    global_total_epsilon = 1, global_total_delta = 1e-6,
    decay = 0.5, adjacency = "add_remove_patient",
    patient_column = "patient_id", unit_capacity = 100L,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    ledger_path = tempfile("joint-convolution-ledger-")))
  expect_identical(
    .dsvert_joint_dp_mechanism(fixture$mechanism, policy)$sampler,
    .DSVERT_JOINT_DP_CONVOLUTION_SAMPLER)
  legacy_id <- fixture$mechanism
  legacy_id$sampler <- "analyst_chosen_sampler"
  expect_error(.dsvert_joint_dp_mechanism(legacy_id, policy),
               "mechanism contract")
})

test_that("server-local Ring128 split is purpose-bound and never advertises capability", {
  fixture <- .joint_convolution_test_state()
  captured <- new.env(parent = emptyenv())
  splitter <- function(input) {
    captured$input <- input
    list(
      version = input$version, capability_available = FALSE,
      unavailable_reason = .DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE,
      query_id = input$query_id,
      capsule_release_id = input$capsule_release_id,
      allocation_index = input$allocation_index,
      source_contract_hash = input$source_contract_hash,
      mask_contract_hash = input$mask_contract_hash,
      coordinate_index = input$coordinate_index,
      ring_bits = 128L,
      left_share = "340282366920938463463374607431768211455",
      right_share = "74",
      mask_protocol = .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL,
      mask_conditional_min_entropy_bits = 128L,
      generator = "os_csprng_uniform_16_bytes",
      requires_durable_replay = TRUE)
  }
  result <- .dsvert_joint_dp_uniform_split_ring128(
    73, fixture$state$record$query_id, 7, fixture$source,
    coordinate_index = 1, .splitter = splitter)
  expect_false(result$capability_available)
  expect_true(result$requires_durable_replay)
  expect_identical(captured$input$count, "73")
  expect_identical(captured$input$query_id,
                   captured$input$capsule_release_id)
  expect_false("count" %in% names(result))
  expect_identical(result$left_share,
                   "340282366920938463463374607431768211455")
  expect_error(.dsvert_joint_dp_uniform_split_ring128(
    2^53, fixture$state$record$query_id, 7, fixture$source,
    .splitter = splitter), "uniform split request")
  expect_error(.dsvert_joint_dp_uniform_split_ring128(
    73, fixture$state$record$query_id, 7, fixture$source,
    coordinate_index = 2, .splitter = splitter), "outside")
  expect_error(.dsvert_joint_dp_uniform_split_ring128(
    73, strrep("8", 64L), 7, fixture$source,
    .splitter = splitter), "uniform split request")

  bad <- function(input) {
    value <- splitter(input)
    value$left_share <- "340282366920938463463374607431768211456"
    value
  }
  expect_error(.dsvert_joint_dp_uniform_split_ring128(
    73, fixture$state$record$query_id, 7, fixture$source,
    .splitter = bad), "canonical residue")
})
