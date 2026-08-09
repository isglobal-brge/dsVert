.dp_test_sampler <- function(values, epsilons, sensitivities, seed) {
  stopifnot(
    is.character(seed), length(seed) == 1L,
    grepl("^[0-9a-f]{64}$", seed))
  list(
    values = unname(values),
    accuracy_95_abs = unname(floor(
      log(20) * sensitivities / epsilons + 0.5)),
    accuracy_simultaneous_95_abs = unname(floor(
      log(20 * length(values)) * sensitivities / epsilons + 0.5)),
    clipped_coordinates = 0L,
    mechanism = "dsvert_dp_v1_deterministic_granular_laplace_int64",
    implementation = paste0(
      "dsVert adapted Google Differential Privacy v4.1.0 ",
      "granular Laplace integer mechanism"),
    sampler = "deterministic_two_sided_geometric",
    randomness = "HMAC-SHA256/ChaCha20",
    l0_sensitivity = 1L,
    delta = 0,
    marginal_confidence = 0.95,
    simultaneous_confidence = 0.95,
    simultaneous_method = "union_bound",
    max_granularity = 1,
    output_lower_bound = -(2^53 - 1),
    output_upper_bound = 2^53 - 1
  )
}

.dp_test_noise_selection <- function(input) {
  granularity <- 2^ceiling(log2(
    (input$laplace_l1_sensitivity / input$laplace_epsilon) / 2^40))
  laplace_available <- input$laplace_epsilon >= 2^-50 &&
    is.finite(granularity) && granularity > 0 && granularity <= 1
  marginal <- if (laplace_available) {
    ceiling(log(20) * input$laplace_l1_sensitivity /
              input$laplace_epsilon)
  } else 0
  simultaneous <- if (laplace_available) {
    ceiling(log(20 * input$coordinate_count) *
              input$laplace_l1_sensitivity / input$laplace_epsilon)
  } else 0
  candidate <- function(
      available, mechanism, epsilon, delta, norm, sensitivity,
      marginal_radius, simultaneous_radius, rmse, sigma, granularity,
      analytic_delta, implementation_delta_bound, accounting_rule,
      accuracy_accounting, verified, reason) {
    list(
      available = available, mechanism = mechanism, epsilon = epsilon,
      delta = delta, sensitivity_norm = norm, sensitivity = sensitivity,
      analytic_delta = analytic_delta,
      implementation_delta_bound = implementation_delta_bound,
      accounting_rule = accounting_rule,
      accuracy_accounting = accuracy_accounting,
      marginal_95_abs = marginal_radius,
      simultaneous_95_abs = simultaneous_radius,
      nominal_rmse = rmse, sigma = sigma, granularity = granularity,
      analytic_accounting_verified = verified,
      unavailable_reason = reason)
  }
  laplace <- candidate(
    laplace_available,
    "dsvert_dp_v1_deterministic_granular_laplace_int64",
    input$laplace_epsilon, 0, "l1", input$laplace_l1_sensitivity,
    marginal, simultaneous,
    if (laplace_available) {
      sqrt(2) * input$laplace_l1_sensitivity / input$laplace_epsilon
    } else 0,
    0, if (laplace_available) granularity else 0,
    0, 0, "pure_dp_no_implementation_slack",
    "exact_granular_laplace_confidence_interval",
    laplace_available,
    if (laplace_available) "" else
      "laplace_calibration_not_representable")
  implementation_delta <- .dsvert_dp_gaussian_implementation_delta_bound(
    input$coordinate_count, input$gaussian_epsilon)
  gaussian <- candidate(
    FALSE, "dsvert_dp_v3_deterministic_approximate_gaussian_int64",
    input$gaussian_epsilon, input$gaussian_delta, "l2",
    input$gaussian_l2_sensitivity, 0, 0, 0, 0, 0,
    0, implementation_delta,
    "analytic_gaussian_delta_plus_dp_transfer_from_total_variation_bound",
    "gaussian_tail_alpha_minus_total_variation_union_bound",
    FALSE,
    if (input$gaussian_delta == 0) "gaussian_delta_is_zero" else
      "gaussian_calibration_not_representable")
  list(
    schema_version = 2L,
    selector = "minimum_conservative_95_radius_v3",
    objective = input$objective,
    coordinate_count = input$coordinate_count,
    laplace = laplace,
    gaussian = gaussian,
    winner = if (laplace_available) "laplace" else "none",
    winner_mechanism = if (laplace_available) laplace$mechanism else "",
    winning_metric_abs = if (identical(
      input$objective, "marginal_95_abs")) marginal else simultaneous,
    winner_delta = 0,
    tie_break = "laplace_unless_gaussian_strictly_improves")
}

.dp_test_noise_provider <- function(
    key = as.raw(seq_len(32L)), key_id = "test-noise-key-v1",
    provider_id = "test-noise-provider") {
  force(key)
  force(key_id)
  force(provider_id)
  function(action, message_base64 = NULL) {
    if (identical(action, "capabilities")) {
      return(list(
        schema_version = 1L, provider_id = provider_id, key_id = key_id,
        external = TRUE, hmac_sha256 = TRUE))
    }
    if (!identical(action, "hmac_sha256") ||
        !is.character(message_base64) || length(message_base64) != 1L) {
      stop("unsupported noise-provider action", call. = FALSE)
    }
    list(
      schema_version = 1L, provider_id = provider_id, key_id = key_id,
      digest_sha256 = digest::hmac(
        key = key, object = jsonlite::base64_dec(message_base64),
        algo = "sha256", serialize = FALSE))
  }
}

.dp_test_runtime_manifest <- function() {
  list(
    schema_version = 1L,
    protocol_version = "dsvert-mpc-runtime-v1",
    runtime_version = "1.1.0",
    api_version = "1.1.0",
    capabilities = list(
      dp_noise_int64 = list(
        available = TRUE,
        capability_id = "dp_noise_int64_v2",
        protocol_version = "dsvert-dp-noise-int64-v2",
        commands = "dp-noise-int64",
        operations = "deterministic-granular-laplace-int64"),
      dp_gaussian_int64 = list(
        available = TRUE,
        capability_id = "dp_gaussian_int64_v3",
        protocol_version = "dsvert-dp-gaussian-int64-v3",
        commands = c("dp-gaussian-int64", "dp-noise-select-int64"),
        operations = c(
          paste0("deterministic-approximate-gaussian-int64-l2-",
                 "dp-transfer-tv-accounted"),
          "minimum-conservative-95-radius-v3")),
      exact_gc = list(
        available = TRUE,
        capability_id = "exact_gc_v1",
        protocol_version = "dsvert-exact-gc-worker-v4",
        commands = c("exact-gc-derive-master", "exact-gc-capability",
                     "exact-gc-plan-mul", "joint-dp-laplace-plan-v2",
                     "joint-dp-laplace-worker-contract-v2",
                     "joint-dp-vector-laplace-plan-v3",
                     "joint-dp-vector-worker-contract-v3",
                     "exact-gc-worker"),
        operations = c("truncate-floor", "count-guard", "clamp-count",
                       "joint-dp-laplace-v2",
                       "joint-dp-vector-laplace-v3"),
        core_operations = c("compare-signed", "truncate-floor",
                            "mul-truncate-checked", "count-guard",
                            "clamp-count", "joint-dp-laplace-v2",
                            "joint-dp-vector-laplace-v3")),
      typed_source_stream = list(
        available = TRUE,
        capability_id = "typed_source_stream_probe_v1",
        protocol_version = "dsvert-typed-source-stream-v1",
        commands = "typed-source-stream-probe",
        operations = "data-free-random-source-probe"),
      joint_dp_vector_convolution = list(
        available = TRUE,
        capability_id = "joint_dp_vector_hybrid_v5",
        protocol_version = "dsvert-joint-dp-vector-hybrid-v5",
        commands = c(
          "joint-dp-vector-convolution-plan-v3",
          "joint-dp-vector-convolution-share-v3",
          "joint-dp-vector-convolution-finalize-v3",
          "joint-dp-vector-gaussian-plan-v2",
          "joint-dp-vector-gaussian-share-v2",
          "joint-dp-vector-gaussian-finalize-v2"),
        operations = c(
          "sticky-independent-complete-vector-discrete-laplace-ring128-v3",
          paste0("sticky-independent-complete-vector-dyadic-discrete-",
                 "gaussian-tv-bounded-ring128-v2"),
          "signed-decode-fixed-public-clamp-no-wrap-v3"))))
}

.dp_test_pk <- function(offset) {
  jsonlite::base64_enc(as.raw((seq_len(32L) + offset) %% 256L))
}

.dp_test_align <- function(data, id_col = "patient_id") {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(seq_len(32L))))
  .psi_attach_alignment_manifest(data, id_col, token)
}

.dp_test_anchor_provider <- function(provider_id = "test-external-anchor") {
  states <- new.env(parent = emptyenv())
  provider <- function(action, anchor_id, expected = NULL,
                       replacement = NULL) {
    if (identical(action, "capabilities")) {
      return(list(
        schema_version = 2L, provider_id = provider_id, external = TRUE,
        durable = TRUE, linearizable_cas = TRUE))
    }
    current <- if (exists(anchor_id, envir = states, inherits = FALSE)) {
      get(anchor_id, envir = states, inherits = FALSE)
    } else {
      NULL
    }
    if (identical(action, "read")) return(current)
    if (!identical(action, "compare_and_swap")) {
      stop("unsupported anchor action", call. = FALSE)
    }
    same <- if (is.null(expected)) {
      is.null(current)
    } else {
      .dsvert_dp_anchor_state_equal(current, expected)
    }
    if (isTRUE(same)) {
      assign(anchor_id, replacement, envir = states)
      current <- replacement
    }
    list(swapped = isTRUE(same), state = current)
  }
  attr(provider, "states") <- states
  provider
}

.dp_test_policy <- function(ledger_path, ...,
                            .local_envir = parent.frame(),
                            .production_contract = FALSE) {
  overrides <- list(...)
  values <- utils::modifyList(list(
    dsvert.dp.enabled = TRUE,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.decay = 0.5,
    dsvert.dp.domain = "test-study-v1",
    dsvert.dp.cohort_id = "test-cohort-v1",
    dsvert.dp.ledger_path = ledger_path,
    dsvert.dp.anchor_provider = NULL,
    dsvert.dp.noise_key_provider = .dp_test_noise_provider(),
    dsvert.dp.noise_key_path = NULL,
    dsvert.dp.noise_key_epoch = 1,
    dsvert.dp.noise_key_previous_id = NULL,
    dsvert.dp.composition_partitions = 2L,
    dsvert.dp.adjacency = "add_remove_patient",
    dsvert.dp.patient_column = "patient_id",
    dsvert.dp.unit_capacity = 1000L,
    dsvert.dp.fixed_cohort_size = NULL,
    dsvert.dp.max_records_per_unit = 100L,
    dsvert.dp.overflow_policy = "reject_snapshot",
    dsvert.dp.contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    dsvert.dp.numeric_grid_bits = 16L,
    dsvert.dp.datasets = c(
      list(
        protected = list(id = "test-protected", version = "v1"),
        protected_b = list(id = "test-protected-b", version = "v1")),
      setNames(lapply(1:8, function(i) {
        list(id = paste0("test-protected-", i), version = "v1")
      }), paste0("protected", 1:8))),
    dsvert.identity_seed = jsonlite::base64_enc(as.raw(seq_len(32L))),
    dsvert.peer_name = "site_a",
    dsvert.trusted_peers = c(site_b = .dp_test_pk(32L))
  ), overrides, keep.null = TRUE)
  # A dataset manifest is an atomic policy object. Recursive modifyList()
  # would retain unrelated default entries, which is invalid in strict mode
  # because every registered snapshot must carry its own custodian digest.
  if ("dsvert.dp.datasets" %in% names(overrides)) {
    values$dsvert.dp.datasets <- overrides$dsvert.dp.datasets
  }
  policy_builder <- .dsvert_dp_policy_build
  test_flags <- if (isTRUE(.production_contract)) {
    list()
  } else {
    list(
      .test_only_skip_snapshot_binding = TRUE,
      .test_only_skip_alignment_binding = TRUE,
      .test_only_allow_local_anchor = TRUE,
      .test_only_allow_nonprivate_ledger = TRUE)
  }
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() do.call(policy_builder, test_flags),
    .package = "dsVert", .env = .local_envir)
  if (!"dsvert.trusted_peers" %in% names(overrides)) {
    partitions <- values$dsvert.dp.composition_partitions
    if (is.numeric(partitions) && length(partitions) == 1L &&
        !is.na(partitions) && partitions == 1L) {
      values$dsvert.trusted_peers <- NULL
      # Test-only single-site policy fixtures do not exercise a deployed MPC
      # federation. Keep that compatibility in this uninstalled helper instead
      # of exposing a production pinning selector.
      testthat::local_mocked_bindings(
        .get_trusted_peers = function() character(),
        .package = "dsVert", .env = .local_envir)
    } else if (is.numeric(partitions) && length(partitions) == 1L &&
               !is.na(partitions) && partitions > 2L &&
               partitions == floor(partitions)) {
      peer_names <- paste0("site_", letters[2:partitions])
      values$dsvert.trusted_peers <- stats::setNames(
        vapply(seq_len(partitions - 1L), function(i) .dp_test_pk(32L * i),
               character(1L)), peer_names)
    }
  }
  real_binary <- Sys.getenv("DSVERT_TEST_MPC_BINARY", unset = "")
  if (nzchar(real_binary)) {
    if (!file.exists(real_binary)) {
      stop("DSVERT_TEST_MPC_BINARY does not exist", call. = FALSE)
    }
    values$dsvert.mpc_binary <- real_binary
  } else {
    testthat::local_mocked_bindings(
      .callMpcTool = function(command, input_data) {
        if (identical(command, "runtime-capabilities")) {
          return(.dp_test_runtime_manifest())
        }
        if (identical(command, "derive-identity")) {
          public <- .dp_test_pk(0L)
          # Go's Ed25519 private-key representation is seed || public key.
          # Keep the fixture structurally valid now that production validates
          # the complete derived pair instead of trusting a placeholder.
          private <- gsub("[\r\n]", "", jsonlite::base64_enc(c(
            as.raw(rep(0L, 32L)), jsonlite::base64_dec(public))))
          return(list(identity_pk = public, identity_sk = private))
        }
        if (identical(command, "dp-noise-select-int64")) {
          return(.dp_test_noise_selection(input_data))
        }
        if (!identical(command, "dp-noise-int64")) {
          stop("Unexpected mocked MPC command: ", command, call. = FALSE)
        }
        .dp_test_sampler(
          unlist(input_data$values, use.names = FALSE),
          unlist(input_data$epsilons, use.names = FALSE),
          unlist(input_data$sensitivities, use.names = FALSE),
          input_data$seed)
      },
      .package = "dsVert", .env = .local_envir)
  }
  withr::local_options(values, .local_envir = .local_envir)
  invisible(values)
}

.dp_test_strict_policy <- function(ledger_path, datasets,
                                   anchor_provider,
                                   .local_anchor_protocol_test = FALSE,
                                   ...) {
  descriptors <- setNames(lapply(seq_along(datasets), function(index) {
    data <- datasets[[index]]
    manifest <- .psi_validate_alignment_manifest(data)
    list(
      id = paste0("strict-", names(datasets)[[index]]),
      version = "v1",
      snapshot_sha256 = .dsvert_dp_snapshot_digest(data),
      alignment_manifest_hash = manifest$hash,
      alignment_manifest_version = manifest$version)
  }), names(datasets))
  .dp_test_policy(
    ledger_path,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.decay = 0.5,
    dsvert.dp.anchor_provider = anchor_provider,
    dsvert.dp.datasets = descriptors,
    ...,
    .local_envir = parent.frame(),
    .production_contract = !isTRUE(.local_anchor_protocol_test))
}

.dp_test_direct_release <- function(policy, protected, method, release_fn,
                                    phase_hook = NULL) {
  secret <- .dsvert_dp_secret()
  dataset <- .dsvert_dp_dataset_binding(
    policy, "protected", protected, secret)
  arguments <- list(test_method = method)
  query_hash <- .dsvert_dp_query_hash(
    secret, policy, dataset$public, method, arguments)
  .dsvert_dp_release(
    policy, query_hash, dataset$ledger_key, dataset$fingerprint,
    paste0("dsvert_test_", method), 1, release_fn,
    noise_context = list(
      dataset = dataset$public, method = method, arguments = arguments),
    .phase_hook = phase_hook)
}

test_that("DP configuration has one custodian-owned safe mode", {
  ledger <- file.path(tempdir(), paste0("dp-policy-", Sys.getpid(), ".sqlite"))
  manifest <- .dp_test_policy(ledger)
  snapshots <- lapply(manifest$dsvert.dp.datasets, function(descriptor) {
    c(descriptor, list(
      snapshot_sha256 = paste(rep("0", 64L), collapse = ""),
      alignment_manifest_hash = paste(rep("1", 64L), collapse = ""),
      alignment_manifest_version = 1L))
  })
  options(dsvert.dp.total_epsilon = 1,
          dsvert.dp.total_delta = 0,
          dsvert.dp.enabled = FALSE,
          dsvert.dp.decay = 0.5,
          dsvert.dp.anchor_provider = .dp_test_anchor_provider(),
          dsvert.dp.datasets = snapshots)
  expect_identical(.dsvert_dp_policy()$adjacency, "add_remove_patient")
  expect_false("enabled" %in% names(.dsvert_dp_policy()))
  expect_equal(.dsvert_dp_policy()$local_total_epsilon, 0.5)
  expect_identical(.dsvert_dp_policy()$policy_contract,
                   "single_safe_policy_v3")
  expect_identical(.dsvert_dp_policy()$schema_version, 6L)
  expect_identical(
    .dsvert_dp_policy()$mechanism_version,
    "dsvert-dp-v7-contingency-unit-aggregation-1")
  expect_identical(
    .dsvert_dp_policy()$contingency_unit_aggregation_policy,
    "consistent_cell_else_exclude_v1")
  expect_identical(
    .dsvert_dp_policy()$transcript_privacy,
    .dsvert_dp_transcript_claim()$policy_value)
  public_policy <- .dsvert_dp_policy_public(.dsvert_dp_policy())
  expect_identical(
    public_policy$contingency_unit_aggregation_policy,
    "consistent_cell_else_exclude_v1")
  changed_aggregation_policy <- .dsvert_dp_policy()
  changed_aggregation_policy$contingency_unit_aggregation_policy <-
    "different_version"
  expect_false(identical(
    .dsvert_dp_policy_hash(changed_aggregation_policy),
    .dsvert_dp_policy_hash(.dsvert_dp_policy())))
  expect_identical(
    .dsvert_dp_policy()$noise_selection$selector,
    "minimum_conservative_95_radius_v3")
  expect_identical(.dsvert_dp_policy()$noise_selection$schema_version, 2L)
  expect_match(
    .dsvert_dp_policy()$noise_selection$capsule_vector_route$activation,
    "conditional_on_signed_capsule_manifest")
  expect_true(any(grepl(
    "dyadic_discrete_gaussian_tv_bounded",
    .dsvert_dp_policy()$noise_selection$capsule_vector_route$candidates,
    fixed = TRUE)))
  expect_true(any(grepl(
    "approximate_gaussian",
    .dsvert_dp_policy()$noise_selection$candidates,
    fixed = TRUE)))
  expect_false(any(c(
    "profile", "mutable_dataset_test_mode", "unaligned_dataset_test_mode",
    "minimum_release_epsilon") %in%
    names(public_policy)))

  options(dsvert.dp.composition_partitions = NULL)
  derived <- .dsvert_dp_policy()
  expect_identical(derived$peer_count, 2L)
  expect_identical(derived$composition_partitions, 2L)
  options(dsvert.dp.composition_partitions = 2L,
          dsvert.dp.total_epsilon = 1,
          dsvert.dp.total_delta = 0,
          dsvert.dp.decay = 0.5)
  incomplete <- snapshots
  incomplete[[1L]]$alignment_manifest_hash <- NULL
  incomplete[[1L]]$alignment_manifest_version <- NULL
  expect_error(withr::with_options(
    list(dsvert.dp.datasets = incomplete), .dsvert_dp_policy_build()),
    "alignment manifest")
  pending <- withr::with_options(
    list(dsvert.dp.anchor_provider = NULL),
    .dsvert_dp_policy_build(.test_only_allow_nonprivate_ledger = TRUE))
  expect_identical(
    pending$rollback_protection$mode,
    "pinned_peer_global_allocator_pending")
  expect_identical(
    pending$rollback_protection$provider_contract,
    "pinned_ed25519_cross_signed_global_allocator_v1")
  expect_error(.dsvert_dp_release(
    pending, strrep("a", 64L), "dataset_snapshot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    strrep("b", 64L), "pending-test", 1,
    function(...) stop("must not sample", call. = FALSE)),
    "fail-closed.*not E2E verified")
  options(
          dsvert.dp.total_epsilon = 9,
          dsvert.dp.total_delta = 0,
          dsvert.dp.decay = 0.5)
  expect_error(.dsvert_dp_policy(), "<= 8")
  options(dsvert.dp.total_epsilon = 8)
  expect_equal(.dsvert_dp_policy()$local_total_epsilon, 4)
})

test_that("automatic aligned-dataset resolution is production-binding only", {
  ledger <- file.path(
    tempdir(), paste0("dp-registry-resolution-gate-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    ledger,
    dsvert.dp.datasets = list(
      protected = list(id = "registry-gate", version = "v1")))

  resolution_calls <- 0L
  resolve <- function(datasets, patient_column, pinset) {
    resolution_calls <<- resolution_calls + 1L
    lapply(datasets, function(descriptor) c(descriptor, list(
      snapshot_sha256 = strrep("a", 64L),
      alignment_manifest_hash = strrep("b", 64L),
      alignment_manifest_version = 3L)))
  }
  testthat::with_mocked_bindings({
    bypass <- .dsvert_dp_policy_build(
      .test_only_skip_snapshot_binding = TRUE,
      .test_only_skip_alignment_binding = TRUE,
      .test_only_allow_nonprivate_ledger = TRUE)
    expect_identical(resolution_calls, 0L)
    expect_false(bypass$require_snapshot_digest)
    expect_false(bypass$require_alignment_manifest)
    expect_identical(
      bypass$datasets$protected[c("id", "version")],
      list(id = "registry-gate", version = "v1"))

    strict <- .dsvert_dp_policy_build(
      .test_only_allow_nonprivate_ledger = TRUE)
    expect_identical(resolution_calls, 1L)
    expect_true(strict$require_snapshot_digest)
    expect_true(strict$require_alignment_manifest)
    expect_identical(strict$datasets$protected$alignment_manifest_version, 3L)
  },
  .dsvert_dp_alignment_registry_resolve_templates = resolve,
  .package = "dsVert")
})

test_that("the automatic capsule delta certifies Count without configuration", {
  ledger <- file.path(
    tempdir(), paste0("dp-default-delta-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(ledger)
  withr::local_options(list(
    dsvert.dp.total_delta = NULL,
    default.dsvert.dp.total_delta = NULL))

  policy <- .dsvert_dp_policy()
  expect_identical(policy$global_total_delta,
                   .DSVERT_DP_DEFAULT_CAPSULE_DELTA)
  expect_identical(policy$global_total_delta, 2^-100)
  expect_gte(
    policy$global_total_delta,
    .DSVERT_JOINT_DP_CONVOLUTION_LAPLACE_DELTA_FLOOR)
})

test_that("production rejects an inexactly excessive lifetime composition", {
  ledger <- file.path(
    tempdir(), paste0("dp-lifetime-policy-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    ledger,
    dsvert.dp.total_epsilon = 8 / 3,
    dsvert.dp.total_delta = 2^-100,
    dsvert.dp.lifetime_max_distinct_capsules = 3)
  build <- function() .dsvert_dp_policy_build(
    .test_only_skip_snapshot_binding = TRUE,
    .test_only_skip_alignment_binding = TRUE,
    .test_only_allow_nonprivate_ledger = TRUE)

  accepted <- build()
  expect_identical(accepted$lifetime_max_distinct_capsules, 3)
  expect_identical(
    .dsvert_joint_dp_lifetime_contract(accepted)$lifetime_epsilon,
    "7.9999999999999995")

  options(dsvert.dp.total_epsilon = 0.8,
          dsvert.dp.lifetime_max_distinct_capsules = 10)
  expect_error(build(), "lifetime composition bound")

  options(dsvert.dp.total_epsilon = 1,
          dsvert.dp.total_delta = 0.5,
          dsvert.dp.lifetime_max_distinct_capsules = 2)
  expect_error(build(), "lifetime composition bound")

  options(dsvert.dp.total_delta = 0.49999999999999994)
  expect_no_error(build())
})

test_that("production derives K from pins and never divides the global budget", {
  ledger <- file.path(
    tempdir(), paste0("dp-global-k-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    ledger,
    dsvert.dp.composition_partitions = NULL,
    dsvert.dp.designated_noise_peers = c("site_c", "site_a"),
    dsvert.trusted_peers = c(
      site_b = .dp_test_pk(32L), site_c = .dp_test_pk(64L)))
  build <- function() .dsvert_dp_policy_build(
    .test_only_skip_snapshot_binding = TRUE,
    .test_only_skip_alignment_binding = TRUE,
    .test_only_allow_nonprivate_ledger = TRUE)
  policy <- build()
  public <- .dsvert_dp_policy_public(policy)
  expect_identical(policy$peer_count, 3L)
  expect_false(any(c(
    "allocation_total_epsilon", "allocation_total_delta", "decay",
    "composition_partitions", "local_total_epsilon", "local_total_delta") %in%
    names(policy)))
  expect_identical(public$peer_count, 3L)
  expect_identical(public$designated_noise_peers,
                   c("site_a", "site_c"))
  context <- .dsvert_joint_dp_policy_context(policy)
  expect_identical(context$peer_name, "site_a")
  expect_identical(
    unname(unlist(context$common$designated_noise_peers,
                  use.names = FALSE)),
    c("site_a", "site_c"))
  expect_identical(as.numeric(context$common$peer_count), 3)
  expect_identical(context$common$peer_pinset_sha256,
                   policy$peer_pinset_sha256)
  expect_false(any(c(
    "composition_partitions", "local_total_epsilon",
    "local_total_delta") %in% names(public)))

  options(dsvert.dp.designated_noise_peers = NULL)
  automatic <- build()
  expect_identical(automatic$designated_noise_peers,
                   c("site_a", "site_b"))
  expect_identical(
    .dsvert_joint_dp_policy_context(
      automatic)$common$designated_noise_peers,
    c("site_a", "site_b"))
  options(dsvert.dp.designated_noise_peers = c("site_a", "missing"))
  expect_error(build(), "designated_noise_peers")
  options(dsvert.dp.designated_noise_peers = c("site_a", "site_c"),
          dsvert.dp.enabled = NA,
          dsvert.dp.decay = Inf,
          dsvert.dp.composition_partitions = 2L)
  ignored_legacy <- build()
  expect_identical(ignored_legacy$peer_count, 3L)
  expect_false(any(c(
    "enabled", "decay", "composition_partitions") %in%
    names(ignored_legacy)))
})

test_that("strict ledger paths and SQLite sidecars remain owner-only", {
  skip_on_os("windows")
  root <- tempfile("dsvert-private-ledger-")
  dir.create(root, mode = "0700")
  Sys.chmod(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)

  path <- file.path(root, "ledger.sqlite")
  canonical <- .dsvert_dp_ledger_path(path, require_private = TRUE)
  expect_identical(dirname(canonical), normalizePath(root, winslash = "/"))

  parent_alias <- tempfile("dsvert-ledger-parent-link-")
  on.exit(unlink(parent_alias, force = TRUE), add = TRUE)
  expect_true(file.symlink(root, parent_alias))
  via_alias <- .dsvert_dp_ledger_path(
    file.path(parent_alias, "via-alias.sqlite"), require_private = TRUE)
  expect_identical(
    via_alias,
    file.path(normalizePath(root, winslash = "/"), "via-alias.sqlite"))

  file.create(path)
  Sys.chmod(path, mode = "0644")
  expect_error(
    .dsvert_dp_ledger_path(path, require_private = TRUE), "mode 0600")
  unlink(path)

  target <- file.path(root, "target.sqlite")
  file.create(target)
  Sys.chmod(target, mode = "0600")
  expect_true(file.symlink(target, path))
  expect_error(
    .dsvert_dp_ledger_path(path, require_private = TRUE), "symbolic link")
  unlink(path)

  expect_true(file.symlink(file.path(root, "missing.sqlite"), path))
  expect_error(
    .dsvert_dp_ledger_path(path, require_private = TRUE), "symbolic link")
  unlink(path)

  insecure <- tempfile("dsvert-shared-ledger-")
  dir.create(insecure, mode = "0755")
  Sys.chmod(insecure, mode = "0755")
  on.exit(unlink(insecure, recursive = TRUE, force = TRUE), add = TRUE)
  expect_error(.dsvert_dp_ledger_path(
    file.path(insecure, "ledger.sqlite"), require_private = TRUE), "mode 0700")

  ledger <- file.path(root, "sidecars.sqlite")
  .dp_test_policy(ledger)
  policy <- .dsvert_dp_policy()
  handle <- .dsvert_dp_open_ledger(policy)
  open_paths <- handle$paths[file.exists(handle$paths)]
  expect_true(all(c("ledger", "lock", "wal", "shm") %in%
                  names(open_paths)))
  expect_true(all(vapply(open_paths, .dsvert_dp_private_mode, logical(1L))))
  .dsvert_dp_close_ledger(handle)
  existing <- c(ledger, paste0(ledger, ".lock"))
  existing <- existing[file.exists(existing)]
  expect_true(length(existing) >= 1L)
  expect_true(all(vapply(existing, .dsvert_dp_private_mode, logical(1L))))

  hardlink <- file.path(root, "ledger-hardlink.sqlite")
  expect_true(file.link(ledger, hardlink))
  private_policy <- policy
  private_policy$ledger_private <- TRUE
  expect_error(.dsvert_dp_open_ledger(private_policy), "hard links")
  unlink(hardlink)

  file.symlink(target, paste0(ledger, "-wal"))
  expect_error(.dsvert_dp_open_ledger(policy), "symbolic link")
})

test_that("protected DP datasets are bound to a custodian-approved snapshot", {
  protected <- data.frame(
    patient_id = c("p2", "p1"), x = c(2, 1), stringsAsFactors = FALSE)
  protected <- .dp_test_align(protected)
  digest <- .dsvert_dp_snapshot_digest(protected)
  alignment <- .psi_validate_alignment_manifest(protected)
  expect_match(digest, "^[0-9a-f]{64}$")
  expect_false(identical(
    digest,
    .dsvert_dp_snapshot_digest(protected[2:1, , drop = FALSE])))
  expect_identical(
    digest,
    .dsvert_dp_snapshot_digest(
      protected[c("x", "patient_id")]))

  ledger <- file.path(tempdir(), paste0("dp-snapshot-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(
    ledger,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.decay = 0.5,
    dsvert.dp.anchor_provider = .dp_test_anchor_provider(),
    dsvert.dp.datasets = list(protected = list(
      id = "snapshot-study", version = "v1", snapshot_sha256 = digest,
      alignment_manifest_hash = alignment$hash,
      alignment_manifest_version = alignment$version)),
    .production_contract = TRUE)
  private_policy <- .dsvert_dp_policy()
  public_policy <- .dsvert_dp_policy_public(private_policy)
  expect_identical(public_policy$schema_version, 9L)
  expect_identical(
    public_policy$policy_contract,
    "single_disclosure_safe_capsule_policy_v2")
  expect_identical(public_policy$lifetime_max_distinct_capsules, 1)
  expect_identical(public_policy$peer_count, 2L)
  expect_identical(public_policy$designated_noise_peers,
                   c("site_a", "site_b"))
  expect_false(any(c(
    "decay", "composition_partitions", "local_total_epsilon",
    "local_total_delta", "allocation_total_epsilon",
    "allocation_total_delta") %in% names(public_policy)))
  expect_named(public_policy$datasets$protected, c(
    "id", "version", "alignment_attested",
    "alignment_protocol_version"))
  expect_true(public_policy$datasets$protected$alignment_attested)
  expect_false(any(c("snapshot_sha256", "alignment_manifest_hash") %in%
                   names(public_policy$datasets$protected)))
  neighboring_policy <- private_policy
  neighboring_policy$datasets$protected$snapshot_sha256 <-
    paste(rep("c", 64L), collapse = "")
  neighboring_policy$datasets$protected$alignment_manifest_hash <-
    paste(rep("d", 64L), collapse = "")
  expect_identical(.dsvert_dp_policy_public(neighboring_policy), public_policy)
  status <- testthat::with_mocked_bindings(
    dsvertDPStatusDS(),
    .dsvert_mpc_require_capabilities = function(...) {
      stop("pending status must not probe the legacy sampler", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(
    status$policy$rollback_protection$mode,
    "pinned_peer_global_allocator_pending_plus_external_cas")
  expect_equal(status$policy$global_total_epsilon, 1)
  expect_equal(status$global_epsilon_used, 0)
  expect_equal(status$global_epsilon_remaining, 1)
  expect_false(any(grepl("^local_", names(status))))
  inactive <- .dsvert_dp_inactive_local_history(
    ledger, .dsvert_dp_secret())
  expect_identical(inactive$status, "empty")
  expect_identical(inactive$seal$count, 0)
  expect_error(dsvertDPCountDS("protected"),
               "fail-closed.*not E2E verified")

  bad_ledger <- file.path(
    tempdir(), paste0("dp-snapshot-bad-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    bad_ledger,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.decay = 0.5,
    dsvert.dp.anchor_provider = .dp_test_anchor_provider(),
    dsvert.dp.datasets = list(protected = list(
      id = "snapshot-study", version = "v1",
      snapshot_sha256 = paste(rep("0", 64L), collapse = ""),
      alignment_manifest_hash = alignment$hash,
      alignment_manifest_version = alignment$version)),
    .production_contract = TRUE)
  # Read-only status performs setup attestation; informative endpoints remain
  # generically gated before touching the protected snapshot.
  expect_error(dsvertDPStatusDS(), "custodian-approved")
  expect_error(dsvertDPCountDS("protected"),
               "fail-closed.*not E2E verified")

  expect_error(.dsvert_dp_datasets(list(
    A = list(id = "same", version = "v1"),
    B = list(id = "same", version = "v1")),
    require_snapshot_digest = FALSE,
    require_alignment_manifest = FALSE), "aliases")
})

test_that("DP snapshot binding rejects an alignment on the wrong patient column", {
  protected <- data.frame(
    patient_id = c("p1", "p2"), alternate_id = c("a1", "a2"),
    x = c(1, 2), stringsAsFactors = FALSE)
  protected <- .dp_test_align(protected, "alternate_id")
  alignment <- .psi_validate_alignment_manifest(protected)
  expect_identical(alignment$id_col, "alternate_id")
  ledger <- file.path(
    tempdir(), paste0("dp-wrong-alignment-id-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    ledger,
    dsvert.dp.anchor_provider = .dp_test_anchor_provider(),
    dsvert.dp.patient_column = "patient_id",
    dsvert.dp.datasets = list(protected = list(
      id = "snapshot-study", version = "v1",
      snapshot_sha256 = .dsvert_dp_snapshot_digest(protected),
      alignment_manifest_hash = alignment$hash,
      alignment_manifest_version = alignment$version)),
    .production_contract = TRUE)

  expect_error(
    .dsvert_dp_dataset_binding(
      .dsvert_dp_policy(), "protected", protected, .dsvert_dp_secret()),
    "wrong privacy-unit column")
})

test_that("snapshot block commitments bind every row across chunk boundaries", {
  n <- .DSVERT_DP_SNAPSHOT_CHUNK_ROWS + 1L
  original <- data.frame(
    patient_id = sprintf("p%06d", seq_len(n)),
    x = as.numeric(seq_len(n)), stringsAsFactors = FALSE)
  expected <- .dsvert_dp_snapshot_digest(original)

  changed_left <- original
  changed_left$x[[.DSVERT_DP_SNAPSHOT_CHUNK_ROWS]] <- -1
  changed_right <- original
  changed_right$x[[n]] <- -1
  rownames(original) <- rev(seq_len(n))

  expect_false(identical(
    expected, .dsvert_dp_snapshot_digest(changed_left)))
  expect_false(identical(
    expected, .dsvert_dp_snapshot_digest(changed_right)))
  expect_identical(expected, .dsvert_dp_snapshot_digest(original))

  matrix_column <- data.frame(id = c("a", "b"))
  matrix_column$m <- I(matrix(1:4, nrow = 2L))
  expect_error(
    .dsvert_dp_snapshot_digest(matrix_column),
    "List, matrix, and array columns")
})

test_that("snapshot canonicalization rejects executable column semantics", {
  ordinary <- data.frame(
    patient_id = c("p1", "p2"), value = c(1, 2),
    stringsAsFactors = FALSE)
  expect_match(.dsvert_dp_snapshot_digest(ordinary), "^[0-9a-f]{64}$")

  custom <- ordinary
  class(custom$value) <- c("mutable_value", class(custom$value))
  expect_error(
    .dsvert_dp_snapshot_digest(custom),
    "custom S3 classes must be converted explicitly")

  attributed <- ordinary
  attr(attributed$value, "mutable_state") <- new.env(parent = emptyenv())
  expect_error(
    .dsvert_dp_snapshot_digest(attributed),
    "invalid or executable attributes")

  builtins <- data.frame(
    category = factor(c("b", "a"), levels = c("a", "b")),
    day = as.Date(c("2025-01-01", "2025-01-02")),
    instant = as.POSIXct(
      c("2025-01-01 00:00:00", "2025-01-02 00:00:00"), tz = "UTC"))
  expect_match(.dsvert_dp_snapshot_digest(builtins), "^[0-9a-f]{64}$")

  skip_if_not_installed("data.table")
  tabular <- data.table::as.data.table(ordinary)
  expect_identical(
    .dsvert_dp_snapshot_digest(tabular),
    .dsvert_dp_snapshot_digest(ordinary))
})

test_that("a production snapshot is validated once and then stays immutable", {
  data_envir <- new.env(parent = emptyenv())
  data_envir$protected <- data.frame(
    patient_id = c("p1", "p2"), x = c(1, 2),
    stringsAsFactors = FALSE)
  policy <- list(
    require_snapshot_digest = TRUE,
    domain = "snapshot-cache-test",
    datasets = list(protected = list(
      id = "cache-study", version = "v1",
      snapshot_sha256 = strrep("a", 64L))))
  cache_key <- .dsvert_dp_snapshot_cache_key(
    policy, "protected", data_envir)
  if (exists(cache_key, envir = .dsvert_dp_snapshot_cache,
             inherits = FALSE)) {
    rm(list = cache_key, envir = .dsvert_dp_snapshot_cache)
  }
  on.exit({
    if (bindingIsLocked("protected", data_envir)) {
      unlockBinding("protected", data_envir)
    }
    if (exists(cache_key, envir = .dsvert_dp_snapshot_cache,
               inherits = FALSE)) {
      rm(list = cache_key, envir = .dsvert_dp_snapshot_cache)
    }
  }, add = TRUE)

  validations <- 0L
  testthat::local_mocked_bindings(
    .dsvert_dp_dataset_binding = function(policy, data_name, data, secret) {
      validations <<- validations + 1L
      list(public = list(id = "cache-study", version = "v1"),
           ledger_key = paste0("dataset_snapshot_", strrep("b", 40L)),
           fingerprint = strrep("c", 64L))
    },
    .package = "dsVert")

  first <- .dsvert_dp_resolve_snapshot(
    policy, "protected", data_envir, "test-secret")
  second <- .dsvert_dp_resolve_snapshot(
    policy, "protected", data_envir, "test-secret")

  expect_identical(validations, 1L)
  expect_false(first$memoized_snapshot)
  expect_true(second$memoized_snapshot)
  expect_identical(first$data, second$data)
  expect_identical(first$dataset, second$dataset)
  expect_true(bindingIsLocked("protected", data_envir))
  expect_error(
    assign("protected", data.frame(x = 3), envir = data_envir),
    "locked binding")
})

test_that("reference-mutable snapshots are copied and active bindings fail closed", {
  skip_if_not_installed("data.table")
  policy <- list(
    require_snapshot_digest = TRUE,
    domain = "snapshot-mutation-test",
    datasets = list(protected = list(
      id = "mutation-study", version = "v1",
      snapshot_sha256 = strrep("d", 64L))))

  reference_envir <- new.env(parent = emptyenv())
  reference_envir$protected <- data.table::data.table(x = 1)
  cache_key <- .dsvert_dp_snapshot_cache_key(
    policy, "protected", reference_envir)
  on.exit({
    if (bindingIsLocked("protected", reference_envir)) {
      unlockBinding("protected", reference_envir)
    }
    if (exists(cache_key, envir = .dsvert_dp_snapshot_cache,
               inherits = FALSE)) {
      rm(list = cache_key, envir = .dsvert_dp_snapshot_cache)
    }
  }, add = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_dp_dataset_binding = function(...) list(
      public = list(id = "mutation-study", version = "v1"),
      ledger_key = paste0("dataset_snapshot_", strrep("e", 40L)),
      fingerprint = strrep("f", 64L)),
    .package = "dsVert")

  first <- .dsvert_dp_resolve_snapshot(
    policy, "protected", reference_envir, "test-secret")
  data.table::set(
    get("protected", envir = reference_envir), j = "x", value = 99)
  second <- .dsvert_dp_resolve_snapshot(
    policy, "protected", reference_envir, "test-secret")
  expect_identical(first$data$x, 1)
  expect_identical(second$data$x, 1)
  expect_identical(
    get("protected", envir = reference_envir)$x, 99)
  expect_true(bindingIsLocked("protected", reference_envir))

  active_envir <- new.env(parent = emptyenv())
  makeActiveBinding("protected", function(value) {
    if (!missing(value)) stop("read only")
    data.frame(x = 1)
  }, active_envir)
  expect_error(
    .dsvert_dp_resolve_snapshot(
      policy, "protected", active_envir, "test-secret"),
    "active bindings")
})

test_that("Google DP wrapper is strict and has no production R fallback", {
  seed <- paste(rep("0", 64L), collapse = "")
  sampled <- .dsvert_dp_noise_int64(
    c(1, 2), c(1, 0.5), c(1, 2), seed, sampler = .dp_test_sampler)
  expect_identical(sampled$values, c(1, 2))
  expect_identical(sampled$mechanism,
                   "dsvert_dp_v1_deterministic_granular_laplace_int64")
  expect_identical(sampled$sampler, "deterministic_two_sided_geometric")
  expect_identical(sampled$randomness, "HMAC-SHA256/ChaCha20")
  expect_true(all(sampled$accuracy_simultaneous_95_abs >=
                  sampled$accuracy_95_abs))
  expect_equal(sampled$simultaneous_confidence, 0.95)
  expect_identical(sampled$simultaneous_method, "union_bound")
  expect_error(.dsvert_dp_noise_int64(
    0, 2^-41, 1, seed, sampler = .dp_test_sampler), "granularity")
  expect_error(.dsvert_dp_noise_int64(
    0, 2^40 * (1 + .Machine$double.eps), 1, seed,
    sampler = .dp_test_sampler), "between 2\\^-50 and 2\\^40")
  expect_silent(.dsvert_dp_noise_int64(
    0, 2^40, 1, seed, sampler = .dp_test_sampler))
  expect_error(.dsvert_dp_noise_int64(
    0.5, 1, 1, seed, sampler = .dp_test_sampler), "exactly representable")
  expect_error(.dsvert_dp_noise_int64(
    0, 1, 1, seed, sampler = function(...) list(values = 0)),
    "invalid mechanism metadata")
  forged_radii <- function(values, epsilons, sensitivities, seed) {
    result <- .dp_test_sampler(values, epsilons, sensitivities, seed)
    result$accuracy_95_abs[] <- 0
    result$accuracy_simultaneous_95_abs[] <- 0
    result
  }
  expect_error(
    .dsvert_dp_noise_int64(
      c(0, 0), c(1, 1), c(1, 1), seed, sampler = forged_radii),
    "invalid result")
  expect_error(
    .dsvert_dp_noise_int64(0, 1, 1, "bad", sampler = .dp_test_sampler),
    "seed must contain")

  source <- paste(readLines(.dsvert_test_package_file(
    "R", "dpPolicyDS.R", source_only = TRUE),
                            warn = FALSE), collapse = "\n")
  expect_false(grepl("\\.dsvert_dp_discrete_laplace", source))
  expect_false(grepl("\\.dsvert_dp_crypto_uniform", source))
  expect_match(source, '\\.callMpcTool\\("dp-noise-int64"')
})

test_that("the packaged runtime implements the DP sampler command", {
  runtime_override <- Sys.getenv("DSVERT_TEST_MPC_BINARY", unset = "")
  if (nzchar(runtime_override)) {
    if (!file.exists(runtime_override)) {
      stop("DSVERT_TEST_MPC_BINARY does not exist", call. = FALSE)
    }
    withr::local_options(dsvert.mpc_binary = runtime_override)
  }
  sampled <- .dsvert_dp_noise_int64(
    0, 1, 1, paste(rep("0", 64L), collapse = ""))
  expect_length(sampled$values, 1L)
  expect_identical(
    sampled$mechanism,
    "dsvert_dp_v1_deterministic_granular_laplace_int64")
  expect_identical(sampled$sampler, "deterministic_two_sided_geometric")
  expect_identical(sampled$randomness, "HMAC-SHA256/ChaCha20")
})

test_that("the runtime accounts for approximate-Gaussian TV error", {
  runtime_override <- Sys.getenv("DSVERT_TEST_MPC_BINARY", unset = "")
  if (nzchar(runtime_override)) {
    if (!file.exists(runtime_override)) {
      stop("DSVERT_TEST_MPC_BINARY does not exist", call. = FALSE)
    }
    withr::local_options(dsvert.mpc_binary = runtime_override)
  }
  selected <- .dsvert_dp_noise_selection(
    coordinate_count = 64L,
    laplace_epsilons = 1,
    laplace_sensitivities = 100,
    gaussian_epsilon = 1,
    gaussian_delta = 1e-5,
    gaussian_l2_sensitivity = 1,
    objective = "simultaneous_95_abs")
  expect_identical(selected$schema_version, 2L)
  expect_identical(selected$winner, "gaussian")
  expected_bound <- .dsvert_dp_gaussian_implementation_delta_bound(64L, 1)
  expect_equal(
    selected$gaussian$implementation_delta_bound,
    expected_bound, tolerance = 1e-14)
  expect_gt(selected$gaussian$implementation_delta_bound, 64 * 2^-40)
  expect_lte(
    selected$gaussian$analytic_delta +
      selected$gaussian$implementation_delta_bound,
    selected$gaussian$delta)

  boundary <- .dsvert_dp_noise_selection(
    coordinate_count = 64L,
    laplace_epsilons = 1,
    laplace_sensitivities = 100,
    gaussian_epsilon = 1,
    gaussian_delta = expected_bound,
    gaussian_l2_sensitivity = 1,
    objective = "simultaneous_95_abs")
  expect_identical(boundary$winner, "laplace")
  expect_false(boundary$gaussian$available)
  expect_identical(
    boundary$gaussian$unavailable_reason,
    "gaussian_delta_does_not_cover_implementation_bound")

  sampled <- .dsvert_dp_gaussian_int64(
    c(0, 0), epsilon = 1, delta = 1e-5,
    l2_sensitivity = sqrt(2), seed = strrep("0", 64L))
  expect_equal(
    sampled$implementation_delta_bound,
    .dsvert_dp_gaussian_implementation_delta_bound(2L, 1),
    tolerance = 1e-14)
  expect_lte(
    sampled$analytic_delta + sampled$implementation_delta_bound,
    sampled$delta)
  expect_identical(
    sampled$accuracy_accounting,
    "gaussian_tail_alpha_minus_total_variation_union_bound")
})

test_that("memoization is bound to a public immutable dataset identity", {
  ledger <- file.path(tempdir(), paste0("dp-count-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(
    patient_id = c("p1", "p1", "p2", "p3"),
    value = c(1, 2, 3, 4), stringsAsFactors = FALSE)

  admission_calls <- 0L
  original_admission <- .dsvert_dp_admit_units
  first_and_second <- testthat::with_mocked_bindings(
    list(dsvertDPCountDS("protected"), dsvertDPCountDS("protected")),
    .dsvert_dp_admit_units = function(...) {
      admission_calls <<- admission_calls + 1L
      original_admission(...)
    },
    .package = "dsVert")
  first <- first_and_second[[1L]]
  second <- first_and_second[[2L]]
  expect_identical(admission_calls, 1L)
  expect_true(first$released)
  expect_identical(first$value, second$value)
  expect_false(any(c("release_id", "memoized") %in% names(first)))
  expect_false(any(c("release_id", "memoized") %in% names(second)))
  expect_equal(first$epsilon, 0.25)

  original <- protected
  protected <- protected[rev(seq_len(nrow(protected))), , drop = FALSE]
  expect_error(dsvertDPCountDS("protected"), "dataset version changed")

  protected <- original
  protected$patient_id[[4L]] <- "p4"
  expect_error(dsvertDPCountDS("protected"), "dataset version changed")

  protected_b <- data.frame(
    patient_id = c("p1", "p2", "p3", "p4"), stringsAsFactors = FALSE)
  third <- dsvertDPCountDS("protected_b")
  expect_equal(third$epsilon, 0.125)
  status <- dsvertDPStatusDS()
  expect_identical(status$informative_releases, 2)
  expect_lt(status$local_epsilon_used, status$policy$local_total_epsilon)
  expect_false(status$request_limit)
  expect_true(status$repeated_queries_are_memoized)

  protected_alias <- protected_b
  expect_error(dsvertDPCountDS("protected_alias"), "not registered")
})

test_that("an unchanged ledger uses its audited process seal in O(1)", {
  ledger <- file.path(
    tempdir(), paste0("dp-ledger-cache-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  expect_true(dsvertDPCountDS("protected")$released)
  cache_path <- .dsvert_dp_policy()$ledger_path
  expect_true(exists(
    cache_path, envir = .dsvert_dp_ledger_validation_cache,
    inherits = FALSE))

  original_validator <- .dsvert_dp_validate_release_row
  validations <- 0L
  testthat::local_mocked_bindings(
    .dsvert_dp_validate_release_row = function(row, secret) {
      validations <<- validations + 1L
      original_validator(row, secret)
    },
    .package = "dsVert")

  expect_true(dsvertDPCountDS("protected")$released)
  # The memoized query row is authenticated, but the already-sealed unchanged
  # historical chain is not scanned again.
  expect_identical(validations, 1L)

  rm(list = cache_path, envir = .dsvert_dp_ledger_validation_cache)
  validations <- 0L
  expect_true(dsvertDPCountDS("protected")$released)
  # A simulated process restart has no in-memory seal: full audit plus lookup.
  expect_identical(validations, 2L)
})

test_that("obsolete epsilon floors cannot impose a request limit", {
  ledger <- file.path(tempdir(), paste0("dp-floor-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger, dsvert.dp.composition_partitions = 1L,
                  dsvert.dp.minimum_release_epsilon = 0.2)
  releases <- vector("list", 8L)
  for (i in seq_along(releases)) {
    data_name <- paste0("protected", i)
    assign(data_name,
           data.frame(patient_id = paste0("p", seq_len(i)),
                      stringsAsFactors = FALSE))
    releases[[i]] <- dsvertDPCountDS(data_name)
  }
  expect_true(all(vapply(releases, `[[`, logical(1L), "released")))
  expect_identical(dsvertDPStatusDS()$informative_releases, 8)
})

test_that("mechanism-specific sampler floors suppress without ledger use", {
  run_count <- function(multiplier, suffix) {
    floor <- 1 / 2^40
    ledger <- file.path(
      tempdir(), paste0("dp-count-floor-", suffix, "-", Sys.getpid(),
                        ".sqlite"))
    .dp_test_policy(
      ledger, dsvert.dp.composition_partitions = 1L,
      dsvert.dp.total_epsilon = 2 * floor * multiplier,
      dsvert.dp.decay = 0.5,
      dsvert.dp.datasets = list(
        protected = list(id = paste0("count-floor-", suffix), version = "v1")))
    protected <- data.frame(patient_id = c("p1", "p2"),
                            stringsAsFactors = FALSE)
    list(release = dsvertDPCountDS("protected"),
         status = dsvertDPStatusDS())
  }
  below <- run_count(1 - 1e-6, "below")
  expect_false(below$release$released)
  expect_identical(below$release$reason,
                   "privacy_allocation_not_representable")
  expect_equal(below$release$epsilon, 0)
  expect_identical(below$status$informative_releases, 0)

  above <- run_count(1 + 1e-6, "above")
  expect_true(above$release$released)
  expect_identical(above$status$informative_releases, 1)

  table_ledger <- file.path(
    tempdir(), paste0("dp-table-floor-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    table_ledger, dsvert.dp.composition_partitions = 1L,
    dsvert.dp.total_epsilon = 2 * (1 / 2^40) * (1 - 1e-6),
    dsvert.dp.decay = 0.5,
    dsvert.dp.categorical_levels = list(
      exposed = c("no", "yes"), outcome = c("no", "yes")),
    dsvert.dp.datasets = list(
      protected = list(id = "table-floor-below", version = "v1")))
  protected <- data.frame(
    patient_id = c("p1", "p2"), exposed = c("yes", "no"),
    outcome = c("yes", "no"), stringsAsFactors = FALSE)
  below_table <- dsvertDPContingencyDS(
    "protected", "exposed", "outcome")
  expect_false(below_table$released)
  expect_identical(
    below_table$unit_aggregation_policy,
    "consistent_cell_else_exclude_v1")
  expect_false(any(grepl(
    "excluded|conflict", names(below_table), ignore.case = TRUE)))

  run_moments <- function(multiplier, suffix) {
    grid_scale <- 2^16
    floor <- 3 * grid_scale / 2^40
    ledger <- file.path(
      tempdir(), paste0("dp-moment-floor-", suffix, "-", Sys.getpid(),
                        ".sqlite"))
    .dp_test_policy(
      ledger, dsvert.dp.composition_partitions = 1L,
      dsvert.dp.total_epsilon = 2 * floor * multiplier,
      dsvert.dp.decay = 0.5,
      dsvert.dp.numeric_bounds = list(age = c(0, 120)),
      dsvert.dp.datasets = list(
        protected = list(id = paste0("moment-floor-", suffix), version = "v1")))
    protected <- data.frame(patient_id = c("p1", "p2"), age = c(20, 60),
                            stringsAsFactors = FALSE)
    list(release = dsvertDPMeanVarDS("protected", "age"),
         status = dsvertDPStatusDS())
  }
  below_moments <- run_moments(1 - 1e-6, "below")
  expect_false(below_moments$release$released)
  expect_identical(below_moments$status$informative_releases, 0)

  above_moments <- run_moments(1 + 1e-6, "above")
  expect_true(above_moments$release$released)
  expect_identical(above_moments$status$informative_releases, 1)
})

test_that("policy drift and ledger tampering are detected", {
  ledger <- file.path(tempdir(), paste0("dp-integrity-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(patient_id = c("a", "b"), stringsAsFactors = FALSE)
  original <- dsvertDPCountDS("protected")

  con <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(con, "UPDATE dp_releases SET payload = '{}' WHERE release_index = 0")
  DBI::dbDisconnect(con)
  expect_error(dsvertDPCountDS("protected"), "integrity check")

  ledger2 <- file.path(tempdir(), paste0("dp-drift-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger2, paste0(ledger2, "-wal"), paste0(ledger2, "-shm"),
           paste0(ledger2, ".lock")), force = TRUE)
  .dp_test_policy(ledger2)
  expect_true(dsvertDPCountDS("protected")$released)
  options(dsvert.dp.total_epsilon = 2)
  expect_error(dsvertDPStatusDS(), "immutable policy")
})

test_that("retired local DP migration path uses exact pins and fails closed pending the automatic allocator", {
  # These scalar DP functions are deliberately unregistered compatibility
  # primitives. Exercise their ledger migration contract through the
  # test-only compatibility gate; production has no corresponding selector.
  ledger <- file.path(tempdir(), paste0("dp-strict-contract-", Sys.getpid(),
                                        ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), x = c(1, 2),
    stringsAsFactors = FALSE))
  .dp_test_strict_policy(ledger, list(protected = protected),
                         .dp_test_anchor_provider())
  status <- dsvertDPStatusDS()
  expect_identical(
    status$policy$rollback_protection$mode,
    "pinned_peer_global_allocator_pending_plus_external_cas")
  expect_false(status$rollback_anchor$ready)
  expect_true(status$rollback_anchor$external)
  expect_error(dsvertDPCountDS("protected"),
               "fail-closed.*not E2E verified")

  # The first successful full validation freezes this logical dataset version.
  # A reordered cohort must be published under a new custodian version rather
  # than replacing the object behind an existing sticky query identity.
  expect_error(
    protected <- protected[2:1, , drop = FALSE],
    "locked binding")
  expect_error(dsvertDPCountDS("protected"),
               "fail-closed.*not E2E verified")

  options(dsvert.dp.cohort_id = "different-cohort")
  expect_error(dsvertDPStatusDS(), "immutable policy")

  missing_anchor_root <- tempfile("dp-strict-no-anchor-")
  dir.create(missing_anchor_root, mode = "0700")
  Sys.chmod(missing_anchor_root, mode = "0700")
  on.exit(unlink(missing_anchor_root, recursive = TRUE, force = TRUE),
          add = TRUE)
  missing_anchor_ledger <- file.path(missing_anchor_root, "ledger.sqlite")
  .dp_test_strict_policy(
    missing_anchor_ledger, list(protected = .dp_test_align(data.frame(
      patient_id = c("p1", "p2"), stringsAsFactors = FALSE))), NULL)
  pending <- .dsvert_dp_policy()
  expect_identical(
    pending$rollback_protection$mode,
    "pinned_peer_global_allocator_pending")
  expect_error(.dsvert_dp_release(
    pending, strrep("a", 64L), "dataset_snapshot_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    strrep("b", 64L), "pending-test", 1,
    function(...) stop("must not sample", call. = FALSE)),
    "fail-closed.*not E2E verified")
  expect_false(file.exists(missing_anchor_ledger))

  options(dsvert.dp.total_epsilon = 1,
          dsvert.dp.total_delta = 0,
          dsvert.dp.decay = -1,
          dsvert.dp.composition_partitions = 3L,
          dsvert.trusted_peers = c(site_b = .dp_test_pk(32L)))
  ignored_legacy <- .dsvert_dp_policy()
  expect_identical(ignored_legacy$peer_count, 2L)
  expect_false(any(c("decay", "composition_partitions") %in%
                   names(ignored_legacy)))
})

test_that("retired anchor-free DP status cannot sample or charge locally", {
  root <- tempfile("dp-auto-allocator-pending-")
  dir.create(root, mode = "0700")
  Sys.chmod(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  ledger <- file.path(root, "ledger.sqlite")
  pending_data <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(pending_data = pending_data), anchor_provider = NULL)

  status <- dsvertDPStatusDS()
  expect_identical(
    status$policy$rollback_protection$mode,
    "pinned_peer_global_allocator_pending")
  expect_false(status$rollback_anchor$ready)
  expect_identical(status$informative_releases, 0)
  expect_error(dsvertDPCountDS("pending_data"),
               "fail-closed.*not E2E verified")
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_identical(DBI::dbGetQuery(
    connection,
    "SELECT value FROM dp_meta WHERE key = 'next_index'")$value[[1L]],
    "0")
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM dp_releases")$n[[1L]], 0)
})

test_that("fixed-cohort public constant never waits for a private allocator", {
  root <- tempfile("dp-fixed-count-pending-allocator-")
  dir.create(root, mode = "0700")
  Sys.chmod(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  ledger <- file.path(root, "ledger.sqlite")
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected), anchor_provider = NULL,
    dsvert.dp.adjacency = "replace_one_fixed_cohort",
    dsvert.dp.unit_capacity = 2L,
    dsvert.dp.fixed_cohort_size = 2L,
    dsvert.dp.max_records_per_unit = 1L)

  before <- dsvertDPStatusDS()
  expect_false(before$rollback_anchor$ready)
  release <- dsvertPublicFixedCohortCountDS("protected")
  replay <- dsvertPublicFixedCohortCountDS("protected")
  after <- dsvertDPStatusDS()

  expect_identical(release, replay)
  expect_identical(release$value, 2)
  expect_identical(release$mechanism, "public_fixed_cohort_size_v1")
  expect_identical(release$sensitivity, 0)
  expect_identical(release$epsilon, 0)
  expect_identical(release$delta, 0)
  expect_identical(release$peer_count, 2L)
  expect_false("composition_partitions" %in% names(release))
  expect_identical(after$allocation_slots_consumed,
                   before$allocation_slots_consumed)
  expect_identical(after$informative_releases,
                   before$informative_releases)
})

test_that("retired local DP primitives cannot bypass the pending global allocator", {
  ledger_dir <- file.path(
    tempdir(), paste0("dp-strict-endpoints-", Sys.getpid()))
  dir.create(ledger_dir, mode = "0700", showWarnings = FALSE)
  Sys.chmod(ledger_dir, mode = "0700")
  ledger <- file.path(ledger_dir, "ledger.sqlite")
  on.exit(unlink(ledger_dir, recursive = TRUE, force = TRUE), add = TRUE)
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"),
    exposed = c("yes", "no"), outcome = c("yes", "no"),
    age = c(20, 40), time = c(1, 2), status = c("A", "0"),
    stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected),
    .dp_test_anchor_provider("strict-endpoint-witness"),
    dsvert.dp.unit_capacity = 4L,
    dsvert.dp.max_records_per_unit = 1L,
    dsvert.dp.categorical_levels = list(
      exposed = c("no", "yes"), outcome = c("no", "yes"),
      status = c("0", "A")),
    dsvert.dp.numeric_bounds = list(age = c(0, 120), time = c(0, 4)),
    dsvert.dp.describe_specs = list(primary = list(
      version = "v1", dataset = "protected", variables = "age",
      histogram_grids = list(age = c(30, 60, 90, 120)),
      allocation = c(
        count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2))),
    dsvert.dp.survival_specs = list(primary = list(
      version = "v1", dataset = "protected", time = "time",
      event = "status", censor = "0", time_grid = 1:4, entry = NULL)))

  status <- dsvertDPStatusDS()
  expect_identical(
    status$policy$rollback_protection$mode,
    "pinned_peer_global_allocator_pending_plus_external_cas")
  calls <- list(
    function() dsvertDPCountDS("protected"),
    function() dsvertDPContingencyDS("protected", "exposed", "outcome"),
    function() dsvertDPMeanVarDS("protected", "age"),
    function() dsvertDPDescribeDS("protected", "primary"),
    function() dsvertDPSurvivalDS("protected", "primary"))
  for (call in calls) {
    expect_error(call(), "fail-closed.*not E2E verified")
  }
  expect_error(
    dsvertDPCountDS("missing-protected-object"),
    "fail-closed.*not E2E verified")
  status <- dsvertDPStatusDS()
  expect_identical(status$informative_releases, 0)
  expect_identical(status$allocation_slots_consumed, 0)
})

test_that("external anchor schema versions are exact", {
  ledger <- file.path(tempdir(), paste0("dp-anchor-schema-", Sys.getpid(),
                                        ".sqlite"))
  provider <- .dp_test_anchor_provider("schema-witness")
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected), provider,
    .local_anchor_protocol_test = TRUE)
  policy <- .dsvert_dp_policy()

  malformed_state <- list(
    schema_version = 2.9,
    policy_hash = .dsvert_dp_policy_hash(policy),
    next_index = 0, chain_head = "GENESIS")
  expect_error(
    .dsvert_dp_anchor_state(malformed_state, policy),
    "invalid state")

  legacy_state <- list(
    schema_version = 1L,
    policy_hash = .dsvert_dp_policy_hash(policy),
    next_index = 0)
  expect_error(
    .dsvert_dp_anchor_state(legacy_state, policy),
    "legacy schema v1")

  malformed_capabilities <- function(action, anchor_id, expected = NULL,
                                     replacement = NULL) {
    result <- provider(action, anchor_id, expected, replacement)
    if (identical(action, "capabilities")) result$schema_version <- "1"
    result
  }
  options(dsvert.dp.anchor_provider = malformed_capabilities)
  expect_error(
    .dsvert_dp_anchor_capabilities(.dsvert_dp_policy()),
    "does not attest")
})

test_that("a local ledger rollback fails closed without changing sticky mappings", {
  ledger <- file.path(tempdir(), paste0("dp-full-rollback-", Sys.getpid(),
                                        ".sqlite"))
  snapshot <- paste0(ledger, ".old")
  unlink(c(ledger, snapshot, paste0(ledger, "-wal"),
           paste0(ledger, "-shm"), paste0(ledger, ".lock")), force = TRUE)
  provider <- .dp_test_anchor_provider("rollback-witness")
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), x = c(1, 2),
    stringsAsFactors = FALSE))
  protected_b <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), x = c(10, 20),
    stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected, protected_b = protected_b), provider,
    .local_anchor_protocol_test = TRUE)

  first <- dsvertDPCountDS("protected")
  expect_equal(first$epsilon, 0.25)
  con <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(con, "PRAGMA wal_checkpoint(TRUNCATE)")
  DBI::dbDisconnect(con)
  expect_true(file.copy(ledger, snapshot, overwrite = TRUE))

  second <- dsvertDPCountDS("protected_b")
  expect_equal(second$epsilon, 0.125)
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm")),
         force = TRUE)
  expect_true(file.copy(snapshot, ledger, overwrite = TRUE))

  rollback_error <- "anchor is ahead of the authenticated local query-to-payload ledger"
  expect_error(dsvertDPStatusDS(), rollback_error)
  # Even a query whose old payload is still present is not served while the
  # durable ledger and rollback witness disagree. This prevents an incomplete
  # restored mapping from becoming an oracle for which queries survived.
  expect_error(dsvertDPCountDS("protected"), rollback_error)
  expect_error(dsvertDPCountDS("protected_b"), rollback_error)

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT release_index, payload FROM dp_releases ORDER BY release_index"))
  expect_equal(nrow(rows), 1L)
  expect_identical(rows$release_index[[1L]], 0L)
  expect_identical(
    jsonlite::fromJSON(rows$payload[[1L]], simplifyVector = TRUE),
    first[setdiff(names(first), c(
      "epsilon", "delta", "adjacency", "composition_partitions"))])
})

test_that("two-phase releases are crash safe at every durable boundary", {
  phases <- c(
    "before_sampling", "after_sampling", "after_local_commit",
    "after_anchor_commit")
  fixture_envir <- environment()
  clear_snapshot_fixture <- function() {
    if (exists("protected", envir = fixture_envir, inherits = FALSE) &&
        bindingIsLocked("protected", fixture_envir)) {
      unlockBinding("protected", fixture_envir)
    }
    cached <- ls(.dsvert_dp_snapshot_cache, all.names = TRUE)
    if (length(cached)) {
      rm(list = cached, envir = .dsvert_dp_snapshot_cache)
    }
  }
  on.exit(clear_snapshot_fixture(), add = TRUE)
  for (phase in phases) {
    clear_snapshot_fixture()
    ledger <- file.path(tempdir(), paste0(
      "dp-two-phase-", phase, "-", Sys.getpid(), ".sqlite"))
    unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
             paste0(ledger, ".lock")), force = TRUE)
    provider <- .dp_test_anchor_provider(paste0("phase-", phase))
    protected <- .dp_test_align(data.frame(
      patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
    .dp_test_strict_policy(
      ledger, list(protected = protected), provider,
      .local_anchor_protocol_test = TRUE)
    policy <- .dsvert_dp_policy()
    sampler_calls <- 0L
    sampled_payloads <- list()
    release_fn <- function(epsilon, delta, seed) {
      sampler_calls <<- sampler_calls + 1L
      sampled <- .dsvert_dp_noise_int64(0, epsilon, 1, seed)
      value <- list(released = TRUE, value = sampled$values[[1L]])
      sampled_payloads[[length(sampled_payloads) + 1L]] <<- value
      value
    }
    failed <- FALSE
    lock_checks <- logical()
    phase_hook <- function(current) {
      if (identical(.Platform$OS.type, "unix")) {
        lock_path <- paste0(ledger, ".lock")
        probe <- paste0(
          "candidate <- filelock::lock(", deparse(lock_path),
          ", timeout=0); quit(status=if (is.null(candidate)) 0L else 1L)")
        status <- system2(
          file.path(R.home("bin"), "Rscript"),
          c("-e", shQuote(probe)), stdout = FALSE, stderr = FALSE)
        lock_checks <<- c(lock_checks, identical(status, 0L))
      }
      if (!failed && identical(current, phase)) {
        failed <<- TRUE
        stop("simulated phase crash", call. = FALSE)
      }
    }

    first <- tryCatch(.dp_test_direct_release(
      policy, protected, paste0("phase_", phase), release_fn,
      phase_hook), error = identity)
    expect_s3_class(first, "error")
    expect_match(conditionMessage(first), "simulated phase crash",
                 info = phase)
    if (identical(.Platform$OS.type, "unix")) {
      expect_true(all(lock_checks), info = phase)
    }

    connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
    rows <- DBI::dbGetQuery(connection,
      "SELECT payload FROM dp_releases ORDER BY release_index")
    DBI::dbDisconnect(connection)
    locally_committed <- phase %in%
      c("after_local_commit", "after_anchor_commit")
    expect_equal(nrow(rows), as.integer(locally_committed), info = phase)

    states <- attr(provider, "states")
    anchor_id <- policy$rollback_protection$anchor_id
    anchor_after_failure <- get(
      anchor_id, envir = states, inherits = FALSE)$next_index
    expect_equal(
      anchor_after_failure,
      if (identical(phase, "after_anchor_commit")) 1 else 0,
      info = phase)

    replay <- .dp_test_direct_release(
      policy, protected, paste0("phase_", phase), release_fn)
    expected_calls <- switch(
      phase, before_sampling = 1L, after_sampling = 2L,
      after_local_commit = 1L, after_anchor_commit = 1L)
    expect_identical(sampler_calls, expected_calls, info = phase)
    if (identical(phase, "after_sampling")) {
      expect_identical(sampled_payloads[[1L]], sampled_payloads[[2L]],
                       info = phase)
    }
    if (locally_committed) {
      expect_identical(
        .dsvert_dp_canonical_json(replay$payload), rows$payload[[1L]],
        info = phase)
    }
    expect_identical(
      get(anchor_id, envir = states, inherits = FALSE)$next_index, 1,
      info = phase)
    expect_equal(dsvertDPStatusDS()$informative_releases, 1, info = phase)
  }
})

test_that("unknown CAS read-back accepts only expected or replacement", {
  run_case <- function(outcome = c("expected", "replacement", "third")) {
    outcome <- match.arg(outcome)
    ledger <- file.path(tempdir(), paste0(
      "dp-cas-readback-", outcome, "-", Sys.getpid(), ".sqlite"))
    unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
             paste0(ledger, ".lock")), force = TRUE)
    underlying <- .dp_test_anchor_provider(paste0("readback-", outcome))
    states <- attr(underlying, "states")
    lose_once <- TRUE
    uncertain <- function(action, anchor_id, expected = NULL,
                          replacement = NULL) {
      if (identical(action, "compare_and_swap") && !is.null(expected) &&
          isTRUE(lose_once)) {
        lose_once <<- FALSE
        if (!identical(outcome, "expected")) {
          underlying(action, anchor_id, expected, replacement)
        }
        if (identical(outcome, "third")) {
          third <- replacement
          third$next_index <- replacement$next_index + 1
          assign(anchor_id, third, envir = states)
        }
        stop("RAW_LOST_CAS_DETAIL", call. = FALSE)
      }
      underlying(action, anchor_id, expected, replacement)
    }
    protected <- .dp_test_align(data.frame(
      patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
    .dp_test_strict_policy(
      ledger, list(protected = protected), uncertain,
      .local_anchor_protocol_test = TRUE)
    policy <- .dsvert_dp_policy()
    sampler_calls <- 0L
    release_fn <- function(epsilon, delta, seed) {
      sampler_calls <<- sampler_calls + 1L
      sampled <- .dsvert_dp_noise_int64(0, epsilon, 1, seed)
      list(released = TRUE, value = sampled$values[[1L]])
    }
    first <- tryCatch(.dp_test_direct_release(
      policy, protected, paste0("cas_", outcome), release_fn),
      error = identity)
    replay <- tryCatch(.dp_test_direct_release(
      policy, protected, paste0("cas_", outcome), release_fn),
      error = identity)
    list(
      outcome = outcome, ledger = ledger, policy = policy,
      protected = protected, states = states, first = first,
      replay = replay, sampler_calls = sampler_calls)
  }

  expected <- run_case("expected")
  expect_s3_class(expected$first, "error")
  expect_match(conditionMessage(expected$first), "was not advanced")
  expect_false(grepl(
    "RAW_LOST_CAS_DETAIL", conditionMessage(expected$first), fixed = TRUE))
  expect_identical(expected$sampler_calls, 1L)
  expect_type(expected$replay, "list")
  expect_true(expected$replay$memoized)

  replacement <- run_case("replacement")
  expect_type(replacement$first, "list")
  expect_identical(replacement$sampler_calls, 1L)
  expect_type(replacement$replay, "list")
  expect_identical(replacement$replay$payload, replacement$first$payload)

  third <- run_case("third")
  expect_s3_class(third$first, "error")
  expect_match(conditionMessage(third$first), "incompatible")
  expect_identical(third$sampler_calls, 1L)
  expect_s3_class(third$replay, "error")
  expect_match(
    conditionMessage(third$replay),
    "anchor is ahead of the authenticated local query-to-payload ledger")
})

test_that("an authenticated local gap reconciles but a rebound policy fails", {
  ledger <- file.path(tempdir(), paste0("dp-anchor-mismatch-", Sys.getpid(),
                                        ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  provider <- .dp_test_anchor_provider("mismatch-witness")
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
  protected_b <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2", "p3"), stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected, protected_b = protected_b), provider,
    .local_anchor_protocol_test = TRUE)
  expect_true(dsvertDPCountDS("protected")$released)
  expect_true(dsvertDPCountDS("protected_b")$released)
  policy <- .dsvert_dp_policy()
  anchor_id <- policy$rollback_protection$anchor_id
  states <- attr(provider, "states")
  state <- get(anchor_id, envir = states, inherits = FALSE)
  state$next_index <- 0
  state$chain_head <- "GENESIS"
  assign(anchor_id, state, envir = states)
  status <- dsvertDPStatusDS()
  expect_identical(status$informative_releases, 2)
  expect_identical(
    get(anchor_id, envir = states, inherits = FALSE)$next_index, 2)

  state <- get(anchor_id, envir = states, inherits = FALSE)
  state$policy_hash <- paste(rep("0", 64L), collapse = "")
  assign(anchor_id, state, envir = states)
  expect_error(dsvertDPStatusDS(), "different immutable policy")
})

test_that("a tampered local gap never advances the external anchor", {
  ledger <- file.path(tempdir(), paste0(
    "dp-anchor-tampered-gap-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  provider <- .dp_test_anchor_provider("tampered-gap-witness")
  protected <- .dp_test_align(data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE))
  .dp_test_strict_policy(
    ledger, list(protected = protected), provider,
    .local_anchor_protocol_test = TRUE)
  expect_true(dsvertDPCountDS("protected")$released)
  policy <- .dsvert_dp_policy()
  anchor_id <- policy$rollback_protection$anchor_id
  states <- attr(provider, "states")
  state <- get(anchor_id, envir = states, inherits = FALSE)
  state$next_index <- 0
  state$chain_head <- "GENESIS"
  assign(anchor_id, state, envir = states)

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(connection,
    "UPDATE dp_releases SET payload = '{\"released\":true}' WHERE release_index = 0")
  DBI::dbDisconnect(connection)
  expect_error(dsvertDPStatusDS(), "integrity check")
  expect_identical(
    get(anchor_id, envir = states, inherits = FALSE)$next_index, 0)
})

test_that("a v2 chain receipt fails closed across split-brain replicas", {
  ledger_a <- file.path(tempdir(), paste0(
    "dp-split-brain-a-", Sys.getpid(), ".sqlite"))
  ledger_b <- file.path(tempdir(), paste0(
    "dp-split-brain-b-", Sys.getpid(), ".sqlite"))
  for (ledger in c(ledger_a, ledger_b)) {
    unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
             paste0(ledger, ".lock")), force = TRUE)
  }
  provider <- .dp_test_anchor_provider("split-brain-witness")
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)

  .dp_test_policy(
    ledger_a, dsvert.dp.anchor_provider = provider)
  policy_a <- .dsvert_dp_policy()
  .dp_test_policy(
    ledger_b, dsvert.dp.anchor_provider = provider)
  policy_b <- .dsvert_dp_policy()
  expect_identical(.dsvert_dp_policy_hash(policy_a),
                   .dsvert_dp_policy_hash(policy_b))
  expect_identical(policy_a$rollback_protection$anchor_id,
                   policy_b$rollback_protection$anchor_id)

  sampler_a <- sampler_b <- 0L
  release_a <- function(epsilon, delta, seed) {
    sampler_a <<- sampler_a + 1L
    list(released = TRUE, value = 101L)
  }
  release_b <- function(epsilon, delta, seed) {
    sampler_b <<- sampler_b + 1L
    list(released = TRUE, value = 202L)
  }
  stop_after_commit <- function(phase) {
    if (identical(phase, "after_local_commit")) {
      stop("simulated replica pause", call. = FALSE)
    }
  }
  expect_error(.dp_test_direct_release(
    policy_a, protected, "split_query_a", release_a, stop_after_commit),
    "simulated replica pause")
  expect_error(.dp_test_direct_release(
    policy_b, protected, "split_query_b", release_b, stop_after_commit),
    "simulated replica pause")

  row_mac <- function(path) {
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    DBI::dbGetQuery(connection,
      "SELECT row_mac FROM dp_releases WHERE release_index = 0")$row_mac[[1L]]
  }
  head_a <- row_mac(ledger_a)
  head_b <- row_mac(ledger_b)
  expect_false(identical(head_a, head_b))

  served_a <- .dp_test_direct_release(
    policy_a, protected, "split_query_a", release_a)
  expect_true(served_a$memoized)
  expect_identical(sampler_a, 1L)
  anchor_id <- policy_a$rollback_protection$anchor_id
  anchored <- get(anchor_id, envir = attr(provider, "states"),
                  inherits = FALSE)
  expect_identical(anchored$next_index, 1)
  expect_identical(anchored$chain_head, head_a)

  expect_error(.dp_test_direct_release(
    policy_b, protected, "split_query_b", release_b),
    "divergent chain receipts")
  expect_identical(sampler_b, 1L)
  expect_false(identical(anchored$chain_head, head_b))
})

test_that("concurrent identical releases commit only one noisy answer", {
  skip_on_os("windows")
  ledger <- file.path(tempdir(), paste0("dp-concurrent-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(patient_id = sprintf("p%03d", 1:100),
                          stringsAsFactors = FALSE)
  results <- parallel::mclapply(1:4, function(unused) {
    dsvertDPCountDS("protected")
  }, mc.cores = 4L)
  expect_length(unique(vapply(results, `[[`, numeric(1L), "value")), 1L)
  expect_identical(dsvertDPStatusDS()$informative_releases, 1)
  expect_true(all(vapply(results, function(result) {
    !any(c("release_id", "memoized") %in% names(result))
  }, logical(1L))))
})

test_that("fixed-domain tables bound each patient to one contribution", {
  ledger <- file.path(tempdir(), paste0("dp-table-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger,
    dsvert.dp.categorical_levels = list(
      exposed = c("no", "yes"), outcome = c("no", "yes")))
  protected <- data.frame(
    patient_id = c("p1", "p1", "p2", "p3", "p4", "p4", "p5"),
    exposed = c("yes", "yes", "no", "no", "yes", "no", "outside"),
    outcome = c("yes", "yes", "no", "yes", "yes", "yes", "yes"),
    stringsAsFactors = FALSE)
  bounded <- .dsvert_dp_bounded_pairs(
    protected, .dsvert_dp_policy(), "exposed", "outcome")
  expect_length(bounded$cell, .dsvert_dp_policy()$unit_capacity)
  expect_identical(sum(!is.na(bounded$cell)), 3L)

  pair_scan_calls <- 0L
  original_pairs <- .dsvert_dp_bounded_pairs
  query_arguments <- list()
  original_query_hash <- .dsvert_dp_query_hash
  releases <- testthat::with_mocked_bindings(
    list(
      dsvertDPContingencyDS("protected", "exposed", "outcome"),
      dsvertDPContingencyDS("protected", "exposed", "outcome")),
    .dsvert_dp_bounded_pairs = function(...) {
      pair_scan_calls <<- pair_scan_calls + 1L
      original_pairs(...)
    },
    .dsvert_dp_query_hash = function(secret, policy, dataset, method,
                                     arguments) {
      query_arguments[[length(query_arguments) + 1L]] <<- arguments
      original_query_hash(
        secret, policy, dataset, method, arguments)
    },
    .package = "dsVert")
  release <- releases[[1L]]
  repeated <- releases[[2L]]
  expect_identical(pair_scan_calls, 1L)
  expect_gte(length(query_arguments), 2L)
  expect_true(all(vapply(query_arguments, function(arguments) {
    identical(
      arguments$unit_aggregation_policy,
      "consistent_cell_else_exclude_v1")
  }, logical(1L))))
  expect_true(release$released)
  expect_length(release$counts, 4L)
  expect_identical(release$counts, repeated$counts)
  expect_identical(release$row_levels, c("no", "yes"))
  expect_identical(release$col_levels, c("no", "yes"))
  expect_identical(
    release$unit_aggregation_policy,
    "consistent_cell_else_exclude_v1")
  expect_false(any(grepl(
    "excluded|conflict", names(release), ignore.case = TRUE)))
  expect_length(release$accuracy_95_abs_per_cell, 4L)
  expect_gte(release$accuracy_simultaneous_95_abs,
             max(release$accuracy_95_abs_per_cell))
  expect_equal(release$accuracy_simultaneous_confidence, 0.95)
  expect_identical(release$accuracy_simultaneous_method, "union_bound")

  protected <- protected[rev(seq_len(nrow(protected))), , drop = FALSE]
  expect_error(
    dsvertDPContingencyDS("protected", "exposed", "outcome"),
    "dataset version changed")
})

test_that("DP domains are bounded before protected data access or allocation", {
  expect_identical(
    .dsvert_dp_coordinate_count(seq_len(1000L), seq_len(1000L)),
    1000000L)
  expect_error(
    .dsvert_dp_coordinate_count(seq_len(1001L), seq_len(1000L)),
    "exceeds 1000000 coordinates")

  policy <- list(
    categorical_levels = list(
      row = sprintf("r%04d", seq_len(1001L)),
      column = sprintf("c%04d", seq_len(1000L))),
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1")
  expect_error(
    .dsvert_dp_bounded_pairs(data.frame(), policy, "row", "column"),
    "exceeds 1000000 coordinates")
})

test_that("numeric DP bounds reject overflow and underflow geometry", {
  expect_error(
    .dsvert_dp_numeric_bounds(list(x = c(-1e308, 1e308))),
    "finite positive width")
  expect_error(
    .dsvert_dp_numeric_bounds(list(x = c(0, 1e200))),
    "finite positive squared width")
  expect_error(
    .dsvert_dp_numeric_bounds(list(x = c(0, .Machine$double.xmin))),
    "finite positive squared width")
  expect_identical(
    .dsvert_dp_numeric_bounds(list(x = c(-120, 120))),
    list(x = c(-120, 120)))
})

test_that("bounded moment release remains inside custodian limits", {
  ledger <- file.path(tempdir(), paste0("dp-moments-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger,
    dsvert.dp.numeric_bounds = list(age = c(0, 120)))
  protected <- data.frame(
    patient_id = sprintf("p%03d", seq_len(100L)),
    age = rep(c(-10, 40, 50, 70, 200), length.out = 100L),
    stringsAsFactors = FALSE)
  bounded <- .dsvert_dp_bounded_numeric(
    protected, .dsvert_dp_policy(), "age")
  expect_true(all(bounded$values >= 0 & bounded$values <= 120))
  expect_length(bounded$values, 100L)
  quantized <- .dsvert_dp_quantized_moments(
    bounded$values / 120, .dsvert_dp_policy()$numeric_grid_bits)
  expect_true(all(quantized$statistics == floor(quantized$statistics)))
  expect_equal(quantized$scale, 2^16)

  numeric_scan_calls <- 0L
  original_numeric <- .dsvert_dp_bounded_numeric
  releases <- testthat::with_mocked_bindings(
    list(dsvertDPMeanVarDS("protected", "age"),
         dsvertDPMeanVarDS("protected", "age")),
    .dsvert_dp_bounded_numeric = function(...) {
      numeric_scan_calls <<- numeric_scan_calls + 1L
      original_numeric(...)
    },
    .package = "dsVert")
  release <- releases[[1L]]
  repeated <- releases[[2L]]
  expect_identical(numeric_scan_calls, 1L)
  expect_true(release$released)
  expect_gte(release$mean, 0)
  expect_lte(release$mean, 120)
  expect_gte(release$variance, 0)
  expect_identical(
    release$variance_definition,
    "population_central_second_moment_denominator_n")
  mean_z <- release$mean / 120
  expect_lte(release$variance / 120^2,
             mean_z * (1 - mean_z) + 1e-12)
  expect_lte(release$variance, 120^2 / 4 + 1e-12)
  expect_identical(
    release$mechanism,
    "dsvert_dp_v1_deterministic_granular_laplace_int64")
  expect_identical(release$sampler, "deterministic_two_sided_geometric")
  expect_identical(release$randomness, "HMAC-SHA256/ChaCha20")
  expect_equal(sum(release$epsilon_allocation), release$epsilon)
  expect_identical(release$submechanism_count, 3L)
  expect_identical(
    release$composition_rule,
    "three_sequential_laplace_coordinates")
  expect_equal(release$coordinate_l1_sensitivity,
               c(1, 2^16, 2^16))
  expect_identical(release$mean, repeated$mean)
  expect_identical(release$variance, repeated$variance)
})

test_that("numeric contributions clip every row before patient collapse", {
  policy <- list(
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 2L, fixed_cohort_size = NULL,
    max_records_per_unit = 2L, overflow_policy = "reject_snapshot",
    numeric_bounds = list(age = c(0, 120)))
  protected <- data.frame(
    patient_id = c("p1", "p1", "p2", "p2"),
    age = c(-1e308, 1e308, -1e308, -1e308))
  bounded <- .dsvert_dp_bounded_numeric(protected, policy, "age")
  expect_identical(bounded$values, c(60, 0))
  expect_true(all(is.finite(bounded$unit_values)))
  expect_true(all(bounded$unit_values >= 0 & bounded$unit_values <= 120))
})

test_that("empty bounded moments consume DP and return a typed non-estimable result", {
  ledger <- file.path(
    tempdir(), paste0("dp-empty-moments-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(
    ledger, dsvert.dp.numeric_bounds = list(age = c(0, 120)))
  protected <- data.frame(
    patient_id = c("p1", "p2"), age = c(NA_real_, Inf),
    stringsAsFactors = FALSE)

  release <- dsvertDPMeanVarDS("protected", "age")
  repeat_release <- dsvertDPMeanVarDS("protected", "age")
  status <- dsvertDPStatusDS()
  expect_true(release$released)
  expect_identical(
    release$status, "dp_effective_count_not_certified_positive")
  expect_identical(
    release$reason, "dp_noisy_effective_count_lower_bound_is_zero")
  expect_true(is.numeric(release$n) && length(release$n) == 1L &&
                is.finite(release$n) && release$n >= 0 &&
                release$n == floor(release$n))
  expect_lte(release$n, release$accuracy_95_abs_count)
  expect_equal(release$effective_count_95_lower_bound, 0)
  expect_null(release$mean)
  expect_null(release$variance)
  expect_identical(repeat_release$status, release$status)
  expect_identical(repeat_release$n, release$n)
  expect_identical(status$informative_releases, 1)
  expect_gt(status$local_epsilon_used, 0)
})

test_that("bounded moments retain a DP point when only count confidence is weak", {
  ledger <- file.path(
    tempdir(), paste0("dp-small-moments-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(
    ledger, dsvert.dp.numeric_bounds = list(age = c(0, 120)))
  protected <- data.frame(
    patient_id = "p1", age = 60, stringsAsFactors = FALSE)

  release <- testthat::with_mocked_bindings(
    dsvertDPMeanVarDS("protected", "age"),
    .dsvert_dp_sample_selected_int64 = function(
        values, laplace_epsilons, laplace_sensitivities,
        epsilon, delta, l2_sensitivity, seed, mechanism_plan) {
      .dp_test_sampler(
        values, laplace_epsilons, laplace_sensitivities, seed)
    },
    .package = "dsVert")
  expect_identical(
    release$status, "dp_point_available_count_not_certified_positive")
  expect_identical(
    release$reason, "dp_noisy_effective_count_lower_bound_is_zero")
  expect_equal(release$n, 1)
  expect_equal(release$effective_count_95_lower_bound, 0)
  expect_equal(release$mean, 60)
  expect_equal(release$variance, 0)
})

test_that("DP noise roots are provisioned, private, and domain separated", {
  ledger <- file.path(
    tempdir(), paste0("dp-noise-root-", Sys.getpid(), ".sqlite"))
  secret_key <- as.raw(201:232)
  provider <- .dp_test_noise_provider(
    key = secret_key, key_id = "domain-separated-key")
  .dp_test_policy(
    ledger, dsvert.dp.noise_key_provider = provider,
    dsvert.dp.noise_key_epoch = 1)
  policy <- .dsvert_dp_policy()
  context <- list(
    dataset = list(id = "dataset", version = "v1"),
    method = "unit_count", arguments = list(adjacency = "patient_add_remove"))
  query_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), policy, context$dataset, context$method,
    context$arguments)
  seed <- .dsvert_dp_noise_seed(
    policy, query_hash, 0, "count", 0.25, 0, 1)
  expect_identical(
    seed,
    .dsvert_dp_noise_seed(policy, query_hash, 0, "count", 0.25, 0, 1))
  changed <- context
  changed$method <- "bounded_mean_variance"
  changed_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), policy, changed$dataset, changed$method,
    changed$arguments)
  expect_false(identical(
    seed,
    .dsvert_dp_noise_seed(
      policy, changed_hash, 0, "count", 0.25, 0, 1)))
  expect_false(identical(
    seed,
    .dsvert_dp_noise_seed(
      policy, query_hash, 1, "count", 0.25, 0, 1)))

  reordered_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), policy, context$dataset, context$method,
    list(second = list(z = 2L, a = 1L), first = 1L))
  normalized_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), policy, context$dataset, context$method,
    list(first = 1, second = list(a = 1, z = 2)))
  expect_identical(reordered_hash, normalized_hash)
  expect_identical(
    .dsvert_dp_noise_seed(
      policy, reordered_hash, 0, "count", 0.25, 0, 1),
    .dsvert_dp_noise_seed(
      policy, normalized_hash, 0, "count", 0.25, 0, 1))

  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  release <- dsvertDPCountDS("protected")
  status <- dsvertDPStatusDS()
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  persisted <- c(
    DBI::dbGetQuery(connection, "SELECT value FROM dp_meta")$value,
    DBI::dbGetQuery(connection, "SELECT payload FROM dp_releases")$payload)
  secret_hex <- paste(format(secret_key), collapse = "")
  secret_b64 <- jsonlite::base64_enc(secret_key)
  transcript <- c(
    .dsvert_dp_canonical_json(status),
    .dsvert_dp_canonical_json(release),
    persisted,
    paste(format(serialize(status, NULL, version = 3L)), collapse = ""),
    paste(format(serialize(release, NULL, version = 3L)), collapse = ""))
  expect_false(any(grepl(secret_hex, transcript, fixed = TRUE)))
  expect_false(any(grepl(secret_b64, transcript, fixed = TRUE)))
  expect_false(any(grepl(seed, transcript, fixed = TRUE)))
  expect_identical(status$noise_root$key_material_exposed, FALSE)
  expect_identical(status$noise_root$automatic_generation, FALSE)
  expect_identical(status$noise_root$automatic_recovery, FALSE)
})

test_that("DP noise-root file bootstrap enforces owner-only storage", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-root-")
  Sys.chmod(directory, mode = "0700")
  key_path <- file.path(directory, "noise-root.hex")
  writeLines(paste(sprintf("%02x", 0:31), collapse = ""), key_path,
             useBytes = TRUE)
  Sys.chmod(key_path, mode = "0600")

  withr::local_options(list(
    dsvert.identity_seed = gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(173L, 32L)))),
    dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = key_path,
    dsvert.dp.noise_key_epoch = 1,
    dsvert.dp.noise_key_previous_id = NULL))
  root <- .dsvert_dp_noise_key_file(
    key_path, .allow_test_path = TRUE)
  expect_identical(root$storage, "owner_only_file")
  expect_true(root$automatic_generation)
  expect_true(root$automatic_recovery)
  expect_false(root$external)
  expect_match(root$hmac(charToRaw("context")), "^[0-9a-f]{64}$")

  Sys.chmod(key_path, mode = "0644")
  expect_error(.dsvert_dp_noise_key_file(
    key_path, .allow_test_path = TRUE), "owner-only file")
  Sys.chmod(key_path, mode = "0600")
  link_path <- file.path(directory, "noise-root-link.hex")
  expect_true(file.symlink(key_path, link_path))
  expect_error(.dsvert_dp_noise_key_file(
    link_path, .allow_test_path = TRUE), "symbolic link")
})

test_that("sticky replay persists query allocation and byte-identical payload", {
  ledger <- file.path(
    tempdir(), paste0("dp-sticky-replay-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(
    patient_id = c("p1", "p2", "p3"), stringsAsFactors = FALSE)

  first <- dsvertDPCountDS("protected")
  # Every call opens and closes a fresh SQLite connection. This exercises the
  # restart/retry path rather than an in-memory response cache.
  replay <- dsvertDPCountDS("protected")
  expect_identical(
    serialize(first, NULL, version = 3L),
    serialize(replay, NULL, version = 3L))

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT query_hash, release_index, payload FROM dp_releases",
    "ORDER BY release_index"))
  expect_equal(nrow(rows), 1L)
  expect_match(rows$query_hash[[1L]], "^[0-9a-f]{64}$")
  expect_identical(rows$release_index[[1L]], 0L)
  expect_identical(
    jsonlite::fromJSON(rows$payload[[1L]], simplifyVector = TRUE),
    first[setdiff(names(first), c(
      "epsilon", "delta", "adjacency", "composition_partitions"))])
})

test_that("DP key changes fail closed unless an explicit epoch rotation continues composition", {
  ledger <- file.path(
    tempdir(), paste0("dp-key-rotation-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(ledger)
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  first <- dsvertDPCountDS("protected")
  expect_equal(first$epsilon, 0.25)

  withr::local_options(dsvert.dp.noise_key_provider =
    .dp_test_noise_provider(
      key = as.raw(33:64), key_id = "test-noise-key-v2"))
  expect_error(
    dsvertDPStatusDS(), "changed without an explicit privacy-epoch rotation")

  withr::local_options(list(
    dsvert.dp.noise_key_epoch = 2,
    dsvert.dp.noise_key_previous_id = "wrong-key"))
  expect_error(dsvertDPStatusDS(), "bind the previous key id")

  withr::local_options(
    dsvert.dp.noise_key_previous_id = "test-noise-key-v1")
  before <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  next_before <- DBI::dbGetQuery(
    before, "SELECT value FROM dp_meta WHERE key='next_index'")$value[[1L]]
  DBI::dbDisconnect(before)
  rotated <- dsvertDPStatusDS()
  expect_identical(rotated$noise_root$privacy_epoch, 2)
  expect_identical(rotated$noise_root$key_id, "test-noise-key-v2")
  expect_identical(rotated$allocation_slots_consumed, 1)
  expect_equal(rotated$local_epsilon_used, 0.25)

  second <- dsvertDPCountDS("protected")
  expect_equal(second$epsilon, 0.125)
  expect_equal(second$privacy_epoch, 2)
  expect_identical(second$noise_key_id, "test-noise-key-v2")
  final <- dsvertDPStatusDS()
  expect_identical(final$informative_releases, 2)
  expect_identical(final$allocation_slots_consumed, 2)
  expect_equal(final$local_epsilon_used, 0.375)
  expect_identical(next_before, "1")

  withr::local_options(list(
    dsvert.dp.noise_key_epoch = 1,
    dsvert.dp.noise_key_provider = .dp_test_noise_provider()))
  expect_error(dsvertDPStatusDS(), "advance exactly one privacy epoch")
})

test_that("file-root loss auto-rotates from authenticated ledger history", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dp-auto-key-rotation-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  key_path <- file.path(directory, "privacy", "noise_root")
  .dp_test_policy(
    ledger, dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = key_path)
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")
  protected <- data.frame(
    patient_id = c("p1", "p2", "p3"), stringsAsFactors = FALSE)
  first_policy <- .dsvert_dp_policy()
  first_release <- dsvertDPCountDS("protected")
  first_status <- dsvertDPStatusDS()
  expect_identical(first_policy$noise_root$epoch, 1)
  expect_equal(first_release$privacy_epoch, 1)
  expect_identical(first_status$noise_root$privacy_epoch, 1)
  context <- list(
    dataset = list(id = "dataset", version = "v1"),
    method = "unit_count", arguments = list(adjacency = "add_remove_patient"))
  first_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), first_policy, context$dataset,
    context$method, context$arguments)

  unlink(c(key_path, .dsvert_dp_noise_recovery_path(key_path)), force = TRUE)
  second_policy <- .dsvert_dp_policy()
  expect_identical(second_policy$noise_root$epoch, 2)
  expect_identical(
    second_policy$noise_root$previous_key_id,
    first_policy$noise_root$key_id)

  # Rotate once more before the local ledger observes epoch 2. The signed
  # journal bridges every consecutive transition, so history is not a gate.
  unlink(c(key_path, .dsvert_dp_noise_recovery_path(key_path)), force = TRUE)
  third_policy <- .dsvert_dp_policy()
  expect_identical(third_policy$noise_root$epoch, 3)
  third_status <- dsvertDPStatusDS()
  expect_identical(third_status$noise_root$privacy_epoch, 3)
  expect_identical(third_status$noise_root$rotation_count, 2)
  expect_identical(third_status$informative_releases, 1)
  expect_equal(third_status$local_epsilon_used, 0.25)

  # A status/readiness call may persist the new epoch without sampling under
  # it. Losing the root in that window must still rotate automatically.
  unlink(c(key_path, .dsvert_dp_noise_recovery_path(key_path)), force = TRUE)
  fourth_policy <- .dsvert_dp_policy()
  expect_identical(fourth_policy$noise_root$epoch, 4)
  fourth_status <- dsvertDPStatusDS()
  expect_identical(fourth_status$noise_root$privacy_epoch, 4)
  expect_identical(fourth_status$noise_root$rotation_count, 3)
  third_hash <- .dsvert_dp_query_hash(
    .dsvert_dp_secret(), fourth_policy, context$dataset,
    context$method, context$arguments)
  expect_false(identical(first_hash, third_hash))
  expect_identical(
    third_hash,
    .dsvert_dp_query_hash(
      .dsvert_dp_secret(), .dsvert_dp_policy(), context$dataset,
      context$method, context$arguments))
  third_release <- dsvertDPCountDS("protected")
  third_replay <- dsvertDPCountDS("protected")
  expect_equal(third_release$privacy_epoch, 4)
  expect_identical(
    serialize(third_release, NULL, version = 3L),
    serialize(third_replay, NULL, version = 3L))
  expect_false(identical(
    first_release$noise_key_id, third_release$noise_key_id))

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  metadata <- DBI::dbGetQuery(connection, paste(
    "SELECT key, value FROM dp_meta WHERE key IN",
    "('noise_key_epoch', 'noise_key_id', 'cumulative_epsilon',",
    "'cumulative_delta')"))
  metadata <- setNames(metadata$value, metadata$key)
  expect_identical(metadata[["noise_key_epoch"]], "4")
  expect_identical(metadata[["noise_key_id"]], fourth_policy$noise_root$key_id)
  expect_equal(as.numeric(metadata[["cumulative_epsilon"]]), 0.375)
  expect_identical(metadata[["cumulative_delta"]], "0")
})

test_that("inactive bootstrap rotates from an authenticated used local ledger", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dp-inactive-ledger-rotation-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  key_path <- file.path(directory, "privacy", "noise_root")
  identity_path <- file.path(directory, "identity.seed")
  .dp_test_policy(
    ledger, dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = key_path,
    dsvert.state_dir = directory,
    dsvert.identity_seed_path = identity_path)
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")
  .dsvert_init_identity_seed(identity_path, .allow_test_path = TRUE)

  protected <- data.frame(
    patient_id = c("p1", "p2", "p3"), stringsAsFactors = FALSE)
  first <- dsvertDPCountDS("protected")
  first_status <- dsvertDPStatusDS()
  expect_identical(first_status$informative_releases, 1)
  expect_equal(first_status$local_epsilon_used, 0.25)

  withr::local_options(dsvert.dp.enabled = FALSE)
  unlink(c(key_path, .dsvert_dp_noise_recovery_path(key_path)), force = TRUE)
  state <- .dsvert_noise_bootstrap_state_from_options()
  expect_true(is.function(state$history_provider))

  outcomes <- parallel::mclapply(
    seq_len(4L), function(unused) {
      tryCatch({
        .dsvert_dp_ensure_noise_key_file(
          key_path, .allow_test_path = TRUE, .bootstrap_state = state)
        key <- .dsvert_dp_noise_validate_file(key_path)
        list(key_id = paste0("file_", digest::digest(
          key, algo = "sha256", serialize = FALSE)))
      }, error = function(error) list(error = conditionMessage(error)))
    }, mc.cores = 4L, mc.preschedule = FALSE)
  errors <- unname(vapply(
    Filter(function(value) !is.null(value$error), outcomes),
    `[[`, character(1L), "error"))
  expect_identical(errors, character())
  identifiers <- vapply(outcomes, function(value) {
    if (is.null(value$key_id)) "" else value$key_id
  }, character(1L))
  expect_length(unique(identifiers), 1L)
  rotated <- .dsvert_dp_noise_key_file(
    key_path, .allow_test_path = TRUE, .bootstrap_state = state)
  expect_identical(rotated$epoch, 2)
  expect_identical(rotated$previous_key_id, first$noise_key_id)
  expect_true(rotated$automatic_rotation)
  transition <- utils::tail(rotated$transition_chain(), 1L)[[1L]]
  expect_identical(transition$composition_audit$release_count, "1")
  expect_equal(as.numeric(
    transition$composition_audit$cumulative_epsilon), 0.25)
  expect_identical(transition$composition_audit$cumulative_delta, "0")

  withr::local_options(dsvert.dp.enabled = TRUE)
  second <- dsvertDPCountDS("protected")
  replay <- dsvertDPCountDS("protected")
  final_status <- dsvertDPStatusDS()
  expect_equal(second$privacy_epoch, 2)
  expect_false(identical(second$noise_key_id, first$noise_key_id))
  expect_identical(
    serialize(second, NULL, version = 3L),
    serialize(replay, NULL, version = 3L))
  expect_identical(final_status$informative_releases, 2)
  expect_equal(final_status$local_epsilon_used, 0.375)
})

test_that("inactive bootstrap rebinds a valid empty local ledger", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dp-inactive-empty-ledger-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  key_path <- file.path(directory, "privacy", "noise_root")
  identity_path <- file.path(directory, "identity.seed")
  .dp_test_policy(
    ledger, dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = key_path,
    dsvert.state_dir = directory,
    dsvert.identity_seed_path = identity_path)
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")
  .dsvert_init_identity_seed(identity_path, .allow_test_path = TRUE)

  empty_status <- dsvertDPStatusDS()
  expect_identical(empty_status$informative_releases, 0)
  old_key_id <- empty_status$noise_root$key_id
  withr::local_options(dsvert.dp.enabled = FALSE)
  unlink(c(
    key_path, .dsvert_dp_noise_recovery_path(key_path),
    .dsvert_dp_noise_receipt_path(key_path),
    .dsvert_dp_noise_epoch_path(key_path)), force = TRUE)
  state <- .dsvert_noise_bootstrap_state_from_options()
  expect_true(is.function(state$history_provider))
  expect_identical(.dsvert_dp_ensure_noise_key_file(
    key_path, random_bytes = function(n) as.raw(rep(219L, n)),
    .allow_test_path = TRUE, .bootstrap_state = state),
    normalizePath(key_path, winslash = "/"))
  replacement <- .dsvert_dp_noise_key_file(
    key_path, .allow_test_path = TRUE, .bootstrap_state = state)
  expect_identical(replacement$epoch, 1)
  expect_false(identical(replacement$key_id, old_key_id))

  withr::local_options(dsvert.dp.enabled = TRUE)
  rebound <- dsvertDPStatusDS()
  expect_identical(rebound$informative_releases, 0)
  expect_equal(rebound$local_epsilon_used, 0)
  expect_identical(rebound$noise_root$key_id, replacement$key_id)
})

test_that("inactive bootstrap rejects authenticated-ledger MAC and meta tamper", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dp-inactive-ledger-tamper-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  key_path <- file.path(directory, "privacy", "noise_root")
  identity_path <- file.path(directory, "identity.seed")
  .dp_test_policy(
    ledger, dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = key_path,
    dsvert.state_dir = directory,
    dsvert.identity_seed_path = identity_path)
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")
  .dsvert_init_identity_seed(identity_path, .allow_test_path = TRUE)
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  dsvertDPCountDS("protected")
  withr::local_options(dsvert.dp.enabled = FALSE)
  unlink(c(key_path, .dsvert_dp_noise_recovery_path(key_path)), force = TRUE)
  state <- .dsvert_noise_bootstrap_state_from_options()

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  original_mac <- DBI::dbGetQuery(
    connection, "SELECT row_mac FROM dp_releases WHERE release_index = 0")$
    row_mac[[1L]]
  DBI::dbExecute(
    connection,
    "UPDATE dp_releases SET row_mac = ? WHERE release_index = 0",
    params = list(strrep("0", 64L)))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    key_path, random_bytes = function(n) stop("must reject MAC first"),
    .allow_test_path = TRUE, .bootstrap_state = state),
    "could not be authenticated")
  expect_false(file.exists(key_path))

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(
    connection,
    "UPDATE dp_releases SET row_mac = ? WHERE release_index = 0",
    params = list(original_mac))
  DBI::dbExecute(connection, paste(
    "UPDATE dp_meta SET value = '999'",
    "WHERE key = 'cumulative_epsilon'"))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    key_path, random_bytes = function(n) stop("must reject meta first"),
    .allow_test_path = TRUE, .bootstrap_state = state),
    "could not be authenticated")
  expect_false(file.exists(key_path))
})

test_that("inactive bootstrap combines only coherent ledger histories", {
  ledger <- file.path(withr::local_tempdir(
    pattern = "dp-inactive-combined-history-"), "ledger.sqlite")
  key_id <- paste0("file_", strrep("a", 64L))
  joint_key_id <- key_id
  component <- function(source, count, epsilon, chain_head) list(
    status = "used", source = source, seal = list(source = source),
    privacy_epoch = 2, noise_key_id = if (identical(source, "joint")) {
      joint_key_id
    } else {
      key_id
    },
    noise_key_provider_id = "owner_only_file_v2",
    count = count, epsilon = epsilon, delta = 0,
    chain_head = chain_head)
  evaluate <- function() testthat::with_mocked_bindings(
    .dsvert_dp_inactive_noise_history(ledger),
    .dsvert_dp_history_file_present = function(path, what) {
      !startsWith(what, "legacy") && !grepl("vector", what, fixed = TRUE)
    },
    .dsvert_dp_inactive_local_history = function(path, secret) {
      component("local", 2, 0.5, strrep("1", 64L))
    },
    .dsvert_dp_inactive_joint_history = function(path, secret) {
      component("joint", 3, 1, strrep("2", 64L))
    },
    .dsvert_dp_secret = function() as.raw(seq_len(32L)),
    .package = "dsVert")

  history <- evaluate()
  expect_identical(history$privacy_epoch, 2)
  expect_identical(history$noise_key_id, key_id)
  expect_identical(history$composition_audit$source, "local+joint")
  expect_identical(history$composition_audit$release_count, "5")
  expect_equal(as.numeric(
    history$composition_audit$cumulative_epsilon), 1.5)

  joint_key_id <- paste0("file_", strrep("b", 64L))
  expect_error(evaluate(), "disagree on the current noise-root epoch")
})

test_that("a failed noise-root HMAC cannot reserve or expose provider details", {
  ledger <- file.path(
    tempdir(), paste0("dp-noise-provider-fail-", Sys.getpid(), ".sqlite"))
  provider <- function(action, message_base64 = NULL) {
    if (identical(action, "capabilities")) {
      return(list(
        schema_version = 1L, provider_id = "failing-provider",
        key_id = "failing-key", external = TRUE, hmac_sha256 = TRUE))
    }
    stop("INTERNAL_PROVIDER_SECRET_123", call. = FALSE)
  }
  .dp_test_policy(ledger, dsvert.dp.noise_key_provider = provider)
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  error <- tryCatch(dsvertDPCountDS("protected"), error = identity)
  expect_s3_class(error, "error")
  expect_match(conditionMessage(error), "provider failed during 'hmac_sha256'")
  expect_false(grepl(
    "INTERNAL_PROVIDER_SECRET_123", conditionMessage(error), fixed = TRUE))
  printed_error <- paste(capture.output(print(error)), collapse = "\n")
  expect_false(grepl(
    "INTERNAL_PROVIDER_SECRET_123", printed_error, fixed = TRUE))

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM dp_releases")$n[[1L]], 0)
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT value FROM dp_meta WHERE key='next_index'")$value[[1L]],
    "0")
})

test_that("adjacency aliases canonicalize and capacity policy fails closed", {
  ledger <- file.path(
    tempdir(), paste0("dp-adjacency-policy-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(ledger, dsvert.dp.adjacency = "patient_add_remove")
  expect_identical(.dsvert_dp_policy()$adjacency, "add_remove_patient")

  replacement <- withr::with_options(list(
    dsvert.dp.adjacency = "replace_one_fixed_cohort",
    dsvert.dp.unit_capacity = 2L,
    dsvert.dp.fixed_cohort_size = 2L), .dsvert_dp_policy())
  expect_identical(replacement$adjacency, "replace_one_fixed_cohort")
  expect_identical(replacement$fixed_cohort_size, 2L)
  defaulted_aggregation <- withr::with_options(
    list(dsvert.dp.contingency_unit_aggregation_policy = NULL),
    .dsvert_dp_policy())
  expect_identical(
    defaulted_aggregation$contingency_unit_aggregation_policy,
    "consistent_cell_else_exclude_v1")

  malformed <- list(
    list(dsvert.dp.adjacency = "row_add_remove"),
    list(dsvert.dp.unit_capacity = 0L),
    list(dsvert.dp.max_records_per_unit = 0L),
    list(dsvert.dp.overflow_policy = "truncate"),
    list(dsvert.dp.contingency_unit_aggregation_policy =
           "first_valid_snapshot_row_v1"),
    list(dsvert.dp.fixed_cohort_size = 2L),
    list(
      dsvert.dp.adjacency = "replace_one_fixed_cohort",
      dsvert.dp.unit_capacity = 2L,
      dsvert.dp.fixed_cohort_size = 1L))
  for (configuration in malformed) {
    expect_error(withr::with_options(configuration, .dsvert_dp_policy()))
  }
})

test_that("every admission rejection is generic and consumes no allocation", {
  ledger <- file.path(
    tempdir(), paste0("dp-admission-no-charge-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(
    ledger,
    dsvert.dp.unit_capacity = 2L,
    dsvert.dp.max_records_per_unit = 1L,
    dsvert.dp.categorical_levels = list(
      exposed = c("no", "yes"), outcome = c("no", "yes"),
      status = c("0", "A")),
    dsvert.dp.numeric_bounds = list(age = c(0, 120), time = c(0, 4)),
    dsvert.dp.describe_specs = list(primary = list(
      version = "v1", dataset = "protected", variables = "age",
      histogram_grids = list(age = c(30, 60, 90, 120)),
      allocation = c(
        count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2))),
    dsvert.dp.survival_specs = list(primary = list(
      version = "v1", dataset = "protected", time = "time",
      event = "status", censor = "0", time_grid = 1:4, entry = NULL)))
  protected <- data.frame(
    patient_id = c("p1", "p2", "p3"),
    exposed = c("yes", "no", "yes"),
    outcome = c("yes", "no", "no"),
    age = c(20, 40, 60), time = c(1, 2, 3),
    status = c("A", "0", "A"), stringsAsFactors = FALSE)
  before <- dsvertDPStatusDS()
  calls <- list(
    function() dsvertDPCountDS("protected"),
    function() dsvertDPContingencyDS(
      "protected", "exposed", "outcome"),
    function() dsvertDPMeanVarDS("protected", "age"),
    function() dsvertDPDescribeDS("protected", "primary"),
    function() dsvertDPSurvivalDS("protected", "primary"))
  messages <- vapply(calls, function(call) {
    conditionMessage(tryCatch(call(), error = identity))
  }, character(1L))
  expect_identical(
    unique(messages),
    "The protected snapshot does not satisfy its custodian-owned DP admission contract")
  after <- dsvertDPStatusDS()
  expect_identical(after$allocation_slots_consumed,
                   before$allocation_slots_consumed)
  expect_identical(after$informative_releases, before$informative_releases)
  expect_identical(after$local_epsilon_used, before$local_epsilon_used)

  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM dp_releases")$n[[1L]], 0)
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT value FROM dp_meta WHERE key='next_index'")$value[[1L]],
    "0")
})

test_that("fixed-cohort count is public, exact, and ledger-free", {
  ledger <- file.path(
    tempdir(), paste0("dp-fixed-count-", Sys.getpid(), ".sqlite"))
  unlink(c(ledger, paste0(ledger, "-wal"), paste0(ledger, "-shm"),
           paste0(ledger, ".lock")), force = TRUE)
  .dp_test_policy(
    ledger,
    dsvert.dp.adjacency = "replace_one_fixed_cohort",
    dsvert.dp.unit_capacity = 2L,
    dsvert.dp.fixed_cohort_size = 2L,
    dsvert.dp.max_records_per_unit = 1L)
  protected <- data.frame(
    patient_id = c("p1", "p2"), stringsAsFactors = FALSE)
  before <- dsvertDPStatusDS()
  release <- dsvertPublicFixedCohortCountDS("protected")
  replay <- dsvertPublicFixedCohortCountDS("protected")
  after <- dsvertDPStatusDS()
  expect_identical(release, replay)
  expect_identical(release$value, 2)
  expect_identical(release$mechanism, "public_fixed_cohort_size_v1")
  expect_identical(release$data_dependency,
                   "none_public_fixed_cohort_policy")
  expect_identical(release$sensitivity, 0)
  expect_identical(release$epsilon, 0)
  expect_identical(release$peer_count, 2L)
  expect_false("composition_partitions" %in% names(release))
  expect_identical(after$allocation_slots_consumed,
                   before$allocation_slots_consumed)
  expect_identical(after$informative_releases, before$informative_releases)
  expect_identical(after$local_epsilon_used, before$local_epsilon_used)
})
