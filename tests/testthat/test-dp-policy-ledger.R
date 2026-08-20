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
    api_version = "1.2.0",
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
          "signed-decode-fixed-public-clamp-no-wrap-v3")),
      joint_dp_frequency_backend_selection = list(
        available = TRUE,
        capability_id = "joint_dp_frequency_backend_selection_v1",
        protocol_version =
          "dsvert-joint-dp-frequency-backend-selection-v1",
        commands = "joint-dp-frequency-backend-select-v1",
        operations =
          "public-data-free-certified-frequency-backend-selection-v1")))
}

.dp_test_pk <- function(offset) {
  jsonlite::base64_enc(as.raw((seq_len(32L) + offset) %% 256L))
}

.dp_test_align <- function(data, id_col = "patient_id") {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(seq_len(32L))))
  .psi_attach_alignment_manifest(data, id_col, token)
}


.dp_test_policy <- function(ledger_path, ...,
                            .local_envir = parent.frame(),
                            .production_contract = FALSE) {
  overrides <- list(...)
  values <- utils::modifyList(list(
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.domain = "test-study-v1",
    dsvert.dp.cohort_id = "test-cohort-v1",
    dsvert.dp.ledger_path = ledger_path,
    dsvert.dp.anchor_provider = NULL,
    dsvert.dp.noise_key_provider = .dp_test_noise_provider(),
    dsvert.dp.noise_key_path = NULL,
    dsvert.dp.noise_key_epoch = 1,
    dsvert.dp.noise_key_previous_id = NULL,
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
      .test_only_allow_nonprivate_ledger = TRUE)
  }
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() do.call(policy_builder, test_flags),
    .package = "dsVert", .env = .local_envir)
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
                                   anchor_provider, ...) {
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
    dsvert.dp.anchor_provider = anchor_provider,
    dsvert.dp.datasets = descriptors,
    ...,
    .local_envir = parent.frame(),
    .production_contract = TRUE)
}


test_that("legacy DP policy lazily initializes its noise root", {
  ledger <- file.path(
    tempdir(), paste0("dp-lazy-noise-root-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(ledger)
  calls <- 0L
  expected_root <- list(
    protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
    provider_id = "test-provider", key_id = "test-lazy-root",
    epoch = 1, external = TRUE, storage = "hsm_kms_provider",
    hmac = function(message) strrep("a", 64L))

  policy <- testthat::with_mocked_bindings(
    .dsvert_dp_policy(),
    .dsvert_dp_noise_root = function(.bootstrap_state = NULL) {
      calls <<- calls + 1L
      expect_true(is.list(.bootstrap_state))
      expect_identical(
        basename(.bootstrap_state$ledger_path), basename(ledger))
      expected_root
    },
    .package = "dsVert")

  expect_identical(calls, 1L)
  expect_identical(policy$noise_root, expected_root)
})


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
          dsvert.dp.datasets = snapshots)
  expect_identical(.dsvert_dp_policy()$adjacency, "add_remove_patient")
  expect_identical(.dsvert_dp_policy()$policy_contract,
                   "single_disclosure_safe_capsule_policy_v2")
  expect_identical(.dsvert_dp_policy()$schema_version, 9L)
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

  derived <- .dsvert_dp_policy()
  expect_identical(derived$peer_count, 2L)
  expect_identical(derived$designated_noise_peers,
                   c("site_a", "site_b"))
  options(dsvert.dp.total_epsilon = 1,
          dsvert.dp.total_delta = 0)
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
  options(dsvert.dp.total_epsilon = 9,
          dsvert.dp.total_delta = 0)
  expect_error(.dsvert_dp_policy(), "<= 8")
  options(dsvert.dp.total_epsilon = 8)
  expect_equal(.dsvert_dp_policy()$global_total_epsilon, 8)
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
      alignment_manifest_version = 4L)))
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
    expect_identical(strict$datasets$protected$alignment_manifest_version, 4L)
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
})

test_that("ledger path prefixes remain owner-only", {
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
  expect_no_error(.dsvert_dp_dataset_binding(
    private_policy, "protected", protected, .dsvert_dp_secret()))

  bad_ledger <- file.path(
    tempdir(), paste0("dp-snapshot-bad-", Sys.getpid(), ".sqlite"))
  .dp_test_policy(
    bad_ledger,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 0,
    dsvert.dp.datasets = list(protected = list(
      id = "snapshot-study", version = "v1",
      snapshot_sha256 = paste(rep("0", 64L), collapse = ""),
      alignment_manifest_hash = alignment$hash,
      alignment_manifest_version = alignment$version)),
    .production_contract = TRUE)
  expect_error(.dsvert_dp_dataset_binding(
    .dsvert_dp_policy(), "protected", protected, .dsvert_dp_secret()),
    "custodian-approved")

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

test_that("snapshot canonicalization removes only validated Opal metadata", {
  ordinary <- data.frame(
    patient_id = c("p1", "p2"), value = c(1, 2),
    stringsAsFactors = FALSE)
  decorate <- function(data, optional = FALSE) {
    for (name in names(data)) {
      column <- data[[name]]
      attr(column, "opal.value_type") <- if (is.character(column)) {
        "text"
      } else {
        "decimal"
      }
      attr(column, "opal.entity_type") <- "Participant"
      attr(column, "opal.repeatable") <- 0
      attr(column, "opal.index") <- 0
      attr(column, "opal.nature") <- if (is.character(column)) {
        "CATEGORICAL"
      } else {
        "CONTINUOUS"
      }
      if (isTRUE(optional)) {
        attr(column, "opal.unit") <- "unitless"
        attr(column, "opal.referenced_entity_type") <- "Participant"
        attr(column, "opal.mime_type") <- "text/plain"
        attr(column, "opal.occurrence_group") <- "primary"
      }
      data[[name]] <- column
    }
    data
  }

  decorated <- decorate(ordinary)
  expect_identical(
    .dsvert_dp_snapshot_digest(decorated),
    .dsvert_dp_snapshot_digest(ordinary))
  expect_identical(
    .dsvert_dp_snapshot_digest(decorate(ordinary, optional = TRUE)),
    .dsvert_dp_snapshot_digest(ordinary))
  canonical_attributes <- names(attributes(
    .dsvert_dp_snapshot_columns(decorated)$value))
  if (is.null(canonical_attributes)) canonical_attributes <- character()
  expect_false(any(startsWith(canonical_attributes, "opal.")))

  unknown <- decorated
  attr(unknown$value, "opal.executable") <- new.env(parent = emptyenv())
  expect_error(
    .dsvert_dp_snapshot_digest(unknown), "invalid Opal metadata")

  partial <- decorated
  attr(partial$value, "opal.index") <- NULL
  expect_error(
    .dsvert_dp_snapshot_digest(partial), "incomplete Opal metadata")

  invalid <- decorated
  attr(invalid$value, "opal.repeatable") <- 2
  expect_error(
    .dsvert_dp_snapshot_digest(invalid), "invalid Opal metadata")

  attributed <- decorated
  value <- attr(attributed$value, "opal.entity_type", exact = TRUE)
  attr(value, "payload") <- new.env(parent = emptyenv())
  attr(attributed$value, "opal.entity_type") <- value
  expect_error(
    .dsvert_dp_snapshot_digest(attributed), "invalid Opal metadata")

  dispatched <- FALSE
  length.dsvert_opal_metadata_trap <- function(x) {
    dispatched <<- TRUE
    stop("metadata method executed")
  }
  on.exit(rm(length.dsvert_opal_metadata_trap), add = TRUE)
  class(value) <- "dsvert_opal_metadata_trap"
  trapped <- decorated
  attr(trapped$value, "opal.entity_type") <- value
  expect_error(
    .dsvert_dp_snapshot_digest(trapped), "invalid Opal metadata")
  expect_false(dispatched)
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


test_that("DP noise roots are provisioned and domain separated", {
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
  secret_hex <- paste(format(secret_key), collapse = "")
  secret_b64 <- jsonlite::base64_enc(secret_key)
  expect_false(identical(seed, secret_hex))
  expect_false(identical(seed, secret_b64))
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
