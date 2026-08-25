.capsule_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.capsule_test_snapshot <- function(version = "v1") {
  list(
    logical_snapshot_id = "aligned-biomedical-cohort",
    version = version, alignment_protocol_version = 1L)
}

.capsule_test_specs <- function() {
  list(
    describe = list(primary = list(
      version = "v1", dataset = "protected",
      variables = c("age", "marker"),
      histogram_grids = list(
        age = c(50, 100), marker = c(5, 10)),
      allocation = c(
        count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2))),
    survival = list(primary = list(
      version = "v1", dataset = "protected", time = "time",
      event = "status", censor = "censor", time_grid = 1:5,
      entry = NULL)),
    gaussian = list())
}

.capsule_test_noise_selector <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective, gaussian_winner = TRUE) {
  list(
    selector = .DSVERT_DP_NOISE_SELECTOR,
    objective = objective, coordinate_count = as.integer(coordinate_count),
    winner = if (isTRUE(gaussian_winner)) "gaussian" else "laplace",
    laplace = list(available = TRUE, simultaneous_95_abs = 100),
    gaussian = list(
      available = TRUE,
      simultaneous_95_abs = if (isTRUE(gaussian_winner)) 50 else 100))
}

.capsule_test_fixture <- function(
    peer = "peer_a", delta = 1e-6, vertical = FALSE) {
  pins <- c(
    peer_a = .capsule_test_b64url(as.raw(seq_len(32L))),
    peer_b = .capsule_test_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  all_numeric <- list(
    age = c(0, 100), marker = c(0, 10), time = c(0, 5))
  all_categorical <- list(
    sex = c("female", "male"),
    status = c("censor", "event_a", "event_b"))
  policy <- list(
    domain = "biomedical-study", cohort_id = "cohort-v1",
    peer_name = peer, peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    global_total_epsilon = 1, global_total_delta = delta,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 100L, fixed_cohort_size = NULL,
    max_records_per_unit = 4L, overflow_policy = "reject_snapshot",
    numeric_grid_bits = 8L,
    numeric_bounds = if (identical(peer, "peer_a")) {
      all_numeric
    } else if (isTRUE(vertical)) {
      list(remote_marker = c(-1, 1))
    } else {
      list()
    },
    categorical_levels = if (identical(peer, "peer_a")) {
      all_categorical
    } else {
      list()
    },
    datasets = stats::setNames(list(list(
      id = if (identical(peer, "peer_a")) {
        "biomedical-cohort"
      } else {
        "remote-biomedical-cohort"
      }, version = "v1",
      snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L)),
      if (identical(peer, "peer_a")) "protected" else "remote"),
    noise_root = list(epoch = 1, key_id = "capsule-test-root"),
    ledger_path = tempfile("capsule-workload-ledger-"))
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = .capsule_test_snapshot(),
    peer_pinset_sha256 = pin_hash,
    datasets = list(protected = list(
      dataset_id = "biomedical-cohort", dataset_version = "v1",
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = list(peer_a = "patient_id"),
      columns = list(
        age = list(
          kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 100),
        marker = list(
          kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 10),
        time = list(
          kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 5),
        sex = list(
          kind = "categorical", owner_peer = "peer_a",
          levels = c("female", "male")),
        status = list(
          kind = "categorical", owner_peer = "peer_a",
          levels = c("censor", "event_a", "event_b")))),
      remote = list(
        dataset_id = "remote-biomedical-cohort", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_b = "patient_id"),
        columns = list(remote_marker = list(
          kind = "numeric", owner_peer = "peer_b",
          lower = -1, upper = 1)))),
    signatures = list(peer_a = strrep("A", 86L),
                      peer_b = strrep("B", 86L)))
  if (!isTRUE(vertical)) {
    schema$datasets$remote <- NULL
    if (!identical(peer, "peer_a")) {
      policy$datasets <- list()
    }
  }
  list(policy = policy, schema = schema, snapshot = .capsule_test_snapshot(),
       specs = .capsule_test_specs())
}

.capsule_test_k3_fixture <- function(peer, k = 3L) {
  if (!peer %in% c("peer_a", "peer_c") || !k %in% 3:5) {
    stop("invalid K>=3 fixture")
  }
  fixture <- .capsule_test_fixture(
    if (identical(peer, "peer_c")) "peer_b" else "peer_a",
    vertical = TRUE)
  extra_indices <- seq.int(3L, k)
  extra_peers <- paste0("peer_", letters[extra_indices])
  extra_pins <- stats::setNames(vapply(extra_indices, function(index) {
    .capsule_test_b64url(as.raw(32L * (index - 1L) + seq_len(32L)))
  }, character(1L)), extra_peers)
  pins <- c(fixture$policy$peer_pinset, extra_pins)
  pins <- pins[order(names(pins), method = "radix")]
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  fixture$policy$peer_name <- peer
  fixture$policy$peer_pinset <- pins
  fixture$policy$peer_pinset_sha256 <- pin_hash
  fixture$policy$peer_count <- as.integer(k)
  fixture$policy$designated_noise_peers <- c("peer_a", "peer_b")
  fixture$schema$peer_pinset_sha256 <- pin_hash
  fixture$schema$datasets$remote$patient_keys <- list(peer_c = "patient_id")
  fixture$schema$datasets$remote$columns$remote_marker$owner_peer <- "peer_c"
  for (index in extra_indices) {
    peer_name <- paste0("peer_", letters[[index]])
    fixture$schema$signatures[[peer_name]] <- strrep(LETTERS[[index]], 86L)
  }
  fixture
}

.capsule_test_build <- function(
    fixture, ..., .noise_selector = .capsule_test_noise_selector,
    .gaussian_planner = function(...) {
      stop("test exact-Gaussian backend unavailable", call. = FALSE)
    }) {
  .dsvert_dp_capsule_workload_manifest(
    fixture$policy, fixture$snapshot, fixture$schema,
    describe_specs = fixture$specs$describe,
    survival_specs = fixture$specs$survival,
    gaussian_specs = fixture$specs$gaussian,
    .signature_verifier = function(...) TRUE,
    .noise_selector = .noise_selector,
    .gaussian_planner = .gaussian_planner, ...)
}

.capsule_test_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(value, .capsule_test_names),
                         use.names = FALSE))
}

test_that("a local categorical scope materializes a true projected vector", {
  fixture <- .capsule_test_fixture()
  build <- function(pair, schema = fixture$schema) {
    .dsvert_dp_capsule_workload_manifest(
      fixture$policy, fixture$snapshot, schema,
      describe_specs = list(), survival_specs = list(),
      gaussian_specs = list(), vertical_cross_specs = list(),
      .signature_verifier = function(...) TRUE,
      .noise_selector = .capsule_test_noise_selector,
      .gaussian_planner = function(...) {
        stop("test exact-Gaussian backend unavailable", call. = FALSE)
      },
      .primitive_scope = list(
        mode = "catalog_v1", numeric_moments = character(),
        categorical_marginals = character(),
        categorical_pairs = list(pair), correlations = list()))
  }
  projected <- build(c("status", "sex"))
  families <- projected$workload$families
  expect_identical(projected$workload$coordinate_count, 12)
  expect_length(families$numeric_moments$artifacts, 0L)
  expect_length(families$numeric_pair_moments$artifacts, 0L)
  expect_length(families$gaussian_models$artifacts, 0L)
  expect_length(families$fixed_numeric_histograms$artifacts, 0L)
  expect_length(families$describe_artifacts, 0L)
  expect_length(families$survival_artifacts, 0L)
  expect_length(families$categorical_marginals$artifacts, 2L)
  expect_length(families$categorical_pairs$sets, 1L)
  expect_length(families$categorical_pairs$cross_artifacts, 0L)
  expect_identical(
    projected$workload$primitive_scope$selection$explicit_catalog$
      categorical_pairs,
    list(c("sex", "status")))
  expect_identical(
    projected$workload$vertical_crosses$included_coordinate_count, 0)

  permuted <- fixture$schema
  permuted$datasets$protected$columns$sex$levels <- c("male", "female")
  permuted$datasets$protected$columns$status$levels <-
    c("event_b", "censor", "event_a")
  equivalent <- build(c("sex", "status"), permuted)
  expect_identical(equivalent$capsule_identity$capsule_id,
                   projected$capsule_identity$capsule_id)
})

test_that("biomedical capsule manifest covers every supported family", {
  fixture <- .capsule_test_fixture()
  manifest <- testthat::with_mocked_bindings(
    .capsule_test_build(fixture),
    .dsvert_dp_resolve_snapshot = function(...) {
      stop("protected snapshot was resolved", call. = FALSE)
    },
    .dsvert_dp_admit_units = function(...) {
      stop("protected units were inspected", call. = FALSE)
    },
    .package = "dsVert")
  workload <- manifest$workload

  expect_identical(
    manifest$execution_state,
    "registered_lifecycle_available_requires_runtime_preflight")
  expect_identical(workload$execution_state, manifest$execution_state)
  expect_true(workload$declared_workload_fully_materialized)
  expect_false(workload$package_family_coverage_complete)
  expect_identical(
    workload$registered_release_lifecycle,
    .dsvert_dp_capsule_registered_release_lifecycle())
  expect_true(workload$registered_release_lifecycle$package_integration_verified)
  expect_false(workload$registered_release_lifecycle$raw_intermediate_releasable)
  expect_identical(
    workload$registered_release_lifecycle$live_connector_execution,
    "runtime_preflight_required")
  expect_invisible(
    .dsvert_dp_capsule_workload_require_materializable(manifest))
  expect_identical(workload$coordinate_count, 61)
  expect_identical(
    workload$capsule_mechanism$coordinate_count,
    workload$coordinate_count)
  expect_identical(workload$capsule_mechanism$mechanism,
                   "discrete-laplace")
  expect_identical(workload$capsule_mechanism$sensitivity_norm, "l1")
  expect_identical(
    workload$mechanism_selection$utility_winner, "laplace")
  expect_false(workload$mechanism_selection$gaussian_backend_available)
  expect_identical(
    workload$mechanism_selection$deployment_rule,
    "formal_backend_or_explicit_laplace_fallback")
  expect_identical(
    length(workload$families$numeric_moments$artifacts), 3L)
  expect_identical(
    length(workload$families$numeric_pair_moments$artifacts), 3L)
  expect_equal(
    workload$families$numeric_pair_moments$coordinate_count, 18L)
  expect_identical(
    workload$families$numeric_pair_moments$natural_l1_sensitivity, 18)
  expect_named(workload$families$correlation_artifacts, "protected::peer_a")
  expect_identical(
    length(workload$families$categorical_marginals$artifacts), 2L)
  expect_identical(
    length(workload$families$categorical_pairs$sets), 1L)
  expect_identical(
    length(workload$families$fixed_numeric_histograms$artifacts), 2L)
  expect_identical(
    workload$families$fixed_numeric_histograms$coordinate_count, 6)
  expect_named(workload$families$describe_artifacts, "primary")
  expect_named(workload$families$survival_artifacts, "primary")
  expect_match(manifest$capsule_identity$capsule_id, "^[0-9a-f]{64}$")
  expect_identical(
    workload$capsule_mechanism,
    manifest$capsule_identity$contract$workload$capsule_mechanism)

  forbidden <- c(
    "method", "methods", "argument", "arguments", "operation",
    "operation_id", "query_id", "capsule_id", "capsule_release_id")
  identity_components <- list(
    admission = manifest$admission, bounds = manifest$bounds,
    workload = manifest$workload)
  expect_length(intersect(
    tolower(.capsule_test_names(identity_components)), forbidden), 0L)
  expect_false(any(c(
    "data", "rows", "observations", "snapshot_sha256",
    "alignment_manifest_hash") %in%
      tolower(.capsule_test_names(manifest))))
  expect_false(grepl(
    "PROTECTED_SENTINEL_7f46", .dsvert_dp_canonical_json(manifest),
    fixed = TRUE))

  reuse <- workload$reuse_and_composition
  expect_identical(
    reuse$same_capsule, "unlimited_sticky_replay_and_postprocessing")
  expect_identical(reuse$reuse_count_limit, "none")
  expect_false(reuse$prior_reuse_can_deny)
  expect_false(reuse$prior_reuse_changes_accuracy)
  expect_identical(
    reuse$new_capsule_composition,
    "exact_basic_composition_under_authenticated_lifetime_bound")
  expect_true(reuse$historical_composition_can_deny)
  expect_false(reuse$request_limit)
  expect_true(reuse$privacy_budget_gate)
  expect_identical(reuse$lifetime_max_distinct_capsules, 8)
  expect_identical(reuse$lifetime_epsilon_upper_bound, "8")
  expect_identical(
    reuse$lifetime_delta_upper_bound, "7.9999999999999996e-6")
  expect_true(reuse$global_lifetime_dp_claim)
  expect_identical(
    reuse$claim_scope,
    paste0("bounded_dp_indistinguishability_not_probability_zero_",
           "reconstruction"))

  tampered <- manifest
  tampered$workload$registered_release_lifecycle$sampler_integration <- FALSE
  expect_error(
    .dsvert_dp_capsule_workload_require_materializable(tampered),
    "registered release lifecycle")
  lifecycle <- workload$registered_release_lifecycle
  for (name in names(lifecycle)) {
    tampered <- manifest
    value <- lifecycle[[name]]
    tampered$workload$registered_release_lifecycle[[name]] <-
      if (is.logical(value)) !value else paste0(value, "-tampered")
    expect_error(
      .dsvert_dp_capsule_workload_require_materializable(tampered),
      "registered release lifecycle",
      info = paste("tampered lifecycle field", name))
  }
  tampered <- manifest
  tampered$workload$registered_release_lifecycle$extra <- TRUE
  expect_error(
    .dsvert_dp_capsule_workload_require_materializable(tampered),
    "registered release lifecycle")
})

test_that("count, univariate and pairwise numeric sensitivities are valid", {
  added <- .capsule_test_build(.capsule_test_fixture())
  replacement_fixture <- .capsule_test_fixture()
  replacement_fixture$policy$adjacency <- "replace_one_fixed_cohort"
  replacement_fixture$policy$fixed_cohort_size <-
    replacement_fixture$policy$unit_capacity
  replaced <- .capsule_test_build(replacement_fixture)

  expect_identical(
    added$workload$families$admitted_count$l1_sensitivity, 1)
  expect_identical(
    added$workload$families$admitted_count$l2_sensitivity, 1)
  expect_identical(
    replaced$workload$families$admitted_count$l1_sensitivity, 0)
  expect_identical(
    replaced$workload$families$admitted_count$l2_sensitivity, 0)

  scale <- replacement_fixture$policy$numeric_grid_bits
  scale <- 2^scale
  column_count <- length(replacement_fixture$policy$numeric_bounds)
  extreme_delta <- rep(c(1, scale, scale), column_count)
  expected_l1 <- sum(abs(extreme_delta))
  expected_l2 <- sqrt(sum(extreme_delta^2))
  numeric_family <- replaced$workload$families$numeric_moments
  expect_equal(numeric_family$l1_sensitivity, expected_l1, tolerance = 0)
  expect_gte(numeric_family$l2_sensitivity, expected_l2)
  expect_lt(
    numeric_family$l2_sensitivity - expected_l2,
    expected_l2 * 128 * .Machine$double.eps)
  expect_equal(
    added$workload$families$numeric_moments$l1_sensitivity,
    expected_l1, tolerance = 0)
  expect_gte(
    added$workload$families$numeric_moments$l2_sensitivity,
    expected_l2)

  finite_extreme_delta <- rep(c(0, scale, scale), column_count)
  expect_lte(sum(abs(finite_extreme_delta)), expected_l1)
  expect_lte(sqrt(sum(finite_extreme_delta^2)), expected_l2)

  pair_count <- choose(column_count, 2)
  for (manifest in list(added, replaced)) {
    pair_family <- manifest$workload$families$numeric_pair_moments
    expect_equal(length(pair_family$artifacts), pair_count)
    expect_equal(
      pair_family$l1_sensitivity,
      pair_count * (1 + 5 * scale), tolerance = 0)
    expect_gte(
      pair_family$l2_sensitivity,
      sqrt(pair_count * (1 + 5 * scale^2)))
    expect_equal(
      pair_family$natural_l1_sensitivity, 6 * pair_count, tolerance = 0)
    expect_gte(
      pair_family$natural_l2_sensitivity, sqrt(6 * pair_count))
    expect_true(all(vapply(pair_family$artifacts, function(artifact) {
      identical(artifact$adjacency, manifest$admission$adjacency) &&
        identical(artifact$natural_l1_sensitivity, 6) &&
        artifact$natural_l2_sensitivity >= sqrt(6) &&
        identical(
          artifact$statistic_maximum,
          c(manifest$admission$unit_capacity,
            rep(manifest$admission$unit_capacity * scale, 5L)))
    }, logical(1L))))
  }
})

test_that("per-operation L2 guards dominate adversarial binary64 oracles", {
  as_bignum <- function(value) {
    openssl::bignum(format(
      value, scientific = FALSE, trim = TRUE, digits = 22L))
  }

  # At 2^53, naive binary64 addition of one stagnates. The guarded
  # accumulator must remain above the exact integer sum in either order.
  start <- 2^53
  increments <- rep(1, 4096L)
  naive <- start
  for (increment in increments) naive <- naive + increment
  expect_identical(naive, start)
  forward <- Reduce(.dsvert_dp_capsule_l2_add, increments, init = start)
  reverse <- Reduce(
    .dsvert_dp_capsule_l2_add, rev(c(start, increments)), init = 0)
  exact <- openssl::bignum("9007199254740992") +
    openssl::bignum(as.character(length(increments)))
  expect_true(exact <= as_bignum(forward))
  expect_true(exact <= as_bignum(reverse))
  expect_lt((forward - start) / start, 1e-9)
  expect_lt((reverse - start) / start, 1e-9)

  # This square is one above a binary64 lattice point at its magnitude.
  # The raw multiplication rounds it, whereas the certified bound must be
  # strictly outside the exact big-integer oracle.
  value <- 134217729
  square_exact <- openssl::bignum("134217729")^2
  square_bound <- .dsvert_dp_capsule_l2_square(value)
  expect_true(square_exact <= as_bignum(square_bound))
  expect_gte(.dsvert_dp_capsule_l2_sqrt(value * value), value)

  fixture <- .capsule_test_fixture()
  manifest <- .capsule_test_build(fixture)
  expect_identical(
    manifest$workload$sensitivity$l2_rounding,
    "per_operation_outward_binary64_guard_v2")
})

test_that("signed Gaussian artifacts have bounded global sensitivity", {
  fixture <- .capsule_test_fixture()
  fixture$specs$gaussian$primary_gaussian <- list(
    version = "v1", dataset = "protected", outcome = "marker",
    predictors = c("time", "age"), intercept = TRUE)
  manifest <- .capsule_test_build(fixture)
  family <- manifest$workload$families$gaussian_models
  artifact <- family$artifacts$primary_gaussian
  scale <- 2^fixture$policy$numeric_grid_bits
  # q=3, hence 1 + 6 X'X + 3 X'y + 1 y'y = 11 coordinates.
  expect_identical(artifact$predictor_order, c("age", "time"))
  expect_identical(
    artifact$design_terms, c("(Intercept)", "age", "time"))
  expect_equal(artifact$coordinate_count, 11L)
  expect_identical(
    artifact$coordinate_order,
    "n_then_xtx_upper_column_major_then_xty_design_order_then_yty_v1")
  expect_identical(
    artifact$missingness_policy,
    "complete_case_across_outcome_and_all_predictors_v1")
  expect_identical(artifact$source_raw_l1_sensitivity, 1 + 10 * scale)
  expect_gte(
    artifact$source_raw_l2_sensitivity,
    sqrt(1 + 10 * scale^2))
  expect_identical(artifact$natural_l1_sensitivity, 11)
  expect_gte(artifact$natural_l2_sensitivity, sqrt(11))
  expect_equal(family$coordinate_count, 11L)
  expect_identical(family$natural_l1_sensitivity, 11)
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
  expect_identical(
    manifest$workload$coordinate_count,
    .capsule_test_build(.capsule_test_fixture())$workload$coordinate_count +
      11L)

  vertical <- .capsule_test_fixture(vertical = TRUE)
  vertical$specs$gaussian$unsafe <- list(
    version = "v1", dataset = "protected", outcome = "age",
    predictors = "remote_marker", intercept = TRUE)
  expect_error(
    .capsule_test_build(vertical),
    "must explicitly use version 'v2'")

  vertical$specs$gaussian$unsafe$version <- "v2"
  cross_manifest <- .capsule_test_build(vertical)
  cross <- cross_manifest$workload$families$gaussian_models$artifacts$unsafe
  expect_identical(
    cross$version,
    "bounded-normalized-gaussian-cross-sufficient-statistics-v1")
  expect_identical(cross$spec_version, "v2")
  expect_identical(cross$participating_peers, list("peer_a", "peer_b"))
  expect_identical(cross$computation_peers, list("peer_a", "peer_b"))
  expect_identical(cross$predictors$remote_marker$dataset, "remote")
  expect_identical(cross$predictors$remote_marker$owner_peer, "peer_b")
  expect_identical(cross$outcome$dataset, "protected")
  expect_identical(cross$outcome$owner_peer, "peer_a")
  expect_true(all(cross$statistic_maximum ==
                    vertical$policy$unit_capacity * scale))
  expect_identical(
    cross$source_raw_l1_sensitivity,
    cross$coordinate_count * scale)
  expect_identical(
    cross$source_coordinate_scaling,
    "all_coordinates_already_on_common_numeric_lattice_v1")
  expect_false(cross$quantization_contract$same_owner_v1_numerically_identical)
  expect_true(cross$numeric_certificate$modular_wrap_proved_absent)
  expect_identical(cross$transcript$data_dependent_branches, 0)
  expect_identical(cross$transcript$padded_units,
                   as.numeric(vertical$policy$unit_capacity))
  expect_identical(cross$implementation_state,
                   "cross_owner_exact_gc_materialized")
  expect_identical(cross$cross_owner_state,
                   "exact_gc_to_joint_dp_vector_v1")
})

test_that("cross Gaussian K=3 through K=5 fixes two computation peers", {
  for (k in 3:5) {
    fixture <- .capsule_test_k3_fixture("peer_a", k)
    fixture$specs$gaussian$cross_k3 <- list(
      version = "v2", dataset = "protected", outcome = "age",
      predictors = "remote_marker", intercept = FALSE)
    manifest <- .capsule_test_build(fixture)
    artifact <-
      manifest$workload$families$gaussian_models$artifacts$cross_k3

    expect_length(fixture$policy$peer_pinset, k)
    expect_identical(artifact$participating_peers,
                     list("peer_a", "peer_c"))
    expect_identical(artifact$computation_peers,
                     list("peer_a", "peer_b"))
    expect_identical(artifact$input_variable_order,
                     c("remote_marker", "age"))
    expect_identical(artifact$transcript$variable_count, 2)
    expect_identical(artifact$transcript$validity_product_rounds, 1)
    expect_identical(artifact$numeric_certificate$ring_bits, 128)
    expect_lt(artifact$numeric_certificate$required_signed_bits, 127L)
  }
})

test_that("common output lattice removes numeric-grid scale imbalance", {
  manifest <- .capsule_test_build(.capsule_test_fixture())
  workload <- manifest$workload
  lattice <- workload$release_lattice
  families <- workload$families
  scale <- manifest$bounds$numeric_grid_scale
  survival_l1 <- sum(vapply(
    families$survival_artifacts, `[[`, numeric(1L), "l1_sensitivity"))
  expected_natural_l1 <-
    families$admitted_count$l1_sensitivity +
    3 * length(families$numeric_moments$artifacts) +
    families$numeric_pair_moments$natural_l1_sensitivity +
    families$gaussian_models$natural_l1_sensitivity +
    families$fixed_numeric_histograms$l1_sensitivity +
    families$categorical_marginals$l1_sensitivity +
    families$categorical_pairs$l1_sensitivity + survival_l1

  expect_identical(lattice$version,
                   "biomedical-capsule-common-lattice-v1")
  expect_identical(
    lattice$transform_rule,
    "raw_coordinate_left_shift_to_common_numeric_grid_v1")
  expect_identical(lattice$output_lattice_bits,
                   manifest$bounds$numeric_grid_bits)
  expect_identical(lattice$output_lattice_scale, scale)
  expect_equal(lattice$natural_l1_sensitivity,
               expected_natural_l1, tolerance = 0)
  expect_equal(lattice$integer_l1_sensitivity_steps,
               expected_natural_l1 * scale, tolerance = 0)
  expect_identical(workload$sensitivity$l1,
                   lattice$integer_l1_sensitivity_steps)
  expect_identical(
    workload$capsule_mechanism$sensitivity,
    lattice$integer_l1_sensitivity_steps)
  expect_identical(workload$capsule_mechanism$sensitivity_norm, "l1")
  expect_gt(workload$sensitivity$source_raw_l1,
            lattice$natural_l1_sensitivity)
})

test_that("Describe reuses numeric moments and canonical histogram primitives", {
  fixture <- .capsule_test_fixture()
  one <- .capsule_test_build(fixture)
  duplicated <- fixture
  duplicated$specs$describe$secondary <-
    duplicated$specs$describe$primary
  two <- .capsule_test_build(duplicated)

  one_histograms <- one$workload$families$fixed_numeric_histograms
  two_histograms <- two$workload$families$fixed_numeric_histograms
  expect_identical(two_histograms$artifacts, one_histograms$artifacts)
  expect_identical(
    two_histograms$coordinate_count, one_histograms$coordinate_count)
  expect_identical(
    two$workload$coordinate_count, one$workload$coordinate_count)
  expect_named(two$workload$families$describe_artifacts,
               c("primary", "secondary"))

  primary <- two$workload$families$describe_artifacts$primary
  secondary <- two$workload$families$describe_artifacts$secondary
  expect_identical(primary$numeric_moment_references,
                   secondary$numeric_moment_references)
  expect_identical(primary$histogram_references,
                   secondary$histogram_references)
  expect_identical(
    vapply(primary$numeric_moment_references, `[[`, character(1L),
           "family"),
    rep("numeric_moments", length(primary$variables)))
  expect_setequal(
    vapply(primary$numeric_moment_references, `[[`, character(1L),
           "artifact"),
    primary$variables)
})

test_that("semantic reordering cannot reroll a capsule", {
  fixture <- .capsule_test_fixture()
  expected <- .capsule_test_build(fixture)
  reordered <- fixture
  reordered$schema <- reordered$schema[
    rev(names(reordered$schema))]
  reordered$schema$datasets <- reordered$schema$datasets[
    rev(names(reordered$schema$datasets))]
  dataset <- reordered$schema$datasets$protected
  dataset <- dataset[rev(names(dataset))]
  dataset$columns <- dataset$columns[rev(names(dataset$columns))]
  dataset$columns$sex$levels <- rev(dataset$columns$sex$levels)
  dataset$columns$status$levels <- rev(dataset$columns$status$levels)
  dataset$patient_keys <- dataset$patient_keys[
    rev(names(dataset$patient_keys))]
  reordered$schema$datasets$protected <- dataset
  reordered$schema$signatures <- reordered$schema$signatures[
    rev(names(reordered$schema$signatures))]
  describe <- reordered$specs$describe$primary
  describe$variables <- rev(describe$variables)
  describe$histogram_grids <- describe$histogram_grids[
    describe$variables]
  describe$allocation <- describe$allocation[
    rev(names(describe$allocation))]
  reordered$specs$describe$primary <- describe

  actual <- .capsule_test_build(reordered)
  expect_identical(actual$capsule_identity$capsule_id,
                   expected$capsule_identity$capsule_id)
  expect_identical(actual$admission, expected$admission)
  expect_identical(actual$bounds, expected$bounds)
  expect_identical(actual$workload, expected$workload)

  set.seed(20260801)
  for (index in seq_len(40L)) {
    fuzzed <- reordered
    fuzzed$schema$datasets$protected$columns <-
      fuzzed$schema$datasets$protected$columns[sample(5L)]
    fuzzed$schema$datasets$protected$columns$sex$levels <-
      sample(fuzzed$schema$datasets$protected$columns$sex$levels)
    fuzzed$schema$datasets$protected$columns$status$levels <-
      sample(fuzzed$schema$datasets$protected$columns$status$levels)
    variables <- sample(c("age", "marker"))
    fuzzed$specs$describe$primary$variables <- variables
    fuzzed$specs$describe$primary$histogram_grids <-
      fuzzed$specs$describe$primary$histogram_grids[variables]
    expect_identical(
      .capsule_test_build(fuzzed)$capsule_identity$capsule_id,
      expected$capsule_identity$capsule_id)
  }
})

test_that("vertical owners derive one identity for the declared coordinate vector", {
  peer_a <- .capsule_test_fixture("peer_a", vertical = TRUE)
  peer_b <- .capsule_test_fixture("peer_b", vertical = TRUE)
  manifest_a <- .capsule_test_build(peer_a)
  manifest_b <- .capsule_test_build(peer_b)
  expect_identical(manifest_a$capsule_identity$capsule_id,
                   manifest_b$capsule_identity$capsule_id)
  expect_identical(manifest_a$bounds, manifest_b$bounds)
  expect_identical(manifest_a$workload, manifest_b$workload)
  expect_identical(
    manifest_a$execution_state,
    "registered_lifecycle_available_requires_runtime_preflight")
  expect_false(manifest_a$workload$package_family_coverage_complete)
  expect_gt(length(
    manifest_a$workload$vertical_crosses$cross_owner_sets), 0L)
  expect_invisible(
    .dsvert_dp_capsule_workload_require_materializable(manifest_a))
  reordered_assets <- peer_a
  reordered_assets$schema$datasets <-
    reordered_assets$schema$datasets[rev(names(
      reordered_assets$schema$datasets))]
  expect_identical(
    .capsule_test_build(reordered_assets)$capsule_identity$capsule_id,
    manifest_a$capsule_identity$capsule_id)

  separated <- peer_a
  separated$schema$datasets$remote$alignment_group <- "aligned-other"
  expect_error(.capsule_test_build(separated),
               "exactly one signed alignment group")
})

test_that("K=3 through K=5 custodians attest but cannot allocate noise", {
  for (k in 3:5) {
    peer_a <- .capsule_test_k3_fixture("peer_a", k)
    peer_c <- .capsule_test_k3_fixture("peer_c", k)
    manifest_a <- .capsule_test_build(peer_a)
    manifest_c <- .capsule_test_build(peer_c)
    expect_identical(manifest_c$capsule_identity$capsule_id,
                     manifest_a$capsule_identity$capsule_id)
    expect_identical(
      .dsvert_joint_dp_policy_context(
        peer_c$policy, require_designated = FALSE)$common,
      .dsvert_joint_dp_policy_context(peer_a$policy)$common)
    expect_error(
      .dsvert_joint_dp_policy_context(peer_c$policy),
      "designated noise peer")
    expect_error(
      .dsvert_joint_dp_prepare(
        peer_c$policy, list(), .secret = as.raw(seq_len(32L))),
      "designated noise peer")
  }
})

test_that("semantic inputs, but not a local noise epoch, change capsule identity", {
  fixture <- .capsule_test_fixture()
  original <- .capsule_test_build(fixture)$capsule_identity$capsule_id

  changed_schema <- fixture
  changed_schema$schema$datasets$protected$schema_version <- "schema-v2"
  expect_false(identical(
    .capsule_test_build(changed_schema)$capsule_identity$capsule_id,
    original))

  changed_alignment <- fixture
  changed_alignment$schema$datasets$protected$alignment_group <-
    "aligned-revision"
  expect_false(identical(
    .capsule_test_build(changed_alignment)$capsule_identity$capsule_id,
    original))

  changed_bound <- fixture
  changed_bound$schema$datasets$protected$columns$age$upper <- 120
  changed_bound$policy$numeric_bounds$age[[2L]] <- 120
  changed_bound$specs$describe$primary$histogram_grids$age <- c(60, 120)
  expect_false(identical(
    .capsule_test_build(changed_bound)$capsule_identity$capsule_id,
    original))

  changed_spec <- fixture
  changed_spec$specs$describe$primary$histogram_grids$age <- c(25, 100)
  expect_false(identical(
    .capsule_test_build(changed_spec)$capsule_identity$capsule_id,
    original))

  changed_snapshot <- fixture
  changed_snapshot$snapshot <- .capsule_test_snapshot("v2")
  changed_snapshot$schema$logical_snapshot <- changed_snapshot$snapshot
  expect_false(identical(
    .capsule_test_build(changed_snapshot)$capsule_identity$capsule_id,
    original))

  changed_policy <- fixture
  changed_policy$policy$noise_root$epoch <- 2
  expect_identical(
    .capsule_test_build(changed_policy)$capsule_identity$capsule_id,
    original)
})

test_that("signed ownership fails closed and vertical work remains reserved", {
  fixture <- .capsule_test_fixture()
  unsigned <- fixture
  unsigned$schema$signatures$peer_b <- NULL
  verifier_calls <- 0L
  expect_error(
    .dsvert_dp_capsule_workload_manifest(
      unsigned$policy, unsigned$snapshot, unsigned$schema,
      describe_specs = unsigned$specs$describe,
      survival_specs = unsigned$specs$survival,
      .signature_verifier = function(...) {
        verifier_calls <<- verifier_calls + 1L
        TRUE
      }),
    "Every pinned peer must sign")
  expect_identical(verifier_calls, 0L)
  expect_error(
    .dsvert_dp_capsule_workload_manifest(
      fixture$policy, fixture$snapshot, fixture$schema,
      describe_specs = fixture$specs$describe,
      survival_specs = fixture$specs$survival,
      .signature_verifier = function(...) FALSE),
    "signatures are invalid")

  vertical <- fixture
  vertical$schema$datasets$protected$patient_keys$peer_b <- "patient_id"
  vertical$schema$datasets$protected$columns$status$owner_peer <- "peer_b"
  vertical$policy$categorical_levels$status <- NULL
  vertical$specs$survival <- list()
  manifest <- .capsule_test_build(vertical)
  expect_identical(
    manifest$execution_state,
    "registered_lifecycle_available_requires_runtime_preflight")
  expect_identical(
    manifest$workload$vertical_crosses$implementation_state,
    "reserved_not_materialized")
  expect_gt(length(
    manifest$workload$vertical_crosses$categorical_pair_sets), 0L)
  expect_identical(
    manifest$workload$vertical_crosses$included_coordinate_count, 0)
  expect_invisible(
    .dsvert_dp_capsule_workload_require_materializable(manifest))

  cross_spec <- .capsule_test_fixture(vertical = TRUE)
  cross_manifest <- .capsule_test_build(
    cross_spec,
    vertical_cross_specs = list(marker_cross = list(
      version = "v1", left_dataset = "protected",
      right_dataset = "remote", left = "marker",
      right = "remote_marker", family = "numeric_cross_moment")))
  expect_named(
    cross_manifest$workload$vertical_crosses$configured_crosses,
    "marker_cross")
  expect_identical(
    cross_manifest$execution_state,
    "registered_lifecycle_available_requires_runtime_preflight")
  reversed_cross_manifest <- .capsule_test_build(
    cross_spec,
    vertical_cross_specs = list(marker_cross = list(
      version = "v1", left_dataset = "remote",
      right_dataset = "protected", left = "remote_marker",
      right = "marker", family = "numeric_cross_moment")))
  expect_identical(
    reversed_cross_manifest$capsule_identity$capsule_id,
    cross_manifest$capsule_identity$capsule_id)
})

test_that("custodian catalog excludes undeclared primitives and deduplicates references", {
  fixture <- .capsule_test_fixture()
  fixture$specs$survival <- list()
  fixture$specs$describe <- list(primary = list(
    version = "v1", dataset = "protected", variables = "age",
    histogram_grids = list(age = c(50, 100)),
    allocation = c(
      count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2)))
  fixture$policy$capsule_workload_scope <- list(
    mode = "catalog_v1",
    numeric_moments = c("age", "age"),
    categorical_marginals = "sex",
    categorical_pairs = list(c("status", "sex"), c("sex", "status")),
    correlations = list(c("marker", "age"), c("age", "marker")))

  manifest <- .capsule_test_build(fixture)
  workload <- manifest$workload

  expect_identical(
    names(workload$families$numeric_moments$artifacts),
    c("age", "marker"))
  expect_false("time" %in%
                 names(workload$families$numeric_moments$artifacts))
  expect_identical(
    names(workload$families$categorical_marginals$artifacts),
    c("sex", "status"))
  expect_length(workload$families$numeric_pair_moments$artifacts, 1L)
  expect_equal(
    workload$families$categorical_pairs$sets[[1L]]$pair_count, 1L)
  expect_identical(workload$primitive_scope$mode, "catalog_v1")
  expect_false(workload$primitive_scope$analyst_expandable)
  expect_equal(
    workload$primitive_scope$projected_cost$included_numeric_pair_count,
    1L)
  expect_equal(
    workload$primitive_scope$projected_cost$included_categorical_pair_count,
    1L)
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  expect_identical(
    length(layout$blocks[vapply(layout$blocks, `[[`, character(1L),
                                "family") == "categorical_pairs"]),
    1L)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = manifest, layout = layout))
  expect_equal(length(lattice$raw_upper_bounds),
               workload$coordinate_count)

  without_undeclared <- fixture
  without_undeclared$schema$datasets$protected$columns$time <- NULL
  without_undeclared$policy$numeric_bounds$time <- NULL
  trimmed <- .capsule_test_build(without_undeclared)
  expect_identical(
    workload$coordinate_count, trimmed$workload$coordinate_count)
  expect_identical(workload$sensitivity, trimmed$workload$sensitivity)
})

test_that("signed method specifications populate an otherwise empty catalog once", {
  fixture <- .capsule_test_fixture()
  fixture$specs$gaussian <- list(primary_model = list(
    version = "v1", dataset = "protected", outcome = "marker",
    predictors = "age", intercept = TRUE))
  fixture$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())

  manifest <- .capsule_test_build(fixture)
  scope <- manifest$workload$primitive_scope

  expect_identical(
    names(manifest$workload$families$numeric_moments$artifacts),
    c("age", "marker", "time"))
  expect_identical(
    names(manifest$workload$families$categorical_marginals$artifacts),
    "status")
  expect_false("sex" %in%
                 scope$selection$included$categorical_marginals)
  expect_length(
    manifest$workload$families$numeric_pair_moments$artifacts, 0L)
  expect_length(manifest$workload$families$categorical_pairs$sets, 0L)
  expect_identical(
    scope$selection$referenced_by_signed_specs$gaussian,
    "primary_model")
})

test_that("LMM grouping labels remain signed metadata, not released marginals", {
  fixture <- .capsule_test_fixture()
  fixture$specs <- list(
    describe = list(), survival = list(), gaussian = list(
      lmm = list(
        version = "random_intercept_fixed_v2", dataset = "protected",
        outcome = "marker", predictors = "age", intercept = TRUE,
        cluster = "sex", max_patients_per_cluster = 2L,
        variance_ratio_grid = c(0, 1))))
  fixture$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())

  manifest <- .capsule_test_build(fixture)
  scope <- manifest$workload$primitive_scope$selection

  expect_identical(
    scope$referenced_by_signed_specs$categorical, "sex")
  expect_length(
    manifest$workload$families$categorical_marginals$artifacts, 0L)
  expect_false("sex" %in% scope$included$categorical_marginals)
  expect_equal(
    manifest$workload$families$gaussian_models$artifacts$lmm$
      coordinate_count, 21L)
})

test_that("count and admission remain present with an empty catalog", {
  fixture <- .capsule_test_fixture()
  fixture$specs <- list(describe = list(), survival = list(), gaussian = list())
  fixture$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())

  manifest <- .capsule_test_build(fixture)

  expect_identical(manifest$workload$coordinate_count, 1)
  expect_identical(
    manifest$workload$families$admitted_count$coordinate_count, 1)
  expect_length(
    manifest$workload$primitive_scope$selection$included$numeric_moments,
    0L)
  expect_length(
    manifest$workload$primitive_scope$selection$included$
      categorical_marginals,
    0L)
})

test_that("catalog scope scales linearly while explicit all-schema preserves quadratic coverage", {
  build_wide <- function(width, mode) {
    fixture <- .capsule_test_fixture()
    numeric_names <- paste0("x", seq_len(width))
    categorical_names <- paste0("c", seq_len(width))
    numeric <- stats::setNames(lapply(numeric_names, function(name) {
      list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 1)
    }), numeric_names)
    categorical <- stats::setNames(lapply(categorical_names, function(name) {
      list(kind = "categorical", owner_peer = "peer_a",
           levels = c("no", "yes"))
    }), categorical_names)
    fixture$schema$datasets$protected$columns <- c(numeric, categorical)
    fixture$policy$numeric_bounds <- stats::setNames(
      rep(list(c(0, 1)), width), numeric_names)
    fixture$policy$categorical_levels <- stats::setNames(
      rep(list(c("no", "yes")), width), categorical_names)
    fixture$specs <- list(describe = list(), survival = list(), gaussian = list())
    fixture$policy$capsule_workload_scope <- if (identical(
        mode, "all_schema")) {
      list(mode = "all_schema")
    } else {
      list(
        mode = "catalog_v1", numeric_moments = numeric_names,
        categorical_marginals = categorical_names,
        categorical_pairs = list(), correlations = list())
    }
    .capsule_test_build(fixture)
  }

  scoped_8 <- build_wide(8L, "catalog_v1")
  scoped_16 <- build_wide(16L, "catalog_v1")
  full_8 <- build_wide(8L, "all_schema")
  full_16 <- build_wide(16L, "all_schema")

  expect_identical(scoped_8$workload$coordinate_count, 41)
  expect_identical(scoped_16$workload$coordinate_count, 81)
  expect_identical(
    scoped_16$workload$coordinate_count - 1,
    2 * (scoped_8$workload$coordinate_count - 1))
  expect_gt(
    full_16$workload$coordinate_count - 1,
    3 * (full_8$workload$coordinate_count - 1))
  expect_identical(
    scoped_16$workload$primitive_scope$projected_cost$automatic_pair_expansion,
    "none")
  expect_identical(
    full_16$workload$primitive_scope$projected_cost$automatic_pair_expansion,
    "explicit_all_schema")
})

test_that("explicit all-schema is byte-compatible with the compatibility default", {
  default <- .capsule_test_fixture()
  explicit <- default
  explicit$policy$capsule_workload_scope <- list(mode = "all_schema")

  default_manifest <- .capsule_test_build(default)
  explicit_manifest <- .capsule_test_build(explicit)

  expect_identical(default_manifest, explicit_manifest)
})

test_that("different peer scopes cannot authorize one another before data access", {
  fixture <- .capsule_test_fixture()
  fixture$specs$describe <- list()
  fixture$specs$survival <- list()
  all_schema <- fixture
  catalog <- fixture
  catalog$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = "age",
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())

  protected_access <- 0L
  manifests <- testthat::with_mocked_bindings(
    list(
      all_schema = .capsule_test_build(all_schema),
      catalog = .capsule_test_build(catalog)),
    .dsvert_dp_resolve_snapshot = function(...) {
      protected_access <<- protected_access + 1L
      stop("protected data accessed", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(protected_access, 0L)
  expect_false(identical(
    manifests$all_schema$capsule_identity$capsule_id,
    manifests$catalog$capsule_identity$capsule_id))

  catalog_json <- .dsvert_dp_canonical_json(manifests$catalog)
  all_hash <- digest::digest(
    .dsvert_dp_canonical_json(manifests$all_schema),
    algo = "sha256", serialize = FALSE)
  expect_error(
    .dsvert_dp_capsule_manifest_require_built(
      catalog$policy, catalog_json, secret = as.raw(seq_len(32L)),
      .cache_get = function(policy, secret, cache_key = NULL,
                            manifest_sha256 = NULL) {
        if (identical(manifest_sha256, all_hash)) list() else NULL
      }),
    class = "dsvert_capsule_manifest_rejected")
  expect_identical(protected_access, 0L)
})

test_that("ambiguous malformed and oversized metadata is rejected", {
  fixture <- .capsule_test_fixture()

  malformed_scope <- fixture
  malformed_scope$policy$capsule_workload_scope <- list(
    mode = "all_schema", numeric_moments = "age")
  expect_error(
    .capsule_test_build(malformed_scope), "workload scope")

  unknown_scope <- fixture
  unknown_scope$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = "unknown_column",
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())
  expect_error(.capsule_test_build(unknown_scope), "signed schema")

  cross_owner_scope <- .capsule_test_fixture(vertical = TRUE)
  cross_owner_scope$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list(c("marker", "remote_marker")))
  expect_error(.capsule_test_build(cross_owner_scope), "same-owner")

  ambiguous <- fixture
  ambiguous$schema$datasets$second <-
    ambiguous$schema$datasets$protected
  ambiguous$schema$datasets$second$dataset_id <- "second-cohort"
  expect_error(
    .capsule_test_build(ambiguous), "owner/dataset/column triplet")

  invalid_spec <- fixture
  invalid_spec$specs$survival$primary$time_grid <- c(1, 3, 2, 5)
  expect_error(.capsule_test_build(invalid_spec), "time grid is invalid")

  invalid_bound <- fixture
  invalid_bound$schema$datasets$protected$columns$age$upper <- Inf
  expect_error(.capsule_test_build(invalid_bound), "numeric bounds")

  unknown_owner <- fixture
  unknown_owner$schema$datasets$protected$columns$age$owner_peer <- "peer_x"
  expect_error(.capsule_test_build(unknown_owner), "column ownership")

  oversized <- fixture
  oversized$specs <- list(describe = list(), survival = list())
  levels_left <- paste0("l", seq_len(1001L))
  levels_right <- paste0("r", seq_len(1001L))
  oversized$schema$datasets$protected$columns <- list(
    left = list(kind = "categorical", owner_peer = "peer_a",
                levels = levels_left),
    right = list(kind = "categorical", owner_peer = "peer_a",
                 levels = levels_right))
  oversized$policy$numeric_bounds <- list()
  oversized$policy$categorical_levels <- list(
    left = levels_left, right = levels_right)
  expect_error(.capsule_test_build(oversized),
               "exceeds the DP coordinate limit")
  expect_error(
    .dsvert_dp_capsule_coordinate_add(.DSVERT_DP_MAX_COORDINATES, 1L),
    "coordinate limit")
  expect_error(
    .dsvert_dp_capsule_coordinate_add(0L, 2^53),
    "coordinate limit")
})

test_that("pure-DP policy selects one complete Laplace vector", {
  fixture <- .capsule_test_fixture(delta = 0)
  manifest <- .capsule_test_build(fixture)
  expect_identical(
    manifest$workload$capsule_mechanism$mechanism,
    "discrete-laplace")
  expect_identical(
    manifest$workload$capsule_mechanism$sensitivity_norm, "l1")
  expect_false(manifest$workload$capsule_mechanism$uses_delta)
})

test_that("exact Gaussian decimal calibration is conservatively directed", {
  values <- c(
    .Machine$double.xmin, 1e-100, .Machine$double.eps,
    0.1, 1 / 3, 1, 8, 2^52)
  for (value in values) {
    inward <- .dsvert_dp_capsule_gaussian_decimal(
      value, "inward", "test value")
    outward <- .dsvert_dp_capsule_gaussian_decimal(
      value, "outward", "test value")
    expect_gt(as.numeric(inward), 0)
    expect_lt(as.numeric(inward), value)
    expect_gt(as.numeric(outward), value)
  }
})

test_that("tiny default delta reserves implementation slack without blocking", {
  fixture <- .capsule_test_fixture(delta = 2^-100)
  selector_called <- FALSE
  manifest <- .capsule_test_build(
    fixture,
    .noise_selector = function(...) {
      selector_called <<- TRUE
      .capsule_test_noise_selector(...)
    })
  mechanism <- manifest$workload$capsule_mechanism
  selection <- manifest$workload$mechanism_selection
  expect_true(selector_called)
  expect_identical(mechanism$mechanism, "discrete-laplace")
  expect_identical(mechanism$sensitivity_norm, "l1")
  expect_identical(
    mechanism$sensitivity, manifest$workload$sensitivity$l1)
  expect_true(mechanism$uses_delta)
  expect_true(selection$positive_delta_reserved)
  expect_true(selection$gaussian_eligible)
  expect_false(selection$gaussian_backend_available)
  expect_identical(selection$winner, "laplace")
  expect_identical(selection$utility_winner, "laplace")
  expect_true(selection$canonical_selector_invoked)
  expect_identical(
    selection$gaussian_unavailable_reason,
    "formal_fixed_work_gaussian_plan_unavailable")
  expect_match(selection$decision, "fallback")
})

test_that("eligible Gaussian still loses on a tie or worse utility", {
  fixture <- .capsule_test_fixture(delta = 1e-6)
  manifest <- .capsule_test_build(
    fixture,
    .noise_selector = function(...) {
      .capsule_test_noise_selector(..., gaussian_winner = FALSE)
    })
  mechanism <- manifest$workload$capsule_mechanism
  selection <- manifest$workload$mechanism_selection
  expect_true(selection$gaussian_eligible)
  expect_true(selection$canonical_selector_invoked)
  expect_identical(selection$winner, "laplace")
  expect_identical(selection$utility_winner, "laplace")
  expect_identical(mechanism$mechanism, "discrete-laplace")
  expect_identical(mechanism$sensitivity_norm, "l1")
  expect_true(mechanism$uses_delta)
  expect_match(selection$decision, "Laplace|laplace")
})

.qualified_gaussian_fixture <- function(k) {
  if (identical(k, 2L)) {
    fixture <- .capsule_test_fixture(vertical = TRUE)
    remote_owner <- "peer_b"
  } else if (identical(k, 3L)) {
    fixture <- .capsule_test_k3_fixture("peer_a", 3L)
    remote_owner <- "peer_c"
  } else {
    stop("invalid qualified Gaussian fixture")
  }

  fixture$policy$numeric_bounds$x <- c(-2, 2)
  fixture$policy$capsule_workload_scope <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())
  fixture$schema$datasets$protected$columns[["peer_a$x"]] <- list(
    kind = "numeric", owner_peer = "peer_a", lower = -2, upper = 2)
  fixture$schema$datasets$remote$columns <- stats::setNames(list(list(
    kind = "numeric", owner_peer = remote_owner, lower = -1, upper = 1)),
    paste0(remote_owner, "$x"))
  fixture$specs$describe <- list()
  fixture$specs$survival <- list()
  fixture$specs$gaussian <- list(duplicate_x = list(
    version = "v2", dataset = "protected", outcome = "age",
    predictors = c("peer_a$x", paste0(remote_owner, "$x")),
    intercept = TRUE))
  fixture
}

test_that("signed Gaussian columns distinguish duplicate physical names at K=2/3", {
  for (k in c(2L, 3L)) {
    fixture <- .qualified_gaussian_fixture(k)
    fixture$policy$capsule_workload_specs <- list(
      describe = list(), survival = list(),
      gaussian = fixture$specs$gaussian, vertical_cross = list())
    local_specs <- .dsvert_dp_capsule_manifest_local_specs(fixture$policy)
    expect_identical(
      local_specs$gaussian$duplicate_x$predictors,
      fixture$specs$gaussian$duplicate_x$predictors,
      info = paste("local draft K =", k))
    manifest <- .capsule_test_build(fixture)
    artifact <- manifest$workload$families$gaussian_models$
      artifacts$duplicate_x
    remote_owner <- if (k == 2L) "peer_b" else "peer_c"
    references <- c("peer_a$x", paste0(remote_owner, "$x"))
    owners <- sub("\\$x$", "", references)

    expect_identical(artifact$predictor_order, references,
                     info = paste("K =", k))
    expect_identical(names(artifact$predictors), references,
                     info = paste("K =", k))
    expect_true(all(vapply(
      artifact$predictors, function(value) identical(value$column, "x"),
      logical(1L))), info = paste("K =", k))
    expect_identical(
      unname(vapply(
        artifact$predictors, `[[`, character(1L), "owner_peer")),
      owners, info = paste("K =", k))

    layout <- .dsvert_dp_gaussian_cross_layout(manifest)
    blocks <- layout$blocks[grepl("^duplicate_x::", names(layout$blocks))]
    expect_length(blocks, 6L)
    predictor_blocks <- blocks[vapply(
      blocks, function(block) identical(block$variable, "x"), logical(1L))]
    expect_length(predictor_blocks, 4L)
    expect_setequal(vapply(
      predictor_blocks, `[[`, character(1L), "owner_peer"), owners)

    reordered <- fixture
    reordered$schema$datasets <- rev(reordered$schema$datasets)
    reordered$schema$datasets$protected$columns <-
      rev(reordered$schema$datasets$protected$columns)
    expect_identical(
      .capsule_test_build(reordered)$capsule_identity$capsule_id,
      manifest$capsule_identity$capsule_id,
      info = paste("K =", k))

    wrong_owner <- fixture
    names(wrong_owner$schema$datasets$protected$columns)[
      names(wrong_owner$schema$datasets$protected$columns) == "peer_a$x"] <-
      "peer_b$x"
    expect_error(
      .capsule_test_build(wrong_owner), "names the wrong owner",
      info = paste("K =", k))
  }
})

test_that("qualified Gaussian references reject malformed owner bindings", {
  for (reference in c("peer_a$", "$x", "peer_a$$x")) {
    expect_error(
      .dsvert_dp_capsule_column_reference(reference, "test reference"),
      "Invalid biomedical capsule", info = reference)
  }
})
