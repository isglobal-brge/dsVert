.dp_describe_policy <- function(adjacency = "add_remove_patient",
                                capacity = 8L) {
  list(
    adjacency = adjacency,
    patient_column = "patient_id",
    unit_capacity = capacity,
    fixed_cohort_size = if (identical(
      adjacency, "replace_one_fixed_cohort")) capacity else NULL,
    max_records_per_unit = 4L,
    overflow_policy = "reject_snapshot",
    composition_partitions = 2L,
    numeric_grid_bits = 8L,
    numeric_bounds = list(x = c(0, 4), y = c(0, 8)))
}

.dp_describe_specs <- function() {
  list(primary = list(
    version = "v1",
    dataset = "protected",
    variables = c("x", "y"),
    histogram_grids = list(
      x = as.numeric(1:4),
      y = as.numeric(c(2, 4, 6, 8))),
    allocation = c(
      count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2)))
}

.dp_describe_data <- function() {
  data.frame(
    patient_id = paste0("p", 1:5),
    x = c(0.5, 1.5, 2.5, 3.5, NA_real_),
    y = c(1, 3, 5, 7, Inf),
    stringsAsFactors = FALSE)
}

test_that("describe spec fixes variables, grids, allocation and shape", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  spec <- .dsvert_dp_describe_spec(
    .dp_describe_policy(), "protected", "primary")
  expect_identical(spec$variables, c("x", "y"))
  expect_identical(spec$grid_lengths, c(4L, 4L))
  expect_identical(spec$coordinate_count, 16L)
  expect_equal(sum(spec$allocation_weights), 1, tolerance = 1e-15)
  expect_true(all(spec$allocation_weights > 0))
  expect_identical(spec$family_sensitivity, c(1, 256, 256, 1))
  expect_identical(spec$sum_family_l1_sensitivity_bound, 1028)

  malformed <- .dp_describe_specs()
  malformed$primary$allocation[["histogram"]] <- 0
  withr::local_options(list(dsvert.dp.describe_specs = malformed))
  expect_error(
    .dsvert_dp_describe_spec(
      .dp_describe_policy(), "protected", "primary"),
    "positive and sum to one")
})

test_that("integer sufficient statistics match the central no-noise oracle", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  policy <- .dp_describe_policy()
  spec <- .dsvert_dp_describe_spec(policy, "protected", "primary")
  exact <- .dsvert_dp_describe_statistics(
    .dp_describe_data(), policy, spec)
  expected_block <- c(
    4, 512, 336,
    1, 1, 1, 1, 1)
  expect_identical(exact, c(expected_block, expected_block))
  expect_true(all(exact == floor(exact)))
  expect_length(exact, spec$coordinate_count)
})

test_that("patient collapse clips before averaging and invalid values use a fixed bin", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  policy <- .dp_describe_policy()
  spec <- .dsvert_dp_describe_spec(policy, "protected", "primary")
  data <- rbind(
    data.frame(patient_id = "p1", x = -1e308, y = -1e308),
    data.frame(patient_id = "p1", x = 1e308, y = 1e308),
    data.frame(patient_id = "p2", x = NaN, y = NA_real_))
  exact <- .dsvert_dp_describe_statistics(data, policy, spec)
  x <- exact[1:8]
  y <- exact[9:16]
  # p1 averages the clipped endpoints; p2 enters the fixed invalid cell.
  expect_identical(x, c(1, 128, 64, 0, 1, 0, 0, 1))
  expect_identical(y, c(1, 128, 64, 0, 1, 0, 0, 1))
  expect_true(all(is.finite(exact)))
})

test_that("bounds and public endpoints map to fixed histogram bins", {
  specs <- .dp_describe_specs()
  specs$primary$variables <- "x"
  specs$primary$histogram_grids <- list(x = as.numeric(1:4))
  withr::local_options(list(dsvert.dp.describe_specs = specs))
  policy <- .dp_describe_policy()
  spec <- .dsvert_dp_describe_spec(policy, "protected", "primary")
  data <- data.frame(
    patient_id = paste0("p", 1:6),
    x = c(-Inf, 0, 1, 1 + .Machine$double.eps, 4, Inf))
  exact <- .dsvert_dp_describe_statistics(data, policy, spec)
  # Non-finite values are invalid; lower and the first endpoint are in bin 1.
  expect_identical(exact[4:8], c(2, 1, 0, 1, 2))
})

test_that("add-remove L1 sensitivity holds per patient and overall", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  policy <- .dp_describe_policy()
  spec <- .dsvert_dp_describe_spec(policy, "protected", "primary")
  data <- .dp_describe_data()
  baseline <- .dsvert_dp_describe_statistics(data, policy, spec)
  removed <- .dsvert_dp_describe_statistics(
    data[data$patient_id != "p4", , drop = FALSE], policy, spec)
  difference <- abs(baseline - removed)
  expect_lte(sum(difference), spec$sum_family_l1_sensitivity_bound)
  expect_lte(sum(difference[1:8]), sum(spec$family_sensitivity))
  expect_lte(sum(difference[9:16]), sum(spec$family_sensitivity))

  replaced_data <- data
  replaced_data[replaced_data$patient_id == "p4", c("x", "y")] <- 0
  replaced <- .dsvert_dp_describe_statistics(replaced_data, policy, spec)
  expect_lte(sum(abs(baseline - replaced)),
             2 * spec$sum_family_l1_sensitivity_bound)
})

test_that("invalid patient identifiers fail stable admission", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  policy <- .dp_describe_policy()
  spec <- .dsvert_dp_describe_spec(policy, "protected", "primary")
  data <- data.frame(
    patient_id = c("p1", NA_character_, NA_character_),
    x = c(4, 0, 4), y = c(8, 0, 8))
  expect_error(
    .dsvert_dp_describe_statistics(data, policy, spec),
    "custodian-owned DP admission contract")
})

test_that("histogram epsilon is per vector, never divided across bins", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  spec <- .dsvert_dp_describe_spec(
    .dp_describe_policy(), "protected", "primary")
  plan <- .dsvert_dp_describe_coordinate_plan(spec, epsilon = 0.25)
  expect_equal(
    spec$variable_count * sum(plan$family_epsilon), 0.25,
    tolerance = 1e-15)
  expect_equal(plan$family_epsilon, c(0.025, 0.0375, 0.0375, 0.025))
  expect_true(all(plan$epsilons[4:8] == plan$family_epsilon[[4L]]))
  expect_true(all(plan$epsilons[12:16] == plan$family_epsilon[[4L]]))
  # A tight upper-bound contribution (count=1, qsum=Q, qsumsq=Q,
  # one histogram cell=1) incurs exactly the four family epsilons per
  # variable. Sequential composition over p variables is exactly one slot.
  per_variable_privacy_loss <- sum(
    c(1, 256, 256, 1) * plan$family_epsilon /
      c(1, 256, 256, 1))
  expect_equal(
    spec$variable_count * per_variable_privacy_loss,
    0.25, tolerance = 1e-15)
})

test_that("public dimension and numeric guards fail before protected data", {
  specs <- .dp_describe_specs()
  specs$primary$variables <- "x"
  specs$primary$histogram_grids <- list(
    x = seq(4 / 1000000, 4, length.out = 1000000))
  withr::local_options(list(dsvert.dp.describe_specs = specs))
  expect_error(
    .dsvert_dp_describe_spec(
      .dp_describe_policy(), "protected", "primary"),
    "coordinate limit")
  protected_touched <- FALSE
  testthat::with_mocked_bindings(
    expect_error(
      dsvertDPDescribeDS("protected", "primary"),
      "coordinate limit"),
    .dsvert_dp_policy = function() .dp_describe_policy(),
    .dsvert_dp_get_data = function(...) {
      protected_touched <<- TRUE
      stop("protected data should not be resolved", call. = FALSE)
    },
    .package = "dsVert")
  expect_false(protected_touched)

  specs <- .dp_describe_specs()
  specs$primary$allocation <- c(
    count = 1e-320, sum = 0.3, sumsq = 0.3,
    histogram = 0.4 - 1e-320)
  withr::local_options(list(dsvert.dp.describe_specs = specs))
  expect_error(
    .dsvert_dp_describe_spec(
      .dp_describe_policy(), "protected", "primary"),
    "sampler domain")
})

test_that("describe endpoint uses one purpose-bound sticky callback", {
  withr::local_options(list(
    dsvert.dp.describe_specs = .dp_describe_specs()))
  policy <- .dp_describe_policy()
  data <- .dp_describe_data()
  cache <- new.env(parent = emptyenv())
  release_calls <- sampler_calls <- statistic_calls <- admission_calls <- 0L
  mechanism_seen <- NULL
  original_statistics <- .dsvert_dp_describe_statistics
  original_admission <- .dsvert_dp_admit_units
  release_mock <- function(policy, query_hash, dataset_ledger_key,
                           protected_fingerprint, mechanism, sensitivity,
                           release_fn, mechanism_epsilon_floor = 0,
                           uses_delta = FALSE, noise_context = NULL,
                           mechanism_plan = NULL) {
    release_calls <<- release_calls + 1L
    mechanism_seen <<- mechanism
    if (exists(query_hash, envir = cache, inherits = FALSE)) {
      return(get(query_hash, envir = cache, inherits = FALSE))
    }
    selected_plan <- list(
      selector = "minimum_conservative_95_radius_v3",
      winner = "laplace",
      certificate = list(winner_delta = 0))
    payload <- release_fn(
      epsilon = 0.25, delta = 0, seed = strrep("d", 64L),
      mechanism_plan = selected_plan)
    payload <- c(payload, list(
      privacy_epoch = 1, noise_key_id = "test-noise-key-v1",
      sticky_noise = "dsvert-sticky-noise-v1"))
    value <- list(
      payload = payload, memoized = FALSE, release_index = 0,
      epsilon = 0.25, delta = 0)
    assign(query_hash, value, envir = cache)
    value
  }
  sampler_mock <- function(values, epsilons, sensitivities, seed) {
    sampler_calls <<- sampler_calls + 1L
    expect_length(values, 16L)
    expect_identical(seed, strrep("d", 64L))
    radius <- ceiling(log(20) * sensitivities / epsilons)
    simultaneous <- ceiling(log(20 * length(values)) *
                              sensitivities / epsilons)
    list(
      values = values,
      accuracy_95_abs = radius,
      accuracy_simultaneous_95_abs = simultaneous,
      clipped_coordinates = 0L,
      mechanism =
        "dsvert_dp_v1_deterministic_granular_laplace_int64",
      implementation = paste0(
        "dsVert adapted Google Differential Privacy v4.1.0 ",
        "granular Laplace integer mechanism"),
      sampler = "deterministic_two_sided_geometric",
      randomness = "HMAC-SHA256/ChaCha20",
      simultaneous_confidence = 0.95,
      simultaneous_method = "union_bound")
  }
  evaluate <- function() dsvertDPDescribeDS("protected", "primary")
  result <- testthat::with_mocked_bindings(
    list(evaluate(), evaluate()),
    .dsvert_dp_policy = function() policy,
    .dsvert_dp_get_data = function(data_name, envir) data,
    .dsvert_dp_secret = function() "ledger-secret",
    .dsvert_dp_dataset_binding = function(...) list(
      public = list(id = "study", version = "v1"),
      ledger_key = paste0("dataset_snapshot_", strrep("b", 40L)),
      fingerprint = strrep("c", 64L)),
    .dsvert_dp_query_hash = function(secret, policy, dataset, method,
                                     arguments) {
      digest::digest(list(dataset, method, arguments), algo = "sha256")
    },
    .dsvert_dp_release = release_mock,
    .dsvert_dp_describe_statistics = function(...) {
      statistic_calls <<- statistic_calls + 1L
      original_statistics(...)
    },
    .dsvert_dp_admit_units = function(...) {
      admission_calls <<- admission_calls + 1L
      original_admission(...)
    },
    .dsvert_dp_noise_int64 = sampler_mock,
    .package = "dsVert")
  expect_identical(result[[1L]], result[[2L]])
  expect_identical(release_calls, 2L)
  expect_identical(statistic_calls, 1L)
  expect_identical(admission_calls, 1L)
  expect_identical(sampler_calls, 1L)
  expect_identical(
    mechanism_seen,
    "dsvert_sticky_minimum_conservative_95_radius_v3_pending")
  expect_equal(result[[1L]]$epsilon_allocation_sum, 0.25)
  expect_false(any(grepl(
    "exact|observed_min|observed_max|raw", names(result[[1L]]),
    ignore.case = TRUE)))
})
