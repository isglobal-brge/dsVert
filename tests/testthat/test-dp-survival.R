.dp_survival_policy <- function(delayed_entry = FALSE,
                                adjacency = "add_remove_patient",
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
    numeric_bounds = list(time = c(0, 4), entry = c(0, 4)),
    categorical_levels = list(status = c("0", "A", "B")))
}

.dp_survival_specs <- function(delayed_entry = FALSE) {
  list(primary = list(
    version = "v1", dataset = "protected", time = "time",
    event = "status", censor = "0", time_grid = 1:4,
    entry = if (delayed_entry) "entry" else NULL))
}

.dp_survival_data <- function(delayed_entry = FALSE) {
  result <- data.frame(
    patient_id = c("p1", "p1", "p2", "p3", "p4"),
    time = c(4, 2, 3, 4, NA_real_),
    status = c("0", "A", "0", "B", "unknown"),
    stringsAsFactors = FALSE)
  if (delayed_entry) result$entry <- c(0, 0, 1.2, 2.2, 0)
  result
}

test_that("custodian survival specs fix the public shape and sensitivity", {
  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(FALSE)))
  spec <- .dsvert_dp_survival_spec(
    .dp_survival_policy(FALSE), "protected", "primary")
  expect_identical(spec$time_grid, as.numeric(1:4))
  expect_identical(spec$causes, c("A", "B"))
  expect_false(spec$delayed_entry)
  expect_identical(spec$coordinate_count, 13L)
  expect_identical(spec$l1_sensitivity, 1L)

  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(TRUE)))
  delayed <- .dsvert_dp_survival_spec(
    .dp_survival_policy(TRUE), "protected", "primary")
  expect_true(delayed$delayed_entry)
  expect_identical(delayed$coordinate_count, 17L)
  expect_identical(delayed$l1_sensitivity, 2L)

  malformed <- .dp_survival_specs(FALSE)
  malformed$primary$time_grid <- c(1, 3, 2, 4)
  withr::local_options(list(dsvert.dp.survival_specs = malformed))
  expect_error(
    .dsvert_dp_survival_spec(
      .dp_survival_policy(FALSE), "protected", "primary"),
    "time grid is invalid")
})

test_that("public lower, endpoint, and upper times have fixed ceiling bins", {
  grid <- as.numeric(1:4)
  values <- c(0, 1, 1 + .Machine$double.eps, 2, 3.5, 4)
  expect_identical(
    .dsvert_dp_survival_ceiling_bin(values, grid),
    c(1L, 1L, 2L, 2L, 4L, 4L))
})

test_that("each patient has one fixed exit contribution and no exact release", {
  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(FALSE)))
  policy <- .dp_survival_policy(FALSE)
  spec <- .dsvert_dp_survival_spec(policy, "protected", "primary")
  histogram <- .dsvert_dp_survival_histogram(
    .dp_survival_data(FALSE), policy, spec)
  exit <- matrix(histogram$exact[1:12], nrow = 4L,
                 dimnames = list(NULL, c("0", "A", "B")))
  expect_identical(exit[, "0"], c(0, 0, 1, 0))
  expect_identical(exit[, "A"], c(0, 1, 0, 0))
  expect_identical(exit[, "B"], c(0, 0, 0, 1))
  expect_identical(histogram$exact[[13L]], 1)
  expect_identical(sum(histogram$exact), 4)
  expect_length(histogram$exact, spec$coordinate_count)

  changed <- .dp_survival_data(FALSE)
  changed$time[] <- c(Inf, -Inf, NA, NaN, 1e300)
  changed$status[] <- NA_character_
  invalid <- .dsvert_dp_survival_histogram(changed, policy, spec)
  expect_length(invalid$exact, spec$coordinate_count)
  expect_identical(sum(invalid$exact), 4)
  expect_identical(invalid$exact[[13L]], 4)

  missing_id <- .dp_survival_data(FALSE)
  missing_id$patient_id[1:2] <- NA_character_
  expect_error(
    .dsvert_dp_survival_histogram(missing_id, policy, spec),
    "custodian-owned DP admission contract")
})

test_that("invalid numeric outcomes enter the fixed survival quality bin", {
  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(FALSE)))
  policy <- .dp_survival_policy(FALSE, capacity = 5L)
  policy$categorical_levels$status <- c("0", "1")
  spec <- .dsvert_dp_survival_spec(policy, "protected", "primary")
  data <- data.frame(
    patient_id = paste0("p", 1:5),
    time = rep(1, 5L),
    status = c(0, 1, 1.5, Inf, 2^53 + 2))

  histogram <- .dsvert_dp_survival_histogram(data, policy, spec)
  expect_length(histogram$exact, spec$coordinate_count)
  expect_identical(histogram$exact[[spec$coordinate_count]], 3)
  expect_identical(sum(histogram$exact), 5)
})

test_that("left-truncated patients touch at most two fixed coordinates", {
  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(TRUE)))
  policy <- .dp_survival_policy(TRUE)
  spec <- .dsvert_dp_survival_spec(policy, "protected", "primary")
  histogram <- .dsvert_dp_survival_histogram(
    .dp_survival_data(TRUE), policy, spec)
  entry <- histogram$exact[1:4]
  exit <- matrix(histogram$exact[5:16], nrow = 4L)
  invalid <- histogram$exact[[17L]]
  expect_identical(entry, c(1, 1, 1, 0))
  expect_identical(colSums(exit), c(1, 1, 1))
  expect_identical(invalid, 1)
  expect_identical(sum(histogram$exact), 7)
  expect_identical(spec$l1_sensitivity, 2L)

  repeated <- data.frame(
    patient_id = c("p1", "p1"),
    time = c(1, 3), status = c("A", "B"), entry = c(2, 1),
    stringsAsFactors = FALSE)
  repeated_histogram <- .dsvert_dp_survival_histogram(
    repeated, policy, spec)
  repeated_exit <- matrix(
    repeated_histogram$exact[5:16], nrow = 4L,
    dimnames = list(NULL, c("0", "A", "B")))
  expect_identical(repeated_histogram$exact[1:4], c(1, 0, 0, 0))
  expect_identical(repeated_exit[, "B"], c(0, 0, 1, 0))
  expect_identical(repeated_histogram$exact[[17L]], 0)
})

test_that("add-remove and replacement L1 bounds match the declared adjacency", {
  for (delayed in c(FALSE, TRUE)) {
    withr::local_options(list(
      dsvert.dp.survival_specs = .dp_survival_specs(delayed)))
    policy <- .dp_survival_policy(delayed)
    spec <- .dsvert_dp_survival_spec(policy, "protected", "primary")
    data <- .dp_survival_data(delayed)
    baseline <- .dsvert_dp_survival_histogram(data, policy, spec)$exact

    removed <- data[data$patient_id != "p2", , drop = FALSE]
    removed_histogram <-
      .dsvert_dp_survival_histogram(removed, policy, spec)$exact
    expect_lte(sum(abs(baseline - removed_histogram)),
               spec$l1_sensitivity)

    replaced <- data
    replaced$time[replaced$patient_id == "p2"] <- 1
    replaced$status[replaced$patient_id == "p2"] <- "A"
    replacement_histogram <-
      .dsvert_dp_survival_histogram(replaced, policy, spec)$exact
    # The configured contract is add/remove adjacency. Replacing a whole unit
    # is two adjacent operations and therefore has the corresponding group-
    # privacy bound, not the single add/remove bound.
    expect_lte(sum(abs(baseline - replacement_histogram)),
               2 * spec$l1_sensitivity)
  }
})

test_that("the endpoint uses one sticky joint release and fixed transcript", {
  withr::local_options(list(
    dsvert.dp.survival_specs = .dp_survival_specs(FALSE)))
  policy <- .dp_survival_policy(FALSE)
  data <- .dp_survival_data(FALSE)
  cache <- new.env(parent = emptyenv())
  sampler_calls <- 0L
  histogram_calls <- admission_calls <- 0L
  release_calls <- 0L
  original_histogram <- .dsvert_dp_survival_histogram
  original_admission <- .dsvert_dp_admit_units
  release_mock <- function(policy, query_hash, dataset_ledger_key,
                           protected_fingerprint, mechanism, sensitivity,
                           release_fn, mechanism_epsilon_floor = 0,
                           uses_delta = FALSE, noise_context = NULL,
                           mechanism_plan = NULL) {
    release_calls <<- release_calls + 1L
    if (exists(query_hash, envir = cache, inherits = FALSE)) {
      return(get(query_hash, envir = cache, inherits = FALSE))
    }
    selected_plan <- list(
      selector = "minimum_conservative_95_radius_v3",
      winner = "laplace",
      certificate = list(winner_delta = 0))
    payload <- release_fn(
      epsilon = 0.25, delta = 0, seed = strrep("a", 64L),
      mechanism_plan = selected_plan)
    payload <- c(payload, list(
      privacy_epoch = 1, noise_key_id = "test-noise-key-v1",
      sticky_noise = "dsvert-sticky-noise-v1"))
    value <- list(payload = payload, memoized = FALSE,
                  release_index = 0, epsilon = 0.25, delta = 0)
    assign(query_hash, value, envir = cache)
    value
  }
  sampler_mock <- function(values, epsilons, sensitivities, seed) {
    sampler_calls <<- sampler_calls + 1L
    expect_identical(unique(sensitivities), 1L)
    expect_length(values, 13L)
    list(
      values = values,
      accuracy_95_abs = rep(12, length(values)),
      accuracy_simultaneous_95_abs = rep(23, length(values)),
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
  query_mock <- function(secret, policy, dataset, method, arguments) {
    digest::digest(
      list(dataset, method, arguments), algo = "sha256", serialize = TRUE)
  }
  evaluate <- function() {
    dsvertDPSurvivalDS("protected", "primary")
  }
  result <- testthat::with_mocked_bindings(
    list(evaluate(), evaluate()),
    .dsvert_dp_policy = function() policy,
    .dsvert_dp_get_data = function(data_name, envir) data,
    .dsvert_dp_secret = function() "ledger-secret",
    .dsvert_dp_dataset_binding = function(...) list(
      public = list(id = "study", version = "v1"),
      ledger_key = paste0("dataset_snapshot_", strrep("b", 40L)),
      fingerprint = strrep("c", 64L)),
    .dsvert_dp_query_hash = query_mock,
    .dsvert_dp_release = release_mock,
    .dsvert_dp_survival_histogram = function(...) {
      histogram_calls <<- histogram_calls + 1L
      original_histogram(...)
    },
    .dsvert_dp_admit_units = function(...) {
      admission_calls <<- admission_calls + 1L
      original_admission(...)
    },
    .dsvert_dp_noise_int64 = sampler_mock,
    .package = "dsVert")
  expect_identical(result[[1L]], result[[2L]])
  expect_identical(release_calls, 2L)
  expect_identical(histogram_calls, 1L)
  expect_identical(admission_calls, 1L)
  expect_identical(sampler_calls, 1L)
  expect_false(any(grepl("exact|raw|cohort_size|event_count|risk_set",
                         names(result[[1L]]), ignore.case = TRUE)))
  expect_identical(result[[1L]]$histogram,
                   c(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1))
})
