.dp_transcript_policy <- function() {
  list(
    adjacency = "add_remove_patient",
    patient_column = "patient_id",
    unit_capacity = 4L,
    fixed_cohort_size = NULL,
    max_records_per_unit = 1L,
    overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    composition_partitions = 2L,
    numeric_grid_bits = 8L,
    numeric_bounds = list(x = c(0, 1), time = c(0, 2)),
    categorical_levels = list(
      row = c("1", "2"), col = c("1", "2"),
      status = c("0", "1")))
}

.dp_transcript_data <- function(neighbor = FALSE) {
  data <- data.frame(
    patient_id = c("p1", "p2"),
    row = c(1, 2), col = c(1, 2),
    x = c(0.25, 0.75),
    time = c(1, 2), status = c(0, 1),
    stringsAsFactors = FALSE)
  if (isTRUE(neighbor)) {
    data <- rbind(data, data.frame(
      patient_id = "p3",
      row = 1.5, col = Inf,
      x = NaN, time = Inf, status = 1.5,
      stringsAsFactors = FALSE))
  }
  data
}

.dp_transcript_shape <- function(value) {
  if (is.null(value)) return(list(kind = "NULL"))
  if (is.list(value)) {
    return(list(
      kind = "list", names = names(value),
      fields = lapply(value, .dp_transcript_shape)))
  }
  list(kind = typeof(value), length = length(value), dim = dim(value))
}

.dp_transcript_run <- function(endpoint, data) {
  policy <- .dp_transcript_policy()
  events <- character()
  original_admission <- .dsvert_dp_admit_units
  release_mock <- function(
      policy, query_hash, dataset_ledger_key, protected_fingerprint,
      mechanism, sensitivity, release_fn, mechanism_epsilon_floor = 0,
      uses_delta = FALSE, noise_context = NULL, mechanism_plan = NULL) {
    events <<- c(events, "release")
    plan <- list(
      selector = "minimum_conservative_95_radius_v3",
      winner = "laplace",
      certificate = list(
        selector = "minimum_conservative_95_radius_v3",
        winner = "laplace"))
    payload <- release_fn(
      epsilon = 0.25, delta = 0, seed = strrep("a", 64L),
      mechanism_plan = plan)
    list(
      payload = c(payload, list(
        privacy_epoch = 1,
        noise_key_id = "transcript-test-key",
        sticky_noise = "dsvert-sticky-noise-v1")),
      memoized = FALSE, release_index = 0,
      epsilon = 0.25, delta = 0)
  }
  sampler_mock <- function(
      values, laplace_epsilons, laplace_sensitivities,
      epsilon, delta, l2_sensitivity, seed, mechanism_plan) {
    events <<- c(events, paste0("sample:", length(values)))
    expect_true(all(is.finite(values)))
    expect_true(all(values == trunc(values)))
    expect_length(laplace_epsilons, length(values))
    expect_length(laplace_sensitivities, length(values))
    list(
      values = unname(as.numeric(values)),
      accuracy_95_abs = rep(1, length(values)),
      accuracy_simultaneous_95_abs = rep(2, length(values)),
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
  evaluate <- switch(endpoint,
    count = function() dsvertDPCountDS("protected"),
    contingency = function() {
      dsvertDPContingencyDS("protected", "row", "col")
    },
    meanvar = function() dsvertDPMeanVarDS("protected", "x"),
    describe = function() dsvertDPDescribeDS("protected", "primary"),
    survival = function() dsvertDPSurvivalDS("protected", "primary"))

  result <- testthat::with_mocked_bindings(
    evaluate(),
    .dsvert_dp_policy = function() policy,
    .dsvert_dp_secret = function() as.raw(0:31),
    .dsvert_dp_resolve_snapshot = function(...) list(
      data = data,
      dataset = list(
        public = list(data_name = "protected", id = "cohort", version = "v1"),
        ledger_key = paste0("dataset_snapshot_", strrep("b", 40L)),
        fingerprint = strrep("c", 64L))),
    .dsvert_dp_query_hash = function(...) strrep("d", 64L),
    .dsvert_dp_release = release_mock,
    .dsvert_dp_admit_units = function(...) {
      events <<- c(events, "admit")
      original_admission(...)
    },
    .dsvert_dp_sample_selected_int64 = sampler_mock,
    .package = "dsVert")
  list(result = result, events = events)
}

test_that("promoted DP value domains have fixed endpoint transcript shapes", {
  withr::local_options(list(
    dsvert.dp.describe_specs = list(primary = list(
      version = "v1", dataset = "protected", variables = "x",
      histogram_grids = list(x = c(0.5, 1)),
      allocation = c(
        count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2))),
    dsvert.dp.survival_specs = list(primary = list(
      version = "v1", dataset = "protected", time = "time",
      event = "status", censor = "0", time_grid = c(1, 2),
      entry = NULL))))
  expected_coordinates <- c(
    count = 1L, contingency = 4L, meanvar = 3L,
    describe = 6L, survival = 5L)

  for (endpoint in names(expected_coordinates)) {
    baseline <- .dp_transcript_run(endpoint, .dp_transcript_data(FALSE))
    neighbor <- .dp_transcript_run(endpoint, .dp_transcript_data(TRUE))
    expected_events <- c(
      "release", "admit",
      paste0("sample:", expected_coordinates[[endpoint]]))
    expect_identical(baseline$events, expected_events, info = endpoint)
    expect_identical(neighbor$events, expected_events, info = endpoint)
    expect_identical(
      .dp_transcript_shape(baseline$result),
      .dp_transcript_shape(neighbor$result),
      info = endpoint)
  }
})
