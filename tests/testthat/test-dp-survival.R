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
