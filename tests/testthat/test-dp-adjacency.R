.dp_adjacency_policy <- function(
    adjacency = "add_remove_patient", capacity = 1L,
    max_records = 2L) {
  list(
    adjacency = adjacency,
    patient_column = "patient_id",
    unit_capacity = as.integer(capacity),
    fixed_cohort_size = if (identical(
      adjacency, "replace_one_fixed_cohort")) as.integer(capacity) else NULL,
    max_records_per_unit = as.integer(max_records),
    overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L,
    numeric_bounds = list(x = c(0, 1)),
    categorical_levels = list(row = c("a", "b"), col = c("c", "d")))
}

test_that("contingency unit aggregation excludes only valid-cell conflicts", {
  policy <- .dp_adjacency_policy(capacity = 4L, max_records = 4L)
  data <- data.frame(
    patient_id = c(
      "p1", "p1", "p1",
      "p2", "p2", "p2",
      "p3", "p3",
      "p4", "p4"),
    row = c(
      "a", "a", NA,
      "a", "b", "outside",
      NA, "outside",
      "b", NA),
    col = c(
      "c", "c", "c",
      "c", "d", "c",
      "c", "outside",
      "d", "c"),
    stringsAsFactors = FALSE)

  bounded <- .dsvert_dp_bounded_pairs(data, policy, "row", "col")
  expect_identical(bounded$cell, c(1L, NA_integer_, NA_integer_, 4L))
  expect_identical(
    .dsvert_dp_bounded_pairs(
      data[rev(seq_len(nrow(data))), , drop = FALSE],
      policy, "row", "col")$cell,
    bounded$cell)
})

test_that("invalid numeric categories cannot select a contingency error branch", {
  policy <- .dp_adjacency_policy(capacity = 5L, max_records = 1L)
  data <- data.frame(
    patient_id = paste0("p", 1:5),
    row = c(1, 1.5, Inf, 2^53, 2^53 + 2),
    col = c(3, 3, 3, 4, 4))
  policy$categorical_levels <- list(
    row = c("1", "2"), col = c("3", "4"))

  bounded <- .dsvert_dp_bounded_pairs(data, policy, "row", "col")
  expect_identical(bounded$cell, c(1L, NA_integer_, NA_integer_,
                                    NA_integer_, NA_integer_))
  expect_length(bounded$cell, policy$unit_capacity)
})

.dp_pairwise_max <- function(values, distance) {
  if (length(values) < 2L) return(0)
  max(vapply(utils::combn(seq_along(values), 2L, simplify = FALSE),
             function(index) distance(values[[index[[1L]]]],
                                      values[[index[[2L]]]]),
             numeric(1L)))
}

test_that("admission has one generic failure and a capacity-shaped result", {
  policy <- .dp_adjacency_policy(capacity = 4L, max_records = 2L)
  data <- data.frame(
    patient_id = c("p2", "p1", "p2"), stringsAsFactors = FALSE)
  admitted <- .dsvert_dp_admit_units(data, policy)
  expect_identical(admitted$group, c(2L, 1L, 2L))
  expect_identical(admitted$present, c(TRUE, TRUE, FALSE, FALSE))
  expect_identical(admitted$record_count, c(1L, 2L, 0L, 0L))
  expect_identical(admitted$unit_count, 2L)
  expect_identical(admitted$work_units, 4L)

  failures <- list(
    data.frame(patient_id = paste0("p", 1:5)),
    data.frame(patient_id = c("p1", "p1", "p1")),
    data.frame(patient_id = c("p1", NA_character_)),
    data.frame(patient_id = c("p1", "  ")))
  messages <- vapply(failures, function(value) {
    conditionMessage(tryCatch(
      .dsvert_dp_admit_units(value, policy), error = identity))
  }, character(1L))
  expect_length(unique(messages), 1L)
  expect_identical(
    messages[[1L]],
    "The protected snapshot does not satisfy its custodian-owned DP admission contract")

  replacement <- .dp_adjacency_policy(
    "replace_one_fixed_cohort", capacity = 2L, max_records = 2L)
  expect_identical(
    .dsvert_dp_admit_units(
      data.frame(patient_id = c("p2", "p1")), replacement)$unit_count,
    2L)
  replacement_message <- conditionMessage(tryCatch(
    .dsvert_dp_admit_units(data.frame(patient_id = "p1"), replacement),
    error = identity))
  expect_identical(replacement_message, messages[[1L]])
})

test_that("privacy-unit identifiers are canonical across R formatting options", {
  numeric_ids <- c(10000000, 1, 10000000)
  first <- withr::with_options(
    list(scipen = -9, digits = 3, OutDec = ","),
    .dsvert_canonical_label_values(numeric_ids))
  second <- withr::with_options(
    list(scipen = 100, digits = 15, OutDec = "."),
    .dsvert_canonical_label_values(numeric_ids))
  expect_identical(first, c("10000000", "1", "10000000"))
  expect_identical(second, first)

  policy <- .dp_adjacency_policy(capacity = 4L, max_records = 2L)
  admitted <- .dsvert_dp_admit_units(
    data.frame(patient_id = numeric_ids), policy)
  expect_identical(admitted$group, c(2L, 1L, 2L))
  expect_error(
    .dsvert_dp_admit_units(
      data.frame(patient_id = c(1, 1.5)), policy),
    "custodian-owned DP admission contract")
  expect_error(
    .dsvert_dp_admit_units(
      data.frame(patient_id = c(1, 2^53)), policy),
    "custodian-owned DP admission contract")
})

test_that("categorical tolerance never weakens privacy-unit identifiers", {
  withr::local_seed(20260809)
  policy <- .dp_adjacency_policy(capacity = 2L, max_records = 1L)
  invalid_ids <- c(
    sample(-1000000:1000000, 200L, replace = TRUE) +
      rep(c(0.25, 0.5, 0.75, 0.125), 50L),
    NA_real_, NaN, Inf, -Inf, 2^53, -2^53)
  messages <- vapply(invalid_ids, function(value) {
    conditionMessage(tryCatch(
      .dsvert_dp_admit_units(
        data.frame(patient_id = c(1, value)), policy),
      error = identity))
  }, character(1L))
  expect_identical(
    unique(messages),
    "The protected snapshot does not satisfy its custodian-owned DP admission contract")

  categories <- c(-2^53, -2, -0, 1, 2^53 - 1, 1.25, Inf, NaN, 2^53)
  render <- function(locale, digits, scipen, outdec) {
    suppressWarnings(withr::with_locale(
      c(LC_NUMERIC = locale),
      withr::with_options(
        list(digits = digits, scipen = scipen, OutDec = outdec),
        .dsvert_dp_categorical_label_values(categories, "categories"))))
  }
  baseline <- render("C", 3, -9, ",")
  candidates <- c("fr_FR.UTF-8", "de_DE.UTF-8", "es_ES.UTF-8")
  available <- candidates[vapply(candidates, function(locale) {
    !is.null(suppressWarnings(tryCatch(
      withr::with_locale(c(LC_NUMERIC = locale),
                         Sys.getlocale("LC_NUMERIC")),
      error = function(e) NULL)))
  }, logical(1L))]
  alternate <- if (length(available)) available[[1L]] else "C"
  changed <- render(alternate, 15, 999, ".")

  expect_identical(changed, baseline)
  expect_identical(
    baseline,
    c(NA_character_, "-2", "0", "1", "9007199254740991",
      NA_character_, NA_character_, NA_character_, NA_character_))
})

test_that("finite categorical unit domain exhaustively satisfies both adjacencies", {
  atoms <- data.frame(
    row = c("a", "a", "b", "outside", NA_character_),
    col = c("c", "d", "d", "c", "c"),
    stringsAsFactors = FALSE)
  sequences <- c(
    lapply(seq_len(nrow(atoms)), function(i) i),
    lapply(seq_len(nrow(atoms)^2), function(i) {
      as.integer(arrayInd(i, c(nrow(atoms), nrow(atoms))))
    }))
  unit_data <- lapply(sequences, function(index) {
    data.frame(
      patient_id = rep("p1", length(index)),
      row = atoms$row[index], col = atoms$col[index],
      stringsAsFactors = FALSE)
  })
  statistic <- function(data, adjacency) {
    policy <- .dp_adjacency_policy(adjacency)
    bounded <- .dsvert_dp_bounded_pairs(data, policy, "row", "col")
    expect_length(bounded$cell, policy$unit_capacity)
    tabulate(bounded$cell, nbins = bounded$cell_count)
  }
  add_values <- lapply(unit_data, statistic, "add_remove_patient")
  expect_lte(max(vapply(add_values, function(x) sum(abs(x)), numeric(1L))), 1)
  replace_values <- lapply(
    unit_data, statistic, "replace_one_fixed_cohort")
  expect_lte(.dp_pairwise_max(
    replace_values, function(x, y) sum(abs(x - y))), 2)
})

test_that("finite numeric unit domain exhaustively satisfies moment bounds", {
  atoms <- c(NA_real_, -1, 0, 0.5, 1, 2, Inf)
  sequences <- c(
    lapply(seq_along(atoms), function(i) i),
    lapply(seq_len(length(atoms)^2), function(i) {
      as.integer(arrayInd(i, c(length(atoms), length(atoms))))
    }))
  unit_data <- lapply(sequences, function(index) {
    data.frame(patient_id = rep("p1", length(index)), x = atoms[index])
  })
  statistic <- function(data, adjacency) {
    policy <- .dp_adjacency_policy(adjacency)
    bounded <- .dsvert_dp_bounded_numeric(data, policy, "x")
    expect_length(bounded$unit_values, policy$unit_capacity)
    .dsvert_dp_quantized_moments(
      bounded$values, policy$numeric_grid_bits)$statistics
  }
  bound <- c(1, 256, 256)
  add_values <- lapply(unit_data, statistic, "add_remove_patient")
  expect_true(all(vapply(add_values, function(x) all(abs(x) <= bound),
                         logical(1L))))
  replace_values <- lapply(
    unit_data, statistic, "replace_one_fixed_cohort")
  expect_lte(.dp_pairwise_max(
    replace_values,
    function(x, y) max(abs(x - y) / bound)), 1)
})

test_that("finite describe domain exhaustively satisfies every family bound", {
  atoms <- c(NA_real_, -1, 0, 0.5, 1, 2, Inf)
  sequences <- c(
    lapply(seq_along(atoms), function(i) i),
    lapply(seq_len(length(atoms)^2), function(i) {
      as.integer(arrayInd(i, c(length(atoms), length(atoms))))
    }))
  unit_data <- lapply(sequences, function(index) {
    data.frame(patient_id = rep("p1", length(index)), x = atoms[index])
  })
  spec <- list(
    variables = "x", variable_count = 1L,
    lower_bounds = 0, upper_bounds = 1,
    histogram_grids = list(c(0.5, 1)), grid_lengths = 2L,
    numeric_grid_scale = 256,
    coordinate_count = 6L)
  statistic <- function(data, adjacency) {
    .dsvert_dp_describe_statistics(
      data, .dp_adjacency_policy(adjacency), spec)
  }
  check_difference <- function(x, y, histogram_bound) {
    difference <- abs(x - y)
    all(difference[1:3] <= c(1, 256, 256)) &&
      sum(difference[4:6]) <= histogram_bound
  }
  absent <- rep(0, spec$coordinate_count)
  add_values <- lapply(unit_data, statistic, "add_remove_patient")
  expect_true(all(vapply(
    add_values, check_difference, logical(1L), y = absent,
    histogram_bound = 1)))
  replace_values <- lapply(
    unit_data, statistic, "replace_one_fixed_cohort")
  expect_lte(.dp_pairwise_max(
    replace_values,
    function(x, y) if (check_difference(x, y, 2)) 0 else 1), 0)
})

test_that("finite survival domain exhaustively satisfies declared L1 bounds", {
  times <- c(NA_real_, 0, 1, 2)
  outcomes <- c(NA_character_, "0", "A", "outside")
  entries <- c(NA_real_, 0, 1, 2)
  for (delayed in c(FALSE, TRUE)) {
    domain <- if (delayed) {
      expand.grid(time = times, status = outcomes, entry = entries,
                  stringsAsFactors = FALSE)
    } else {
      expand.grid(time = times, status = outcomes,
                  stringsAsFactors = FALSE)
    }
    spec <- list(
      time = "time", event = "status",
      entry = if (delayed) "entry" else NULL,
      censor = "0", outcome_levels = c("0", "A"),
      time_grid = c(1, 2), time_bounds = c(0, 2),
      delayed_entry = delayed,
      coordinate_count = if (delayed) 7L else 5L)
    values <- lapply(seq_len(nrow(domain)), function(index) {
      data <- domain[index, , drop = FALSE]
      data$patient_id <- "p1"
      data <- data[c("patient_id", setdiff(names(data), "patient_id"))]
      .dsvert_dp_survival_histogram(
        data, .dp_adjacency_policy("replace_one_fixed_cohort"), spec)$exact
    })
    add_bound <- if (delayed) 2 else 1
    expect_lte(max(vapply(values, function(x) sum(abs(x)), numeric(1L))),
               add_bound)
    expect_lte(.dp_pairwise_max(
      values, function(x, y) sum(abs(x - y))), 2 * add_bound)
  }
})

test_that("random multi-record privacy units preserve every declared sensitivity", {
  withr::local_seed(20260804)
  add_policy <- .dp_adjacency_policy(
    "add_remove_patient", capacity = 1L, max_records = 5L)
  replace_policy <- .dp_adjacency_policy(
    "replace_one_fixed_cohort", capacity = 1L, max_records = 5L)

  categorical_atoms <- data.frame(
    row = c("a", "a", "b", "outside", NA_character_),
    col = c("c", "d", "d", "c", "c"),
    stringsAsFactors = FALSE)
  numeric_atoms <- c(NA_real_, -1, 0, 0.2, 0.8, 1, 2, Inf)
  describe_spec <- list(
    variables = "x", variable_count = 1L,
    lower_bounds = 0, upper_bounds = 1,
    histogram_grids = list(c(0.25, 0.5, 0.75, 1)),
    grid_lengths = 4L, numeric_grid_scale = 256,
    coordinate_count = 8L)
  survival_specs <- lapply(c(FALSE, TRUE), function(delayed) {
    list(
      time = "time", event = "status",
      entry = if (delayed) "entry" else NULL,
      censor = "0", outcome_levels = c("0", "A"),
      time_grid = c(1, 2), time_bounds = c(0, 2),
      delayed_entry = delayed,
      coordinate_count = if (delayed) 7L else 5L)
  })

  table_statistic <- function(data, policy) {
    bounded <- .dsvert_dp_bounded_pairs(data, policy, "row", "col")
    tabulate(bounded$cell, nbins = bounded$cell_count)
  }
  moment_statistic <- function(data, policy) {
    bounded <- .dsvert_dp_bounded_numeric(data, policy, "x")
    .dsvert_dp_quantized_moments(
      bounded$values, policy$numeric_grid_bits)$statistics
  }
  describe_statistic <- function(data, policy) {
    .dsvert_dp_describe_statistics(data, policy, describe_spec)
  }
  survival_statistic <- function(data, policy, spec) {
    .dsvert_dp_survival_histogram(data, policy, spec)$exact
  }

  valid <- logical(400L)
  for (iteration in seq_along(valid)) {
    first_index <- sample.int(nrow(categorical_atoms), sample.int(5L, 1L),
                              replace = TRUE)
    second_index <- sample.int(nrow(categorical_atoms), sample.int(5L, 1L),
                               replace = TRUE)
    first_table <- data.frame(
      patient_id = "p1", categorical_atoms[first_index, ],
      row.names = NULL, stringsAsFactors = FALSE)
    second_table <- data.frame(
      patient_id = "p1", categorical_atoms[second_index, ],
      row.names = NULL, stringsAsFactors = FALSE)
    first_counts <- table_statistic(first_table, add_policy)
    table_ok <- sum(abs(first_counts)) <= 1 &&
      sum(abs(table_statistic(first_table, replace_policy) -
                table_statistic(second_table, replace_policy))) <= 2

    make_numeric <- function() {
      data.frame(
        patient_id = "p1",
        x = sample(numeric_atoms, sample.int(5L, 1L), replace = TRUE))
    }
    first_numeric <- make_numeric()
    second_numeric <- make_numeric()
    moment_bound <- c(1, 256, 256)
    first_moments <- moment_statistic(first_numeric, add_policy)
    moments_ok <- all(abs(first_moments) <= moment_bound) &&
      all(abs(moment_statistic(first_numeric, replace_policy) -
                moment_statistic(second_numeric, replace_policy)) <=
            moment_bound)

    first_describe <- describe_statistic(first_numeric, add_policy)
    describe_difference <- abs(
      describe_statistic(first_numeric, replace_policy) -
        describe_statistic(second_numeric, replace_policy))
    describe_ok <- all(first_describe[1:3] <= moment_bound) &&
      sum(first_describe[4:8]) <= 1 &&
      all(describe_difference[1:3] <= moment_bound) &&
      sum(describe_difference[4:8]) <= 2

    survival_ok <- TRUE
    for (spec in survival_specs) {
      make_survival <- function() {
        size <- sample.int(5L, 1L)
        value <- data.frame(
          patient_id = "p1",
          time = sample(c(NA_real_, -1, 0, 0.5, 1, 2, 3, Inf),
                        size, replace = TRUE),
          status = sample(c(NA_character_, "0", "A", "outside"),
                          size, replace = TRUE),
          stringsAsFactors = FALSE)
        if (spec$delayed_entry) {
          value$entry <- sample(
            c(NA_real_, -1, 0, 0.5, 1, 2, 3, Inf),
            size, replace = TRUE)
        }
        value
      }
      first_survival <- make_survival()
      second_survival <- make_survival()
      add_bound <- if (spec$delayed_entry) 2 else 1
      survival_ok <- survival_ok &&
        sum(abs(survival_statistic(
          first_survival, add_policy, spec))) <= add_bound &&
        sum(abs(
          survival_statistic(first_survival, replace_policy, spec) -
            survival_statistic(second_survival, replace_policy, spec))) <=
          2 * add_bound
    }
    valid[[iteration]] <-
      table_ok && moments_ok && describe_ok && survival_ok
  }
  expect_true(all(valid))
})
