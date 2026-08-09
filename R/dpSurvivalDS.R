# Fixed-grid, patient-bounded differential-private survival histogram.

.dsvert_dp_survival_spec <- function(
    policy, data_name, analysis_id,
    specs = .dsvert_dp_option("survival_specs", NULL)) {
  analysis_id <- .dsvert_dp_scalar_string(analysis_id, "analysis_id")
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", analysis_id)) {
    stop("analysis_id contains unsupported characters", call. = FALSE)
  }
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    stop("dsvert.dp.survival_specs must be a uniquely named list",
         call. = FALSE)
  }
  spec <- specs[[analysis_id]]
  expected <- c(
    "version", "dataset", "time", "event", "censor", "time_grid",
    "entry")
  if (!is.list(spec) || is.null(names(spec)) || anyNA(names(spec)) ||
      anyDuplicated(names(spec)) || !setequal(names(spec), expected)) {
    stop("The requested custodian survival specification is unavailable",
         call. = FALSE)
  }
  scalar <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      nzchar(value)
  }
  if (!all(vapply(spec[c("version", "dataset", "time", "event", "censor")],
                  scalar, logical(1L))) ||
      (!is.null(spec$entry) && !scalar(spec$entry)) ||
      !identical(spec$dataset, data_name)) {
    stop("The requested custodian survival specification is invalid",
         call. = FALSE)
  }
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", spec$version)) {
    stop("The custodian survival specification version is invalid",
         call. = FALSE)
  }

  time_bounds <- policy$numeric_bounds[[spec$time]]
  entry_bounds <- if (is.null(spec$entry)) NULL else
    policy$numeric_bounds[[spec$entry]]
  grid <- spec$time_grid
  if (!is.numeric(grid) || length(grid) < 1L || anyNA(grid) ||
      any(!is.finite(grid)) || any(diff(grid) <= 0) ||
      length(grid) > .DSVERT_DP_MAX_COORDINATES ||
      is.null(time_bounds) || !is.numeric(time_bounds) ||
      length(time_bounds) != 2L || anyNA(time_bounds) ||
      any(!is.finite(time_bounds)) || time_bounds[[1L]] >= grid[[1L]] ||
      !isTRUE(all.equal(
        grid[[length(grid)]], time_bounds[[2L]], tolerance = 0))) {
    stop("The custodian survival time grid is invalid", call. = FALSE)
  }
  if (!is.null(spec$entry) &&
      (is.null(entry_bounds) || !is.numeric(entry_bounds) ||
       length(entry_bounds) != 2L || anyNA(entry_bounds) ||
       any(!is.finite(entry_bounds)) ||
       !isTRUE(all.equal(entry_bounds, time_bounds, tolerance = 0)))) {
    stop("Entry and exit time must share the custodian survival bounds",
         call. = FALSE)
  }

  outcome_domain <- policy$categorical_levels[[spec$event]]
  if (!is.character(outcome_domain) || !length(outcome_domain) ||
      anyNA(outcome_domain) || any(!nzchar(outcome_domain)) ||
      anyDuplicated(outcome_domain) || !spec$censor %in% outcome_domain) {
    stop("The custodian survival outcome domain is invalid", call. = FALSE)
  }
  causes <- outcome_domain[outcome_domain != spec$censor]
  if (!length(causes)) {
    stop("The custodian survival outcome domain has no event cause",
         call. = FALSE)
  }
  outcome_levels <- c(spec$censor, causes)
  time_count <- length(grid)
  delayed_entry <- !is.null(spec$entry)
  base_coordinates <- time_count * length(outcome_levels)
  coordinate_count <- base_coordinates + 1 +
    if (delayed_entry) time_count else 0
  if (!is.finite(coordinate_count) ||
      coordinate_count > .DSVERT_DP_MAX_COORDINATES ||
      coordinate_count > .Machine$integer.max) {
    stop("The fixed survival histogram exceeds the DP coordinate limit",
         call. = FALSE)
  }

  max_cells_per_unit <- if (delayed_entry) 2L else 1L
  adjacency_multiplier <- .dsvert_dp_adjacency_multiplier(policy)
  list(
    analysis_id = analysis_id,
    version = spec$version,
    dataset = spec$dataset,
    time = spec$time,
    event = spec$event,
    entry = spec$entry,
    censor = spec$censor,
    causes = unname(causes),
    outcome_levels = unname(outcome_levels),
    time_grid = unname(as.numeric(grid)),
    time_bounds = unname(as.numeric(time_bounds)),
    delayed_entry = delayed_entry,
    coordinate_count = as.integer(coordinate_count),
    l1_sensitivity = max_cells_per_unit * adjacency_multiplier,
    l2_sensitivity = sqrt(max_cells_per_unit * adjacency_multiplier))
}

.dsvert_dp_survival_ceiling_bin <- function(value, grid) {
  as.integer(findInterval(value, grid, left.open = TRUE) + 1L)
}

.dsvert_dp_survival_units <- function(data, policy) {
  .dsvert_dp_admit_units(data, policy)
}

.dsvert_dp_survival_validate_schema <- function(data, policy, spec) {
  required <- c(spec$time, spec$event, spec$entry)
  required <- required[!is.na(required) & nzchar(required)]
  if (!all(required %in% names(data)) ||
      !is.numeric(data[[spec$time]]) ||
      !is.atomic(data[[spec$event]]) ||
      (!is.null(spec$entry) && !is.numeric(data[[spec$entry]])) ||
      !policy$patient_column %in% names(data) ||
      !is.atomic(data[[policy$patient_column]])) {
    stop("The protected snapshot does not match its survival specification",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_survival_unit_rows <- function(data, policy, spec,
                                          admission = NULL) {
  .dsvert_dp_survival_validate_schema(data, policy, spec)
  if (is.null(admission)) {
    admission <- .dsvert_dp_survival_units(data, policy)
  }
  n <- nrow(data)
  selected_rows <- rep(NA_integer_, admission$work_units)
  if (!n) {
    return(list(rows = selected_rows, present = admission$present))
  }

  exit_value <- as.numeric(data[[spec$time]])
  outcome <- tryCatch(
    .dsvert_dp_categorical_label_values(
      data[[spec$event]], "protected survival outcomes"),
    error = function(e) {
      stop("The protected snapshot does not match its survival specification",
           call. = FALSE)
    })
  valid <- is.finite(exit_value) & outcome %in% spec$outcome_levels
  if (spec$delayed_entry) {
    entry_value <- as.numeric(data[[spec$entry]])
    valid <- valid & is.finite(entry_value) & entry_value <= exit_value
  }
  is_censor <- outcome == spec$censor
  cause_rank <- match(outcome, spec$outcome_levels)
  # A patient's first observed event wins. If there is no event, retain the
  # latest censoring record. All tie-breaks are public and deterministic.
  type_key <- ifelse(valid & !is_censor, 0L,
                     ifelse(valid, 1L, 2L))
  time_key <- ifelse(
    valid & !is_censor, exit_value,
    ifelse(valid, -exit_value, 0))
  rank_key <- ifelse(is.na(cause_rank), length(spec$outcome_levels) + 1L,
                     cause_rank)
  # Row position is not a semantic tie-break: a protected snapshot with the
  # same multiset of records must materialize the same patient contribution.
  # Entry time completes the public ordering for delayed-entry records.  Once
  # all value keys tie, choosing any duplicate row produces the same cells.
  entry_key <- if (spec$delayed_entry) {
    entry_value <- as.numeric(data[[spec$entry]])
    ifelse(valid, entry_value, 0)
  } else {
    rep(0, n)
  }
  ordered <- order(
    admission$group, type_key, time_key, rank_key, entry_key, seq_len(n),
    method = "radix")
  rows <- ordered[!duplicated(admission$group[ordered])]
  selected_rows[admission$group[rows]] <- rows
  list(rows = selected_rows, present = admission$present)
}

.dsvert_dp_survival_histogram <- function(data, policy, spec,
                                          admission = NULL) {
  selected <- .dsvert_dp_survival_unit_rows(
    data, policy, spec, admission)
  active <- which(selected$present & !is.na(selected$rows))
  rows <- selected$rows[active]
  time_count <- length(spec$time_grid)
  outcome_count <- length(spec$outcome_levels)
  exit_counts <- matrix(
    0, nrow = time_count, ncol = outcome_count,
    dimnames = list(NULL, spec$outcome_levels))
  entry_counts <- if (spec$delayed_entry) numeric(time_count) else NULL
  invalid_count <- 0

  if (length(rows)) {
    exit_raw <- as.numeric(data[[spec$time]][rows])
    outcome <- tryCatch(
      .dsvert_dp_categorical_label_values(
        data[[spec$event]], "protected survival outcomes")[rows],
      error = function(e) {
        stop("The protected snapshot does not match its survival specification",
             call. = FALSE)
      })
    valid <- is.finite(exit_raw) & outcome %in% spec$outcome_levels
    lower <- spec$time_bounds[[1L]]
    upper <- spec$time_bounds[[2L]]
    exit_bounded <- pmin(upper, pmax(lower, exit_raw))
    entry_bounded <- NULL
    if (spec$delayed_entry) {
      entry_raw <- as.numeric(data[[spec$entry]][rows])
      valid <- valid & is.finite(entry_raw) & entry_raw <= exit_raw
      entry_bounded <- pmin(upper, pmax(lower, entry_raw))
    }
    valid[is.na(valid)] <- FALSE
    invalid_count <- sum(!valid)
    if (any(valid)) {
      exit_bin <- .dsvert_dp_survival_ceiling_bin(
        exit_bounded[valid], spec$time_grid)
      outcome_bin <- match(outcome[valid], spec$outcome_levels)
      exit_cell <- exit_bin + (outcome_bin - 1L) * time_count
      exit_counts[] <- tabulate(
        exit_cell, nbins = time_count * outcome_count)
      if (spec$delayed_entry) {
        entry_bin <- .dsvert_dp_survival_ceiling_bin(
          entry_bounded[valid], spec$time_grid)
        entry_counts[] <- tabulate(entry_bin, nbins = time_count)
      }
    }
  }

  exact <- c(entry_counts, as.vector(exit_counts), invalid_count)
  exact <- .dsvert_dp_integer_vector(exact, "survival histogram")
  if (length(exact) != spec$coordinate_count) {
    stop("The fixed survival histogram shape is invalid", call. = FALSE)
  }
  list(
    exact = exact,
    entry_count = if (spec$delayed_entry) time_count else 0L,
    exit_count = as.integer(time_count * outcome_count),
    invalid_count = 1L)
}
