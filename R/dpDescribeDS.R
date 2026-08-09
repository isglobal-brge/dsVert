# Fixed-domain, quantized differential-private descriptive statistics.

.dsvert_dp_describe_spec <- function(
    policy, data_name, analysis_id,
    specs = .dsvert_dp_option("describe_specs", NULL)) {
  analysis_id <- .dsvert_dp_scalar_string(analysis_id, "analysis_id")
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", analysis_id)) {
    stop("analysis_id contains unsupported characters", call. = FALSE)
  }
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    stop("dsvert.dp.describe_specs must be a uniquely named list",
         call. = FALSE)
  }
  raw <- specs[[analysis_id]]
  expected <- c(
    "version", "dataset", "variables", "histogram_grids", "allocation")
  if (!is.list(raw) || is.null(names(raw)) || anyNA(names(raw)) ||
      anyDuplicated(names(raw)) || !setequal(names(raw), expected)) {
    stop("The requested custodian describe specification is unavailable",
         call. = FALSE)
  }
  scalar <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      nzchar(value)
  }
  if (!scalar(raw$version) || !scalar(raw$dataset) ||
      !identical(raw$dataset, data_name) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", raw$version) ||
      !is.character(raw$variables) || !length(raw$variables) ||
      anyNA(raw$variables) || any(!nzchar(raw$variables)) ||
      anyDuplicated(raw$variables)) {
    stop("The requested custodian describe specification is invalid",
         call. = FALSE)
  }
  variables <- unname(raw$variables)
  grids <- raw$histogram_grids
  if (!is.list(grids) || is.null(names(grids)) || anyNA(names(grids)) ||
      anyDuplicated(names(grids)) || !identical(names(grids), variables)) {
    stop("Describe histogram grids must match the configured variables",
         call. = FALSE)
  }
  lower <- upper <- numeric(length(variables))
  grid_lengths <- integer(length(variables))
  grid_values <- vector("list", length(variables))
  coordinate_count <- 0
  for (index in seq_along(variables)) {
    variable <- variables[[index]]
    bounds <- policy$numeric_bounds[[variable]]
    grid <- grids[[index]]
    if (is.null(bounds) || !is.numeric(bounds) || length(bounds) != 2L ||
        anyNA(bounds) || any(!is.finite(bounds)) || bounds[[1L]] >= bounds[[2L]] ||
        !is.numeric(grid) || !length(grid) || anyNA(grid) ||
        any(!is.finite(grid)) || any(diff(grid) <= 0) ||
        bounds[[1L]] >= grid[[1L]] ||
        !isTRUE(all.equal(
          grid[[length(grid)]], bounds[[2L]], tolerance = 0))) {
      stop("A custodian describe bound or histogram grid is invalid",
           call. = FALSE)
    }
    lower[[index]] <- bounds[[1L]]
    upper[[index]] <- bounds[[2L]]
    grid_lengths[[index]] <- length(grid)
    grid_values[[index]] <- unname(as.numeric(grid))
    coordinate_count <- coordinate_count + length(grid) + 4
    if (!is.finite(coordinate_count) ||
        coordinate_count > .DSVERT_DP_MAX_COORDINATES ||
        coordinate_count > .Machine$integer.max) {
      stop("The fixed describe release exceeds the DP coordinate limit",
           call. = FALSE)
    }
  }

  allocation_names <- c("count", "sum", "sumsq", "histogram")
  allocation <- raw$allocation
  if (!is.numeric(allocation) || length(allocation) != 4L ||
      is.null(names(allocation)) || anyNA(names(allocation)) ||
      anyDuplicated(names(allocation)) ||
      !setequal(names(allocation), allocation_names)) {
    stop("Describe epsilon allocation must name four mechanism families",
         call. = FALSE)
  }
  allocation <- unname(as.numeric(allocation[allocation_names]))
  if (anyNA(allocation) || any(!is.finite(allocation)) ||
      any(allocation <= 0) ||
      abs(sum(allocation) - 1) > 1024 * .Machine$double.eps) {
    stop("Describe epsilon allocation weights must be positive and sum to one",
         call. = FALSE)
  }
  allocation <- allocation / sum(allocation)

  grid_bits <- policy$numeric_grid_bits
  if (!is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || grid_bits != as.integer(grid_bits) ||
      grid_bits < 8L || grid_bits > 18L) {
    stop("The custodian numeric quantization grid is invalid", call. = FALSE)
  }
  grid_scale <- 2^as.integer(grid_bits)
  variable_count <- length(variables)
  family_sensitivity <- c(
    1, grid_scale, grid_scale,
    .dsvert_dp_adjacency_multiplier(policy))
  sum_family_l1_sensitivity_bound <-
    variable_count * sum(family_sensitivity)
  per_variable_l2_squared <- 2 * grid_scale^2 +
    if (identical(policy$adjacency, "replace_one_fixed_cohort")) 3 else 2
  l2_sensitivity_bound <- sqrt(variable_count * per_variable_l2_squared)
  if (!is.finite(sum_family_l1_sensitivity_bound) ||
      sum_family_l1_sensitivity_bound > .dsvert_dp_exact_integer_limit ||
      !is.finite(l2_sensitivity_bound) || l2_sensitivity_bound <= 0 ||
      l2_sensitivity_bound > .dsvert_dp_exact_integer_limit) {
    stop("The describe sensitivity is not exactly representable",
         call. = FALSE)
  }
  minimum_total_epsilon <- max(
    variable_count * family_sensitivity / allocation / 2^40)
  if (!is.finite(minimum_total_epsilon) || minimum_total_epsilon <= 0) {
    stop("Describe epsilon allocation is outside the sampler domain",
         call. = FALSE)
  }

  list(
    analysis_id = analysis_id,
    version = raw$version,
    dataset = raw$dataset,
    variables = variables,
    lower_bounds = lower,
    upper_bounds = upper,
    histogram_grids = grid_values,
    grid_lengths = grid_lengths,
    grid_values = unname(unlist(grid_values, use.names = FALSE)),
    allocation_names = allocation_names,
    allocation_weights = allocation,
    numeric_grid_bits = as.integer(grid_bits),
    numeric_grid_scale = grid_scale,
    variable_count = as.integer(variable_count),
    coordinate_count = as.integer(coordinate_count),
    family_sensitivity = family_sensitivity,
    sum_family_l1_sensitivity_bound =
      sum_family_l1_sensitivity_bound,
    l2_sensitivity_bound = l2_sensitivity_bound,
    minimum_total_epsilon = minimum_total_epsilon)
}

.dsvert_dp_describe_validate_schema <- function(data, policy, spec) {
  if (!all(spec$variables %in% names(data)) ||
      any(!vapply(data[spec$variables], is.numeric, logical(1L))) ||
      !is.character(policy$patient_column) ||
      length(policy$patient_column) != 1L ||
      is.na(policy$patient_column) ||
      !policy$patient_column %in% names(data) ||
      !is.atomic(data[[policy$patient_column]])) {
    stop("The protected snapshot does not match its describe specification",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_describe_units <- function(data, policy) {
  .dsvert_dp_admit_units(data, policy)
}

.dsvert_dp_describe_normalized_units <- function(data, units, variable,
                                                  lower, upper) {
  raw <- as.numeric(data[[variable]])
  finite <- is.finite(raw)
  normalized <- numeric(length(raw))
  normalized[finite] <-
    (pmin(upper, pmax(lower, raw[finite])) - lower) / (upper - lower)
  value <- numeric(units$work_units)
  valid <- rep(FALSE, units$work_units)
  if (any(finite)) {
    rows <- which(finite)
    ordered <- rows[order(
      units$group[rows], normalized[rows], rows, method = "radix")]
    sums <- rowsum(
      matrix(normalized[ordered], ncol = 1L),
      units$group[ordered], reorder = FALSE)
    groups <- as.integer(rownames(sums))
    counts <- tabulate(units$group[ordered], nbins = units$unit_count)
    value[groups] <- as.numeric(sums[, 1L]) / counts[groups]
    valid[groups] <- TRUE
  }
  valid <- valid & units$present
  list(value = value, valid = valid, present = units$present)
}

.dsvert_dp_describe_statistics <- function(data, policy, spec,
                                            units = NULL) {
  .dsvert_dp_describe_validate_schema(data, policy, spec)
  if (is.null(units)) units <- .dsvert_dp_describe_units(data, policy)
  blocks <- vector("list", spec$variable_count)
  for (index in seq_along(spec$variables)) {
    bounded <- .dsvert_dp_describe_normalized_units(
      data, units, spec$variables[[index]],
      spec$lower_bounds[[index]], spec$upper_bounds[[index]])
    valid_value <- bounded$value[bounded$valid]
    q_sum <- round(valid_value * spec$numeric_grid_scale)
    q_sumsq <- round(valid_value^2 * spec$numeric_grid_scale)
    normalized_grid <-
      (spec$histogram_grids[[index]] - spec$lower_bounds[[index]]) /
      (spec$upper_bounds[[index]] - spec$lower_bounds[[index]])
    bin <- as.integer(findInterval(
      valid_value, normalized_grid, left.open = TRUE) + 1L)
    histogram <- c(
      tabulate(bin, nbins = spec$grid_lengths[[index]]),
      sum(bounded$present & !bounded$valid))
    blocks[[index]] <- c(
      length(valid_value), sum(q_sum), sum(q_sumsq), histogram)
  }
  exact <- unname(unlist(blocks, use.names = FALSE))
  exact <- .dsvert_dp_integer_vector(exact, "describe sufficient statistics")
  if (length(exact) != spec$coordinate_count) {
    stop("The fixed describe release shape is invalid", call. = FALSE)
  }
  exact
}

.dsvert_dp_describe_coordinate_plan <- function(spec, epsilon) {
  family_epsilon <- epsilon * spec$allocation_weights / spec$variable_count
  epsilon_blocks <- sensitivity_blocks <-
    vector("list", spec$variable_count)
  for (index in seq_len(spec$variable_count)) {
    grid_length <- spec$grid_lengths[[index]]
    epsilon_blocks[[index]] <- c(
      family_epsilon[1:3],
      rep(family_epsilon[[4L]], grid_length + 1L))
    sensitivity_blocks[[index]] <- c(
      spec$family_sensitivity[1:3],
      rep(spec$family_sensitivity[[4L]], grid_length + 1L))
  }
  epsilons <- unname(unlist(epsilon_blocks, use.names = FALSE))
  sensitivities <- unname(unlist(sensitivity_blocks, use.names = FALSE))
  if (length(epsilons) != spec$coordinate_count ||
      length(sensitivities) != spec$coordinate_count ||
      abs(spec$variable_count * sum(family_epsilon) - epsilon) >
        4096 * .Machine$double.eps * max(1, epsilon)) {
    stop("The describe epsilon allocation plan is invalid", call. = FALSE)
  }
  list(
    family_epsilon = family_epsilon,
    epsilons = epsilons,
    sensitivities = sensitivities)
}

.dsvert_dp_describe_accuracy <- function(values, spec) {
  result <- matrix(
    0, nrow = spec$variable_count, ncol = 4L,
    dimnames = list(NULL, spec$allocation_names))
  cursor <- 1L
  for (index in seq_len(spec$variable_count)) {
    result[index, 1:3] <- values[cursor:(cursor + 2L)]
    cursor <- cursor + 3L
    histogram_length <- spec$grid_lengths[[index]] + 1L
    histogram_values <- values[cursor:(cursor + histogram_length - 1L)]
    if (length(unique(histogram_values)) != 1L) {
      stop("The DP sampler returned inconsistent histogram accuracy",
           call. = FALSE)
    }
    result[index, 4L] <- histogram_values[[1L]]
    cursor <- cursor + histogram_length
  }
  unname(as.numeric(t(result)))
}
