#' @title Standardize Features for GLM (Server-Side)
#' @description Standardizes specified columns of a data frame (center + scale)
#'   and stores the result as a new data frame. Returns column means and
#'   standard deviations for the client to unstandardize coefficients after
#'   convergence. For Gaussian family, also standardizes the response variable.
#'
#' @param data_name Character. Name of the source data frame.
#' @param output_name Character. Name for the standardized data frame.
#' @param x_vars Character vector. Feature columns to standardize.
#' @param y_var Character or NULL. Response variable to standardize (Gaussian only).
#' @param session_id Character or NULL. UUID for session-scoped storage
#'   isolation. Default NULL uses global shared storage.
#'
#' @param skip_standardize Logical. If TRUE, skip server-side standardisation (used by callers that pre-standardised).
#' @param mode Character. One of \code{"full"}, \code{"scale_only"}, or
#'   \code{"none"}.
#' @param missing Character. Missing-data contract. \code{"fail"} (default)
#'   refuses incomplete analysis columns so missing values cannot be silently
#'   converted to zero in fixed-point arithmetic. \code{"mean_impute"} is an
#'   explicit compatibility policy that imputes the local column mean before
#'   applying the requested scaling.
#' @param numeric_family,numeric_ring Custodian numeric-policy context used to
#'   validate the values that will be fixed-point encoded.
#' @param numeric_y_var Response column to validate even when it is not being
#'   standardized (as for binomial and Poisson models).
#' @return List with x_means, x_sds, y_mean (if y_var), y_sd (if y_var)
glmStandardizeDS <- function(data_name, output_name, x_vars, y_var = NULL,
                              session_id = NULL, skip_standardize = FALSE,
                              mode = "full", missing = "fail",
                              numeric_family = "gaussian",
                              numeric_ring = 63L,
                              numeric_y_var = y_var) {
  # mode controls standardization:
  #   "full": (default) subtract mean, divide by sd (current behaviour)
  #   "scale_only": divide by sd, do NOT subtract mean (preserves
  #                 column mean structure while making L-BFGS well-
  #                 conditioned; required for ds.vertLMM's no-const
  #                 GLS fit, where subtracting the mean would shift
  #                 the no-intercept regression)
  #   "none": identical to skip_standardize = TRUE
  if (!is.character(mode) || length(mode) != 1L ||
      !mode %in% c("full", "scale_only", "none")) {
    stop("mode must be one of 'full', 'scale_only', or 'none'",
         call. = FALSE)
  }
  if (!is.character(missing) || length(missing) != 1L ||
      !missing %in% c("fail", "mean_impute")) {
    stop("missing must be one of 'fail' or 'mean_impute'", call. = FALSE)
  }
  if (!is.logical(skip_standardize) || length(skip_standardize) != 1L ||
      is.na(skip_standardize)) {
    stop("skip_standardize must be TRUE or FALSE", call. = FALSE)
  }
  if (!is.null(x_vars) && !is.character(x_vars)) {
    stop("x_vars must be NULL or a character vector", call. = FALSE)
  }
  if (!is.null(y_var) &&
      (!is.character(y_var) || length(y_var) != 1L || !nzchar(y_var))) {
    stop("y_var must be NULL or one non-empty column name", call. = FALSE)
  }
  if (!is.character(numeric_family) || length(numeric_family) != 1L ||
      is.na(numeric_family) ||
      !numeric_family %in% c("gaussian", "binomial", "poisson")) {
    stop("numeric_family must be gaussian, binomial, or poisson",
         call. = FALSE)
  }
  if (!is.numeric(numeric_ring) || length(numeric_ring) != 1L ||
      is.na(numeric_ring) || !is.finite(numeric_ring) ||
      numeric_ring != floor(numeric_ring) ||
      !as.integer(numeric_ring) %in% c(63L, 127L)) {
    stop("numeric_ring must be 63 or 127", call. = FALSE)
  }
  numeric_ring <- as.integer(numeric_ring)
  if (!is.null(numeric_y_var) &&
      (!is.character(numeric_y_var) || length(numeric_y_var) != 1L ||
       is.na(numeric_y_var) || !nzchar(numeric_y_var))) {
    stop("numeric_y_var must be NULL or one non-empty column name",
         call. = FALSE)
  }
  if (length(x_vars) &&
      (anyNA(x_vars) || any(!nzchar(x_vars)) || anyDuplicated(x_vars))) {
    stop("x_vars must contain unique non-empty column names", call. = FALSE)
  }

  ss <- .S(session_id)
  .validate_data_name(data_name)
  .validate_data_name(output_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Privacy check
  n <- nrow(data)
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }

  analysis_vars <- unique(c(x_vars, y_var, numeric_y_var))
  absent <- setdiff(analysis_vars, names(data))
  if (length(absent)) {
    stop("Analysis column(s) not found: ", paste(absent, collapse = ", "),
         call. = FALSE)
  }
  non_numeric <- analysis_vars[!vapply(
    data[analysis_vars], function(x) is.numeric(x) || is.logical(x),
    logical(1L))]
  if (length(non_numeric)) {
    stop("Analysis columns must be numeric; encode factors explicitly before ",
         "fitting", call. = FALSE)
  }

  analysis_data <- lapply(data[analysis_vars], as.numeric)
  if (any(vapply(analysis_data, function(x) any(is.infinite(x)),
                 logical(1L)))) {
    stop("DSVERT_NONFINITE_ANALYSIS_DATA: analysis columns contain Inf/-Inf",
         call. = FALSE)
  }
  has_missing <- any(vapply(analysis_data, anyNA, logical(1L)))
  if (has_missing && identical(missing, "fail")) {
    stop("DSVERT_INCOMPLETE_ANALYSIS_DATA: analysis columns contain missing ",
         "values; align a complete-case cohort or request an explicit ",
         "imputation policy", call. = FALSE)
  }

  policy <- .dsvert_numeric_policy()
  bounds <- policy$bounds
  if (n > bounds$max_observations || length(x_vars) > bounds$max_predictors) {
    stop("DSVERT_NUMERIC_BOUND_FAILURE: GLM input dimensions exceed the ",
         "custodian-owned public policy", call. = FALSE)
  }
  for (v in x_vars) {
    .dsvert_numeric_assert_vector(
      data[[v]][!is.na(data[[v]])], bounds$max_abs_predictor_input,
      paste0("raw predictor '", v, "'"))
  }
  if (!is.null(numeric_y_var)) {
    raw_response <- data[[numeric_y_var]]
    .dsvert_numeric_assert_vector(
      raw_response[!is.na(raw_response)],
      bounds$max_abs_response_input[[numeric_family]],
      paste0("raw ", numeric_family, " response '", numeric_y_var, "'"),
      lower = if (numeric_family %in% c("binomial", "poisson")) 0 else NULL,
      integer = numeric_family %in% c("binomial", "poisson"))
    if (identical(numeric_family, "binomial") &&
        any(!raw_response[!is.na(raw_response)] %in% c(0, 1))) {
      stop("DSVERT_NUMERIC_DOMAIN_FAILURE: binomial response must be 0/1",
           call. = FALSE)
    }
  }

  prepare_column <- function(x) {
    x <- as.numeric(x)
    if (anyNA(x)) {
      replacement <- mean(x, na.rm = TRUE)
      if (!is.finite(replacement)) {
        stop("DSVERT_INCOMPLETE_ANALYSIS_DATA: an analysis column has no ",
             "finite observations", call. = FALSE)
      }
      x[is.na(x)] <- replacement
    }
    x
  }

  result <- list()
  result$missing_policy <- missing
  new_data <- data

  # Standardize X columns
  x_means <- numeric(length(x_vars))
  x_sds <- numeric(length(x_vars))
  names(x_means) <- x_vars
  names(x_sds) <- x_vars

  effective_mode <- if (isTRUE(skip_standardize)) "none" else mode
  for (i in seq_along(x_vars)) {
    v <- x_vars[i]
    raw_col <- as.numeric(data[[v]])
    col <- prepare_column(raw_col)
    if (effective_mode == "none") {
      x_means[i] <- 0; x_sds[i] <- 1
      new_data[[v]] <- col
    } else if (effective_mode == "scale_only") {
      # Keep the column's original mean but rescale by its SD so L-BFGS
      # in the inner loop sees a well-conditioned design. No-op for
      # the implicit constant: x_means[i] is stored as 0 so
      # back-transform (which uses sum(beta * x_means)) doesn't apply
      # a spurious shift.
      sd_v <- stats::sd(raw_col, na.rm = TRUE)
      if (!is.finite(sd_v) || sd_v < 1e-10) sd_v <- 1
      x_means[i] <- 0
      x_sds[i] <- sd_v
      new_data[[v]] <- col / sd_v
    } else {
      # "full" (default): center + scale.
      x_means[i] <- mean(raw_col, na.rm = TRUE)
      x_sds[i] <- stats::sd(raw_col, na.rm = TRUE)
      if (!is.finite(x_sds[i]) || x_sds[i] < 1e-10) x_sds[i] <- 1
      if (!is.finite(x_means[i])) x_means[i] <- 0
      new_data[[v]] <- (col - x_means[i]) / x_sds[i]
    }
  }
  result$x_means <- as.numeric(x_means)
  result$x_sds <- as.numeric(x_sds)

  # Standardize y if requested
  if (!is.null(y_var) && y_var %in% names(data)) {
    raw_y <- as.numeric(data[[y_var]])
    y <- prepare_column(raw_y)
    if (effective_mode == "none") {
      result$y_mean <- 0
      result$y_sd   <- 1
      new_data[[y_var]] <- y
    } else if (effective_mode == "scale_only") {
      sd_y <- stats::sd(raw_y, na.rm = TRUE)
      if (!is.finite(sd_y) || sd_y < 1e-10) sd_y <- 1
      result$y_mean <- 0
      result$y_sd   <- sd_y
      new_data[[y_var]] <- y / sd_y
    } else {
      result$y_mean <- mean(raw_y, na.rm = TRUE)
      result$y_sd <- stats::sd(raw_y, na.rm = TRUE)
      if (!is.finite(result$y_sd) || result$y_sd < 1e-10) result$y_sd <- 1
      if (!is.finite(result$y_mean)) result$y_mean <- 0
      new_data[[y_var]] <- (y - result$y_mean) / result$y_sd
    }
  }
  if (!is.null(numeric_y_var) && !identical(numeric_y_var, y_var) &&
      anyNA(new_data[[numeric_y_var]])) {
    new_data[[numeric_y_var]] <- prepare_column(new_data[[numeric_y_var]])
  }

  frac_bits <- if (numeric_ring == 127L) 50L else 20L
  for (v in x_vars) {
    .dsvert_numeric_assert_vector(
      new_data[[v]], bounds$max_abs_predictor,
      paste0("encoded predictor '", v, "'"))
    .dsvert_numeric_assert_fp_encoding(
      new_data[[v]], numeric_ring, frac_bits,
      paste0("encoded predictor '", v, "'"))
  }
  if (!is.null(numeric_y_var)) {
    .dsvert_numeric_assert_vector(
      new_data[[numeric_y_var]], bounds$max_abs_response[[numeric_family]],
      paste0("encoded ", numeric_family, " response '", numeric_y_var, "'"),
      lower = if (numeric_family %in% c("binomial", "poisson")) 0 else NULL,
      integer = numeric_family %in% c("binomial", "poisson"))
    .dsvert_numeric_assert_fp_encoding(
      new_data[[numeric_y_var]], numeric_ring, frac_bits,
      paste0("encoded ", numeric_family, " response '", numeric_y_var, "'"))
  }

  if (!is.null(session_id)) {
    result$numeric_attestation <- .dsvert_numeric_attestation(
      kind = "glm_standardized_input",
      policy = policy,
      session_id = session_id,
      data_name = data_name,
      variables = unique(c(x_vars, numeric_y_var)),
      family = numeric_family,
      ring = numeric_ring,
      n = n,
      checks = list(
        ieee_finite = TRUE,
        raw_input_bounds = TRUE,
        response_domain = TRUE,
        encoded_input_bounds = TRUE,
        fixed_point_representable = TRUE))
  }

  # Store standardized data in session storage because DataSHIELD aggregate
  # methods cannot persist objects in the server's R environment (the
  # parent.frame() is discarded after each call). The .resolveData() utility
  # in mpcUtils.R looks up data here first, using output_name as the key.
  ss$std_data <- new_data
  ss$std_data_name <- output_name
  ss$k2_numeric_family <- numeric_family

  result
}
