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
#' @return List with x_means, x_sds, y_mean (if y_var), y_sd (if y_var)
#' @export
glmStandardizeDS <- function(data_name, output_name, x_vars, y_var = NULL,
                              session_id = NULL, skip_standardize = FALSE,
                              mode = "full") {
  # mode controls standardization:
  #   "full": (default) subtract mean, divide by sd (current behaviour)
  #   "scale_only": divide by sd, do NOT subtract mean (preserves
  #                 column mean structure while making L-BFGS well-
  #                 conditioned; required for ds.vertLMM's no-const
  #                 GLS fit, where subtracting the mean would shift
  #                 the no-intercept regression)
  #   "none": identical to skip_standardize = TRUE
  ss <- .S(session_id)
  .validate_data_name(data_name)
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

  result <- list()
  new_data <- data

  # Standardize X columns
  x_means <- numeric(length(x_vars))
  x_sds <- numeric(length(x_vars))
  names(x_means) <- x_vars
  names(x_sds) <- x_vars

  effective_mode <- if (isTRUE(skip_standardize)) "none" else mode
  for (i in seq_along(x_vars)) {
    v <- x_vars[i]
    col <- as.numeric(data[[v]])
    if (effective_mode == "none") {
      x_means[i] <- 0; x_sds[i] <- 1
      new_data[[v]] <- col
      new_data[[v]][is.na(col)] <- 0
    } else if (effective_mode == "scale_only") {
      # Keep the column's original mean but rescale by its SD so L-BFGS
      # in the inner loop sees a well-conditioned design. No-op for
      # the implicit constant: x_means[i] is stored as 0 so
      # back-transform (which uses sum(beta * x_means)) doesn't apply
      # a spurious shift.
      sd_v <- stats::sd(col, na.rm = TRUE)
      if (!is.finite(sd_v) || sd_v < 1e-10) sd_v <- 1
      x_means[i] <- 0
      x_sds[i] <- sd_v
      scaled <- col / sd_v
      scaled[is.na(scaled)] <- 0
      new_data[[v]] <- scaled
    } else {
      # "full" (default): center + scale.
      x_means[i] <- mean(col, na.rm = TRUE)
      x_sds[i] <- stats::sd(col, na.rm = TRUE)
      if (!is.finite(x_sds[i]) || x_sds[i] < 1e-10) x_sds[i] <- 1
      if (!is.finite(x_means[i])) x_means[i] <- 0
      new_data[[v]] <- (col - x_means[i]) / x_sds[i]
    }
  }
  result$x_means <- as.numeric(x_means)
  result$x_sds <- as.numeric(x_sds)

  # Standardize y if requested
  if (!is.null(y_var) && y_var %in% names(data)) {
    y <- as.numeric(data[[y_var]])
    if (effective_mode == "none") {
      result$y_mean <- 0
      result$y_sd   <- 1
      new_data[[y_var]] <- y
    } else if (effective_mode == "scale_only") {
      sd_y <- stats::sd(y, na.rm = TRUE)
      if (!is.finite(sd_y) || sd_y < 1e-10) sd_y <- 1
      result$y_mean <- 0
      result$y_sd   <- sd_y
      new_data[[y_var]] <- y / sd_y
    } else {
      result$y_mean <- mean(y, na.rm = TRUE)
      result$y_sd <- stats::sd(y, na.rm = TRUE)
      if (!is.finite(result$y_sd) || result$y_sd < 1e-10) result$y_sd <- 1
      if (!is.finite(result$y_mean)) result$y_mean <- 0
      new_data[[y_var]] <- (y - result$y_mean) / result$y_sd
    }
  }

  # Store standardized data in session storage because DataSHIELD aggregate
  # methods cannot persist objects in the server's R environment (the
  # parent.frame() is discarded after each call). The .resolveData() utility
  # in mpcUtils.R looks up data here first, using output_name as the key.
  ss$std_data <- new_data
  ss$std_data_name <- output_name

  result
}
