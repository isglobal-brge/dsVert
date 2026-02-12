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
#'
#' @return List with x_means, x_sds, y_mean (if y_var), y_sd (if y_var)
#' @export
glmStandardizeDS <- function(data_name, output_name, x_vars, y_var = NULL) {
  data <- eval(parse(text = data_name), envir = parent.frame())

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

  for (i in seq_along(x_vars)) {
    v <- x_vars[i]
    col <- as.numeric(data[[v]])
    x_means[i] <- mean(col)
    x_sds[i] <- sd(col)
    if (x_sds[i] < 1e-10) x_sds[i] <- 1
    new_data[[v]] <- (col - x_means[i]) / x_sds[i]
  }
  result$x_means <- as.numeric(x_means)
  result$x_sds <- as.numeric(x_sds)

  # Standardize y if requested
  if (!is.null(y_var) && y_var %in% names(data)) {
    y <- as.numeric(data[[y_var]])
    result$y_mean <- mean(y)
    result$y_sd <- sd(y)
    if (result$y_sd < 1e-10) result$y_sd <- 1
    new_data[[y_var]] <- (y - result$y_mean) / result$y_sd
  }

  # Store standardized data frame in persistent storage
  # (parent.frame() in aggregate methods is discarded after the call)
  .mhe_storage$std_data <- new_data
  .mhe_storage$std_data_name <- output_name

  result
}
