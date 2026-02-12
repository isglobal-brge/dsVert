#' @title Local Correlation (Server-Side)
#' @description Server-side aggregate function that computes the correlation
#'   matrix for variables stored locally on this server.
#'
#' @param data_name Character string. Name of the data frame in the server environment.
#' @param variables Character vector. Names of numeric columns to include.
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{correlation}: The correlation matrix (p x p)
#'     \item \code{n_obs}: Number of observations used
#'     \item \code{var_names}: Variable names
#'   }
#'
#' @details
#' This function computes the standard Pearson correlation matrix for variables
#' stored locally on the server. No encryption is needed because all the data
#' is on the same server.
#'
#' This is used for the diagonal blocks of the full correlation matrix when
#' combining data from multiple servers.
#'
#' @section Privacy:
#' The correlation matrix is a summary statistic that does not reveal individual
#' observations. However, with very few observations or extreme values, some
#' information about individuals could potentially be inferred.
#'
#' The function enforces a minimum observation count based on the DataSHIELD
#' privacy level setting.
#'
#' @importFrom stats cor
#' @export
localCorDS <- function(data_name, variables) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variables) || length(variables) == 0) {
    stop("variables must be a non-empty character vector", call. = FALSE)
  }

  # Get data from server environment
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Check variables exist
  missing_vars <- setdiff(variables, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found: ", paste(missing_vars, collapse = ", "), call. = FALSE)
  }

  # Extract numeric data
  X <- as.matrix(data[, variables, drop = FALSE])

  if (!is.numeric(X)) {
    stop("All selected variables must be numeric", call. = FALSE)
  }

  # Remove rows with NA
  complete_rows <- complete.cases(X)
  X <- X[complete_rows, , drop = FALSE]
  n_obs <- nrow(X)

  # Privacy check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n_obs < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }

  # Compute correlation
  R <- cor(X)
  rownames(R) <- variables
  colnames(R) <- variables

  list(
    correlation = R,
    n_obs = n_obs,
    var_names = variables
  )
}
