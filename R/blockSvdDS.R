#' @title Block SVD Computation (Server-Side)
#' @description Server-side aggregate function that computes the first step
#'   of Block Singular Value Decomposition for correlation and PCA analysis
#'   on vertically partitioned data.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param variables Character vector. Names of numeric columns to include.
#' @param standardize Logical. Whether to standardize variables before SVD.
#'   Default is TRUE (required for correlation calculation).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{UD}: Matrix product of left singular vectors (U) and
#'       singular values (D). Dimensions: n_obs x n_vars
#'     \item \code{n_obs}: Number of observations
#'     \item \code{var_names}: Names of variables included
#'   }
#'
#' @details
#' This function computes the first step of the distributed Block SVD
#' algorithm for vertically partitioned data:
#'
#' \enumerate{
#'   \item Standardize each column (if standardize = TRUE)
#'   \item Compute SVD: X = U * D * V'
#'   \item Return U * D (left singular vectors weighted by singular values)
#' }
#'
#' The client combines U*D from all servers and performs a final SVD to
#' obtain the correlation matrix: Corr = V * D^2 * V'
#'
#' This method is privacy-preserving because:
#' \itemize{
#'   \item U*D cannot reconstruct original data without V
#'   \item V is never shared from individual servers
#'   \item Only the final combined SVD reveals correlation structure
#' }
#'
#' @references
#' Iwen, M. & Ong, B.W. (2016). A distributed and incremental SVD algorithm
#' for agglomerative data analysis on large networks. SIAM Journal on Matrix
#' Analysis and Applications.
#'
#' @seealso \code{\link[dsVertClient]{ds.vertCor}} for client-side correlation
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' # result <- datashield.aggregate(conn,
#' #   "blockSvdDS('D', c('age', 'weight', 'height'))")
#' }
#'
#' @export
blockSvdDS <- function(data_name, variables, standardize = TRUE) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variables) || length(variables) == 0) {
    stop("variables must be a non-empty character vector", call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Check variables exist
  missing_vars <- setdiff(variables, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found: ", paste(missing_vars, collapse = ", "),
         call. = FALSE)
  }

  # Extract and convert to matrix
  X <- as.matrix(data[, variables, drop = FALSE])

  # Check for numeric data
  if (!is.numeric(X)) {
    stop("All selected variables must be numeric", call. = FALSE)
  }

  # Remove rows with NA
  complete_rows <- complete.cases(X)
  X <- X[complete_rows, , drop = FALSE]
  n_obs <- nrow(X)
  n_vars <- ncol(X)

  # Privacy check: ensure minimum observations
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n_obs < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  }

  # Standardize if requested (required for correlation)
  if (standardize) {
    X <- scale(X, center = TRUE, scale = TRUE)
    # Handle zero-variance columns (replace NaN with 0)
    X[is.nan(X)] <- 0
  }

  # Compute SVD
  svd_result <- svd(X)

  # Compute U * D
  # The number of singular values is min(n_obs, n_vars)
  n_sv <- length(svd_result$d)

  # svd_result$u has dimensions n_obs x n_sv
  # svd_result$d has length n_sv
  # We need to multiply each column of u by corresponding singular value

  # Create UD matrix: scale columns of U by singular values
  UD <- svd_result$u
  for (j in seq_len(n_sv)) {
    UD[, j] <- UD[, j] * svd_result$d[j]
  }

  # Return results
  list(
    UD = UD,
    n_obs = n_obs,
    var_names = variables
  )
}
