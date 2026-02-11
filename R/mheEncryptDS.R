#' @title MHE Encryption (Server-Side)
#' @description Server-side aggregate function that encrypts a data matrix
#'   using the collective public key from MHE setup.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param variables Character vector. Names of numeric columns to encrypt.
#' @param collective_public_key Character string. Base64-encoded collective
#'   public key from MHE setup phase.
#' @param standardize Logical. Whether to standardize variables before encryption.
#'   Default is TRUE (required for correlation).
#' @param log_n Integer. Ring dimension parameter (must match key generation).
#' @param log_scale Integer. Scale parameter (must match key generation).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{ciphertext}: Base64-encoded encrypted data
#'     \item \code{rows}: Number of rows in the encrypted matrix
#'     \item \code{cols}: Number of columns in the encrypted matrix
#'     \item \code{var_names}: Names of encrypted variables
#'   }
#'
#' @details
#' This function encrypts data using the collective public key generated
#' in the MHE setup phase. The encrypted data can be used for homomorphic
#' computations without revealing the underlying values.
#'
#' The data is flattened to a vector (row-major order) before encryption.
#' The CKKS scheme supports approximate arithmetic on real numbers.
#'
#' @section Privacy:
#' \itemize{
#'   \item The ciphertext cannot be decrypted by the client alone
#'   \item Decryption requires collaboration of ALL servers
#'   \item Individual data values are never exposed
#' }
#'
#' @export
mheEncryptDS <- function(data_name, variables, collective_public_key,
                         standardize = TRUE, log_n = 14, log_scale = 40) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variables) || length(variables) == 0) {
    stop("variables must be a non-empty character vector", call. = FALSE)
  }
  if (!is.character(collective_public_key) || length(collective_public_key) != 1) {
    stop("collective_public_key must be a single character string", call. = FALSE)
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

  # Privacy check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n_obs < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  }

  # Standardize if requested
  if (standardize) {
    X <- scale(X, center = TRUE, scale = TRUE)
    X[is.nan(X)] <- 0
  }

  # Convert to list of lists for JSON
  data_list <- lapply(seq_len(nrow(X)), function(i) as.list(X[i, ]))

  # Call mhe-tool
  input <- list(
    data = X,
    collective_public_key = collective_public_key,
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("encrypt", input)

  list(
    ciphertext = result$ciphertext,
    rows = result$rows,
    cols = result$cols,
    var_names = variables
  )
}
