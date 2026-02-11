#' @title MHE Encrypt Columns (Server-Side)
#' @description Server-side aggregate function that standardizes data and encrypts
#'   each column separately. This is optimized for computing cross-products.
#'
#' @param data_name Character string. Name of the data frame in the server environment.
#' @param variables Character vector. Names of numeric columns to encrypt.
#' @param collective_public_key Character string. Base64-encoded collective public key.
#' @param log_n Integer. Ring dimension parameter.
#' @param log_scale Integer. Scale parameter.
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{encrypted_columns}: List of base64-encoded encrypted columns
#'     \item \code{num_rows}: Number of observations
#'     \item \code{num_cols}: Number of variables
#'     \item \code{var_names}: Variable names
#'   }
#'
#' @details
#' This function:
#' \enumerate{
#'   \item Extracts the specified variables
#'   \item Removes rows with NA values
#'   \item Standardizes each column (mean=0, sd=1)
#'   \item Encrypts each column separately using the collective public key
#' }
#'
#' Each column becomes one ciphertext with n slots (one per observation).
#' This format is optimal for computing inner products (dot products) which
#' are the building blocks of correlation.
#'
#' @section Privacy:
#' The encrypted columns can only be decrypted with cooperation from ALL parties
#' that contributed to the collective public key.
#'
#' @export
mheEncryptColumnsDS <- function(data_name, variables, collective_public_key,
                                 log_n = 13, log_scale = 40) {
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

  # Convert from base64url to standard base64
  collective_public_key <- .base64url_to_base64(collective_public_key)

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Check variables exist
  missing_vars <- setdiff(variables, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found: ", paste(missing_vars, collapse = ", "), call. = FALSE)
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
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  }

  # Standardize (required for correlation)
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0  # Handle zero-variance columns

  # Convert to row-list format for JSON (the mhe-tool expects this)
  data_rows <- lapply(seq_len(nrow(Z)), function(i) as.numeric(Z[i, ]))

  # Call mhe-tool to encrypt columns
  input <- list(
    data = data_rows,
    collective_public_key = collective_public_key,
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("encrypt-columns", input)

  # Convert encrypted columns to base64url for safe transmission
  encrypted_columns_b64url <- lapply(result$encrypted_columns, base64_to_base64url)

  list(
    encrypted_columns = encrypted_columns_b64url,
    num_rows = result$num_rows,
    num_cols = result$num_cols,
    var_names = variables
  )
}
