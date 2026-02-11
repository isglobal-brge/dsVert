#' @title MHE Cross Product (Server-Side)
#' @description Server-side aggregate function that computes the cross-product
#'   matrix Z_A' * Z_B where Z_B is encrypted.
#'
#' @param plaintext_data_name Character string. Name of the data frame containing
#'   the plaintext data (Z_A).
#' @param plaintext_variables Character vector. Variable names in Z_A.
#' @param encrypted_columns List. Base64-encoded encrypted columns from the other server.
#' @param secret_key Character string. Base64-encoded secret key for decryption.
#' @param evaluation_keys Character string. Base64-encoded evaluation keys for
#'   homomorphic operations (rotations in sum-reduce).
#' @param n_obs Integer. Number of observations (for computing correlation).
#' @param log_n Integer. Ring dimension parameter.
#' @param log_scale Integer. Scale parameter.
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{cross_correlation}: Matrix (p_A x p_B) of correlations
#'     \item \code{cross_product}: Raw cross-product matrix G_AB = Z_A' * Z_B
#'   }
#'
#' @details
#' This function computes the cross-product G_AB = Z_A' * Z_B homomorphically:
#'
#' \enumerate{
#'   \item Standardize local data Z_A
#'   \item For each pair of columns (i from A, j from B):
#'     \enumerate{
#'       \item Multiply plaintext column i of Z_A with encrypted column j of Z_B element-wise
#'       \item Sum-reduce to get the encrypted inner product
#'       \item Decrypt to get the cross-product entry
#'     }
#'   \item Divide by (n-1) to get correlation
#' }
#'
#' The cross-correlation R_AB = Cor(X_A, X_B) is computed as:
#' \deqn{R_{AB} = G_{AB} / (n-1)}
#'
#' @section Security Note:
#' This server never sees the plaintext values from the other server.
#' It only sees encrypted columns and computes on them homomorphically.
#' The final decryption requires the secret key, which in a true multiparty
#' setup would require collaboration from all parties.
#'
#' @export
mheCrossProductDS <- function(plaintext_data_name, plaintext_variables,
                               encrypted_columns, secret_key, evaluation_keys,
                               n_obs, log_n = 13, log_scale = 40) {
  # Validate inputs
  if (!is.character(plaintext_data_name) || length(plaintext_data_name) != 1) {
    stop("plaintext_data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(plaintext_variables) || length(plaintext_variables) == 0) {
    stop("plaintext_variables must be a non-empty character vector", call. = FALSE)
  }
  if (!is.list(encrypted_columns) && !is.character(encrypted_columns)) {
    stop("encrypted_columns must be a list or character vector", call. = FALSE)
  }
  if (!is.character(secret_key) || length(secret_key) != 1) {
    stop("secret_key must be a single character string", call. = FALSE)
  }
  if (!is.character(evaluation_keys) || length(evaluation_keys) != 1) {
    stop("evaluation_keys must be a single character string", call. = FALSE)
  }

  # Convert from base64url to standard base64
  secret_key <- .base64url_to_base64(secret_key)
  evaluation_keys <- .base64url_to_base64(evaluation_keys)
  encrypted_columns <- lapply(encrypted_columns, .base64url_to_base64)

  # Get plaintext data
  data <- eval(parse(text = plaintext_data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", plaintext_data_name, "' is not a data frame", call. = FALSE)
  }

  # Check variables exist
  missing_vars <- setdiff(plaintext_variables, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found: ", paste(missing_vars, collapse = ", "), call. = FALSE)
  }

  # Extract and standardize
  X <- as.matrix(data[, plaintext_variables, drop = FALSE])
  complete_rows <- complete.cases(X)
  X <- X[complete_rows, , drop = FALSE]

  if (nrow(X) != n_obs) {
    stop("Row count mismatch: local data has ", nrow(X),
         " complete rows but n_obs=", n_obs, call. = FALSE)
  }

  # Standardize
  Z_A <- scale(X, center = TRUE, scale = TRUE)
  Z_A[is.nan(Z_A)] <- 0

  # Convert to column format for the cross-product computation
  Z_A_cols <- lapply(seq_len(ncol(Z_A)), function(j) as.numeric(Z_A[, j]))

  # Ensure encrypted_columns is a list
  if (!is.list(encrypted_columns)) {
    encrypted_columns <- as.list(encrypted_columns)
  }

  # Call mhe-tool to compute cross-product
  input <- list(
    plaintext_columns = Z_A_cols,
    encrypted_columns = encrypted_columns,
    evaluation_keys = evaluation_keys,
    secret_key = secret_key,
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("cross-product", input)

  # Convert to matrix
  if (is.list(result$result) && length(result$result) > 0) {
    G_AB <- do.call(rbind, lapply(result$result, function(row) {
      if (is.list(row)) unlist(row) else row
    }))
  } else {
    G_AB <- matrix(unlist(result$result), nrow = length(plaintext_variables), byrow = TRUE)
  }

  # Set row names
  if (nrow(G_AB) == length(plaintext_variables)) {
    rownames(G_AB) <- plaintext_variables
  }

  # Compute correlation (divide by n-1)
  R_AB <- G_AB / (n_obs - 1)

  list(
    cross_correlation = R_AB,
    cross_product = G_AB
  )
}
