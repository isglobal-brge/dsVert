#' @title MHE Combine Keys (Server-Side)
#' @description Server-side aggregate function that combines public key shares
#'   into a collective public key and generates evaluation keys.
#'
#' @param public_key_shares Character vector or single string. Base64-encoded
#'   public key share(s) from all parties.
#' @param log_n Integer. Ring dimension parameter (must match key generation).
#' @param log_scale Integer. Scale parameter (must match key generation).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{collective_public_key}: Combined public key for encryption
#'     \item \code{relinearization_key}: Key for relinearization after multiplication
#'     \item \code{rotation_keys}: Keys for slot rotation operations
#'   }
#'
#' @details
#' This function combines public key shares from all parties into a single
#' collective public key. It also generates evaluation keys needed for
#' homomorphic operations (multiplication and rotation).
#'
#' @export
mheCombineKeysDS <- function(public_key_shares, log_n = 14, log_scale = 40) {
  # Validate inputs
  if (!is.character(public_key_shares)) {
    stop("public_key_shares must be a character vector", call. = FALSE)
  }

  # Convert from base64url to standard base64 (needed for Opal/Rock compatibility)
  # The client sends base64url because "/" and "+" cause R parser issues
  public_key_shares <- sapply(public_key_shares, .base64url_to_base64, USE.NAMES = FALSE)

  # Ensure it's a list for the tool
  if (length(public_key_shares) == 1) {
    pk_list <- list(public_key_shares)
  } else {
    pk_list <- as.list(public_key_shares)
  }

  # Call mhe-tool
  input <- list(
    public_key_shares = pk_list,
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("combine-keys", input)

  # Convert output to base64url for safe transmission back to client
  list(
    collective_public_key = base64_to_base64url(result$collective_public_key),
    relinearization_key = if (!is.null(result$relinearization_key)) base64_to_base64url(result$relinearization_key) else NULL,
    rotation_keys = if (!is.null(result$rotation_keys)) base64_to_base64url(result$rotation_keys) else NULL
  )
}
