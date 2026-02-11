#' @title MHE Partial Decryption (Server-Side)
#' @description Server-side aggregate function that computes a partial
#'   decryption share using this server's secret key share.
#'
#' @param ciphertext Character string. Base64-encoded ciphertext to partially
#'   decrypt.
#' @param party_id Integer. This server's party ID (used to locate stored key).
#' @param secret_key_share Character string. Optional. Base64-encoded secret key
#'   share. If NULL, uses the key stored during key generation.
#' @param log_n Integer. Ring dimension parameter (must match encryption).
#' @param log_scale Integer. Scale parameter (must match encryption).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{partial_decryption}: Base64-encoded partial decryption share
#'     \item \code{party_id}: This server's party ID
#'   }
#'
#' @details
#' This function computes a partial decryption of the ciphertext using
#' this server's secret key share. The partial decryption alone reveals
#' NOTHING about the plaintext - all parties must contribute their shares
#' to recover the result.
#'
#' @section Security:
#' \itemize{
#'   \item A single partial decryption reveals no information
#'   \item The secret key share is never transmitted
#'   \item ALL parties must collaborate to decrypt
#' }
#'
#' @export
mhePartialDecryptDS <- function(ciphertext, party_id, secret_key_share = NULL,
                                 log_n = 14, log_scale = 40) {
  # Validate inputs
  if (!is.character(ciphertext) || length(ciphertext) != 1) {
    stop("ciphertext must be a single character string", call. = FALSE)
  }
  if (!is.numeric(party_id) || party_id < 0) {
    stop("party_id must be a non-negative integer", call. = FALSE)
  }

  # Get secret key share
  if (is.null(secret_key_share)) {
    # Look for stored key
    key_env_name <- paste0(".mhe_sk_share_", party_id)
    if (!exists(key_env_name, envir = globalenv())) {
      stop("Secret key share not found for party ", party_id,
           ". Run mheKeyGenDS first.", call. = FALSE)
    }
    secret_key_share <- get(key_env_name, envir = globalenv())
  }

  # Call mhe-tool
  input <- list(
    ciphertext = ciphertext,
    secret_key_share = secret_key_share,
    party_id = as.integer(party_id),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("partial-decrypt", input)

  list(
    partial_decryption = result$partial_decryption,
    party_id = result$party_id
  )
}
