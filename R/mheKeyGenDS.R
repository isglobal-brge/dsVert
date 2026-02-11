#' @title MHE Key Generation (Server-Side)
#' @description Server-side aggregate function that generates a secret key share
#'   and public key share for multiparty homomorphic encryption.
#'
#' @param party_id Integer. Unique identifier for this party/server (0-indexed).
#' @param num_parties Integer. Total number of parties in the MHE setup.
#' @param log_n Integer. Ring dimension parameter (default 14, giving 8192 slots).
#' @param log_scale Integer. Scale parameter for CKKS (default 40).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{secret_key_share}: Base64-encoded secret key share
#'     \item \code{public_key_share}: Base64-encoded public key share
#'     \item \code{party_id}: The party ID
#'     \item \code{log_n}: Ring dimension used
#'     \item \code{log_scale}: Scale parameter used
#'   }
#'
#' @details
#' This function generates cryptographic key material for threshold CKKS
#' encryption. The key generation uses Lattigo's CKKS scheme with parameters
#' suitable for statistical computations on real numbers.
#'
#' @section Security:
#' \itemize{
#'   \item Secret keys should be handled securely
#'   \item Decryption requires ALL parties to contribute their shares
#'   \item The client alone cannot decrypt any ciphertext
#' }
#'
#' @seealso \code{\link{mheCombineKeysDS}} for combining public keys
#'
#' @export
mheKeyGenDS <- function(party_id, num_parties, log_n = 14, log_scale = 40) {
  # Validate inputs
  if (!is.numeric(party_id) || party_id < 0) {
    stop("party_id must be a non-negative integer", call. = FALSE)
  }
  if (!is.numeric(num_parties) || num_parties < 1) {
    stop("num_parties must be at least 1", call. = FALSE)
  }
  if (party_id >= num_parties) {
    stop("party_id must be less than num_parties", call. = FALSE)
  }

  # Call mhe-tool
  input <- list(
    party_id = as.integer(party_id),
    num_parties = as.integer(num_parties),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("keygen", input)

  # Return keys in base64url format for safe transmission
  # (standard base64 contains "/" and "+" which cause R parser issues on Opal)
  list(
    secret_key_share = base64_to_base64url(result$secret_key_share),
    public_key_share = base64_to_base64url(result$public_key_share),
    party_id = result$party_id,
    log_n = log_n,
    log_scale = log_scale
  )
}
