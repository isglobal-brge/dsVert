#' @title MHE Fuse Decryption (Server-Side)
#' @description Server-side aggregate function that combines partial decryption
#'   shares to recover the plaintext result.
#'
#' @param partial_decryptions Character vector. Base64-encoded partial decryption
#'   shares from all parties.
#' @param rows Integer. Number of rows in the result matrix.
#' @param cols Integer. Number of columns in the result matrix.
#' @param log_n Integer. Ring dimension parameter (must match encryption).
#' @param log_scale Integer. Scale parameter (must match encryption).
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{data}: The decrypted matrix as a 2D array
#'   }
#'
#' @details
#' This function combines partial decryption shares from ALL parties
#' to recover the plaintext. This is the final step in the MHE protocol
#' where the encrypted computation result is revealed.
#'
#' @section Security:
#' This function can ONLY succeed if partial decryption shares from
#' ALL parties are provided. Missing even one share makes decryption
#' impossible.
#'
#' @note This function is typically called on one server to perform
#' the final combination. The resulting plaintext is the aggregate
#' statistic (e.g., correlation matrix), NOT individual data.
#'
#' @export
mheFuseDecryptDS <- function(partial_decryptions, rows, cols,
                              log_n = 14, log_scale = 40) {
  # Validate inputs
  if (!is.character(partial_decryptions) || length(partial_decryptions) == 0) {
    stop("partial_decryptions must be a non-empty character vector", call. = FALSE)
  }
  if (!is.numeric(rows) || rows < 1) {
    stop("rows must be a positive integer", call. = FALSE)
  }
  if (!is.numeric(cols) || cols < 1) {
    stop("cols must be a positive integer", call. = FALSE)
  }

  # Call mhe-tool
  input <- list(
    partial_decryptions = as.list(partial_decryptions),
    rows = as.integer(rows),
    cols = as.integer(cols),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  result <- .callMheTool("fuse-decrypt", input)

  # Convert to R matrix
  data_matrix <- do.call(rbind, lapply(result$data, unlist))

  list(
    data = data_matrix
  )
}
