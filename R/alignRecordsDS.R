#' @title Align Records Based on Reference Hashes
#' @description Server-side assign function that reorders and subsets a data
#'   frame to match a reference set of hashed identifiers. This ensures that
#'   observations across different vertical partitions are properly aligned.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param id_col Character string. Name of the column containing identifiers.
#' @param reference_hashes Character vector. Hashes from the reference server
#'   to match against.
#' @param algo Character string. Hash algorithm to use. Must match the
#'   algorithm used to generate reference_hashes. Default is "sha256".
#'
#' @return A data frame containing only the matched observations, reordered
#'   to match the order of reference_hashes. This is assigned to the server
#'   environment (not returned to client).
#'
#' @details
#' This function performs the following steps:
#' \enumerate{
#'   \item Hashes the local identifier column using the specified algorithm
#'   \item Matches local hashes against reference hashes
#'   \item Subsets and reorders the data to align with reference
#' }
#'
#' Observations that don't match any reference hash are excluded.
#' The order of the returned data frame matches the order of reference_hashes.
#'
#' @seealso \code{\link{hashIdDS}} for generating the reference hashes
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.assign()
#' # datashield.assign(conn, "D_aligned",
#' #   "alignRecordsDS('D', 'patient_id', reference_hashes)")
#' }
#'
#' @importFrom digest digest
#' @export
alignRecordsDS <- function(data_name, id_col, reference_hashes, algo = "sha256") {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(id_col) || length(id_col) != 1) {
    stop("id_col must be a single character string", call. = FALSE)
  }
  if (!is.character(reference_hashes)) {
    stop("reference_hashes must be a character vector", call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  # Extract and hash local identifiers
  ids <- data[[id_col]]
  local_hashes <- vapply(
    ids,
    function(x) digest::digest(as.character(x), algo = algo),
    character(1),
    USE.NAMES = FALSE
  )

  # Match reference hashes to local hashes
  match_idx <- match(reference_hashes, local_hashes)

  # Filter out NAs (unmatched hashes)
  valid_idx <- !is.na(match_idx)
  matched_idx <- match_idx[valid_idx]

  # Subset and reorder data
  aligned_data <- data[matched_idx, , drop = FALSE]

  # Reset row names to avoid confusion

  rownames(aligned_data) <- NULL

  return(aligned_data)
}
