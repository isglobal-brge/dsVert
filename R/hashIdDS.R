#' @title Hash Identifier Variable
#' @description Server-side aggregate function that hashes an identifier
#'   variable using a cryptographic hash function. Used for privacy-preserving
#'   record matching across vertically partitioned data.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param id_col Character string. Name of the column containing identifiers
#'   to hash.
#' @param algo Character string. Hash algorithm to use. Default is "sha256".
#'   Supported algorithms include "md5", "sha1", "sha256", "sha512".
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{hashes}: Character vector of hashed identifiers
#'     \item \code{n}: Integer count of observations (for validation)
#'   }
#'
#' @details
#' This function is part of the record matching workflow for vertically

#' partitioned data. It uses the SHA-256 algorithm by default, which provides
#' collision resistance suitable for identifier matching.
#'
#' The function returns hashes (not raw identifiers) ensuring that sensitive
#' information like patient IDs never leave the server in identifiable form.
#'
#' @seealso \code{\link{alignRecordsDS}} for reordering data based on hashes
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' # result <- datashield.aggregate(conn, "hashIdDS('D', 'patient_id')")
#' }
#'
#' @importFrom digest digest
#' @export
hashIdDS <- function(data_name, id_col, algo = "sha256") {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(id_col) || length(id_col) != 1) {
    stop("id_col must be a single character string", call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  # Extract identifiers
  ids <- data[[id_col]]

  # Hash each identifier using vectorized approach with vapply for type safety
  hashes <- vapply(
    ids,
    function(x) digest::digest(as.character(x), algo = algo),
    character(1),
    USE.NAMES = FALSE
  )

  # Return hashes with count for validation
  list(
    hashes = hashes,
    n = length(hashes)
  )
}
