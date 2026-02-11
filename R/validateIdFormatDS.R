#' @title Validate Identifier Format (Server-Side)
#' @description Server-side aggregate function that validates the format
#'   of identifier variables and returns aggregate statistics for
#'   cross-server comparison.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param id_col Character string. Name of the column containing identifiers.
#' @param pattern Character string (optional). Regular expression pattern
#'   that IDs should match. If NULL, pattern is inferred from data.
#'
#' @return A list containing:
#'   \itemize{
#'     \item \code{n_obs}: Number of observations
#'     \item \code{n_unique}: Number of unique identifiers
#'     \item \code{n_missing}: Number of missing (NA) identifiers
#'     \item \code{all_match}: Logical, TRUE if all IDs match the pattern
#'       (only if pattern provided)
#'     \item \code{pct_match}: Percentage of IDs matching the pattern
#'     \item \code{format_signature}: Hash of detected format characteristics
#'       for cross-server comparison
#'     \item \code{id_class}: R class of the identifier column
#'   }
#'
#' @details
#' This function helps ensure that identifier variables have consistent
#' formats across servers before performing record alignment. It is
#' privacy-preserving as it only returns aggregate statistics and a
#' format signature hash, never the actual identifier values.
#'
#' The format signature is computed from:
#' \itemize{
#'   \item The detected character class pattern (digits, letters, etc.)
#'   \item The typical length of identifiers
#'   \item The presence of separators (-, _, etc.)
#' }
#'
#' @seealso \code{\link{hashIdDS}} for hashing identifiers,
#'   \code{\link{alignRecordsDS}} for record alignment
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.aggregate()
#' result <- datashield.aggregate(conn,
#'   call("validateIdFormatDS", "D", "patient_id", "^[A-Z][0-9]+$"))
#' }
#'
#' @importFrom stats median var
#' @export
validateIdFormatDS <- function(data_name, id_col, pattern = NULL) {
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
    stop("Column '", id_col, "' not found in data", call. = FALSE)
  }

  # Extract identifiers
  ids <- data[[id_col]]
  n_obs <- length(ids)

  # Privacy check
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n_obs < privacy_level) {
    stop("Insufficient observations for privacy-preserving analysis",
         call. = FALSE)
  }

  # Convert to character for analysis
  ids_char <- as.character(ids)

  # Count statistics
  n_missing <- sum(is.na(ids))
  ids_valid <- ids_char[!is.na(ids_char)]
  n_unique <- length(unique(ids_valid))

  # Pattern matching
  if (!is.null(pattern)) {
    matches <- grepl(pattern, ids_valid)
    n_match <- sum(matches)
    pct_match <- 100 * n_match / length(ids_valid)
    all_match <- all(matches)
  } else {
    pct_match <- NA
    all_match <- NA
  }

  # Compute format signature (privacy-preserving characteristics)
  if (length(ids_valid) > 0) {
    # Analyze character composition
    lengths <- nchar(ids_valid)
    median_length <- median(lengths)
    length_variance <- var(lengths)

    # Check for common patterns (aggregate, not individual)
    has_digits <- mean(grepl("[0-9]", ids_valid))
    has_letters <- mean(grepl("[A-Za-z]", ids_valid))
    has_uppercase <- mean(grepl("[A-Z]", ids_valid))
    has_lowercase <- mean(grepl("[a-z]", ids_valid))
    has_hyphen <- mean(grepl("-", ids_valid))
    has_underscore <- mean(grepl("_", ids_valid))

    # Create format signature string
    format_info <- paste(
      round(median_length),
      round(length_variance, 2),
      round(has_digits, 2),
      round(has_letters, 2),
      round(has_uppercase, 2),
      round(has_lowercase, 2),
      round(has_hyphen, 2),
      round(has_underscore, 2),
      sep = "|"
    )

    # Hash the format signature
    format_signature <- digest::digest(format_info, algo = "sha256")
  } else {
    format_signature <- NA
  }

  list(
    n_obs = n_obs,
    n_unique = n_unique,
    n_missing = n_missing,
    all_match = all_match,
    pct_match = pct_match,
    format_signature = format_signature,
    id_class = class(ids)[1]
  )
}
