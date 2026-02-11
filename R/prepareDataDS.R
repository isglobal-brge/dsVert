#' @title Prepare Data for Analysis
#' @description Server-side assign function that prepares data for vertical
#'   federated analysis. Handles column selection, data type validation,
#'   and optional standardization.
#'
#' @param data_name Character string. Name of the data frame in the server
#'   environment.
#' @param variables Character vector. Names of columns to include in analysis.
#' @param standardize Logical. Whether to center and scale numeric variables.
#'   Default is FALSE.
#' @param complete_cases Logical. Whether to remove rows with any NA values.
#'   Default is TRUE.
#'
#' @return A data frame with selected variables, optionally standardized.
#'   Assigned to server environment (not returned to client).
#'
#' @details
#' This function prepares data for downstream analysis functions like
#' \code{blockSvdDS} and \code{glmPartialFitDS}. It ensures consistent
#' data preparation across all servers in a federated analysis.
#'
#' When standardize = TRUE, each numeric column is centered (mean = 0) and
#' scaled (sd = 1). This is required for proper Block SVD correlation
#' calculations and can improve GLM convergence.
#'
#' @examples
#' \dontrun{
#' # Called from client via datashield.assign()
#' # datashield.assign(conn, "D_prep",
#' #   "prepareDataDS('D', c('age', 'weight', 'height'), TRUE)")
#' }
#'
#' @importFrom stats complete.cases
#' @export
prepareDataDS <- function(data_name, variables, standardize = FALSE,
                          complete_cases = TRUE) {
  # Validate inputs
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(variables) || length(variables) == 0) {
    stop("variables must be a non-empty character vector", call. = FALSE)
  }

  # Get data from server environment
  data <- eval(parse(text = data_name), envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }

  # Check that all requested variables exist
  missing_vars <- setdiff(variables, names(data))
  if (length(missing_vars) > 0) {
    stop("Variables not found in data: ",
         paste(missing_vars, collapse = ", "), call. = FALSE)
  }

  # Select variables
  result <- data[, variables, drop = FALSE]

  # Remove incomplete cases if requested
  if (complete_cases) {
    complete_rows <- stats::complete.cases(result)
    result <- result[complete_rows, , drop = FALSE]
  }

  # Standardize numeric columns if requested
  if (standardize) {
    for (col in names(result)) {
      if (is.numeric(result[[col]])) {
        result[[col]] <- as.vector(scale(result[[col]]))
      }
    }
  }

  # Reset row names
  rownames(result) <- NULL

  return(result)
}
