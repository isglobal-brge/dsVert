#' @title Register an offset column for an open GLM session (server-side)
#' @description Register a plaintext per-patient offset vector to be added
#'   to this server's eta share during every subsequent
#'   \code{k2ComputeEtaShareDS} call in the named session. Used to support
#'   rate-scale Poisson / negative-binomial regressions of the form
#'
#'     log E[y] = X beta + offset
#'
#'   where the offset is typically \code{log(person_years)} or
#'   \code{log(exposure)} and is held on the server that also holds the
#'   outcome variable.
#'
#' @param data_name Character. Aligned data-frame name on this server.
#' @param offset_column Character. Name of a numeric column in
#'   \code{data_name} holding the offset on the linear-predictor scale
#'   (i.e., already log-transformed where appropriate).
#' @param session_id Character. GLM session identifier.
#'
#' @return Named list with \code{stored = TRUE} and the length of the
#'   stored FP vector.
#'
#' @details The offset is added to this server's eta share in-place; the
#'   other DCF party's share is unchanged. Because Ring63 additive
#'   sharing is linear, the reconstructed eta is
#'   \code{eta_own + eta_peer + offset = X beta + offset}.
#'
#'   Offsets never leave their home server; the client only orchestrates
#'   the registration call to the server that owns the offset column.
#' @export
k2SetOffsetDS <- function(data_name, offset_column, session_id = NULL) {
  if (!is.character(data_name) || length(data_name) != 1L) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!is.character(offset_column) || length(offset_column) != 1L) {
    stop("offset_column must be a single character string", call. = FALSE)
  }
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!offset_column %in% names(data)) {
    stop("Offset column '", offset_column, "' not found in '",
         data_name, "'", call. = FALSE)
  }
  offset_values <- data[[offset_column]]
  if (!is.numeric(offset_values)) {
    stop("Offset column must be numeric", call. = FALSE)
  }
  if (anyNA(offset_values)) {
    stop("Offset column contains NA; dsVert requires offsets complete on
          the post-alignment cohort", call. = FALSE)
  }

  ss <- .S(session_id)
  n_expected <- ss$k2_x_n
  if (!is.null(n_expected) && length(offset_values) != n_expected) {
    stop("Offset length (", length(offset_values),
         ") does not match aligned cohort size (", n_expected, ")",
         call. = FALSE)
  }

  fp_result <- .callMpcTool("k2-float-to-fp", list(
    values = as.numeric(offset_values),
    frac_bits = 20L
  ))
  ss$k2_offset_fp <- fp_result$fp_data
  ss$k2_offset_column <- offset_column

  list(stored = TRUE, n = length(offset_values))
}

#' @title Clear a registered offset for a session (server-side)
#' @description Remove any offset stored via \code{k2SetOffsetDS()} so
#'   that subsequent eta computations fall back to plain X beta.
#' @param session_id Character. GLM session identifier.
#' @return \code{list(cleared = TRUE)}
#' @export
k2ClearOffsetDS <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  ss <- .S(session_id)
  ss$k2_offset_fp <- NULL
  ss$k2_offset_column <- NULL
  list(cleared = TRUE)
}
