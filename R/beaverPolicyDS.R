#' Report the server-side Beaver preprocessing policy
#'
#' DataSHIELD administrators can control which Beaver preprocessing backends a
#' server is willing to participate in through R options. The client uses this
#' aggregate method during the preflight handshake so that the effective mode is
#' the strictest mode accepted by all participating servers.
#'
#' Recognised options are:
#' \itemize{
#'   \item \code{dsvert.beaver_preprocessing.allowed}: character vector or
#'     comma-separated string containing \code{"dealer"} and/or \code{"iknp"}.
#'   \item \code{dsvert.beaver_preprocessing.preferred}: \code{"dealer"} or
#'     \code{"iknp"}; used by client \code{"auto"} mode when all servers allow
#'     both.
#'   \item \code{dsvert.beaver_preprocessing.minimum}: \code{"dealer"} or
#'     \code{"iknp"}. Setting \code{"iknp"} forbids dealer preprocessing on
#'     that server.
#' }
#'
#' The usual \code{default.*} DataSHIELD option names are also honoured.
#'
#' @return A list describing supported, allowed, preferred and minimum modes.
#' @export
dsvertBeaverPolicyDS <- function() {
  .dsvert_beaver_policy()
}

.dsvert_get_option <- function(name, default = NULL) {
  value <- getOption(name)
  if (is.null(value)) value <- getOption(paste0("default.", name))
  if (is.null(value)) default else value
}

.dsvert_normalise_beaver_modes <- function(value, default = c("dealer", "iknp")) {
  if (is.null(value)) value <- default
  if (length(value) == 1L && is.character(value) && grepl(",", value)) {
    value <- strsplit(value, ",", fixed = TRUE)[[1L]]
  }
  value <- tolower(trimws(as.character(value)))
  value[value == "ot"] <- "iknp"
  value[value == "auto"] <- default
  value <- unique(value[nzchar(value)])
  invalid <- setdiff(value, c("dealer", "iknp"))
  if (length(invalid)) {
    stop("Invalid dsvert.beaver_preprocessing mode(s): ",
         paste(invalid, collapse = ", "), call. = FALSE)
  }
  unique(value)
}

.dsvert_beaver_policy <- function() {
  supported <- c("dealer", "iknp")
  allowed <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.allowed", supported), supported)
  minimum <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.minimum", "dealer"), "dealer")[1L]
  preferred <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.preferred", "dealer"), "dealer")[1L]

  allowed <- intersect(supported, allowed)
  if (identical(minimum, "iknp")) {
    allowed <- intersect(allowed, "iknp")
  }
  if (!length(allowed)) {
    stop("No dsVert Beaver preprocessing backend is allowed by server policy",
         call. = FALSE)
  }
  if (!preferred %in% allowed) preferred <- allowed[[1L]]

  list(
    supported = supported,
    allowed = allowed,
    preferred = preferred,
    minimum = minimum,
    requires_iknp = !("dealer" %in% allowed)
  )
}

.dsvert_require_beaver_mode <- function(mode) {
  mode <- tolower(as.character(mode)[1L])
  if (identical(mode, "ot")) mode <- "iknp"
  policy <- .dsvert_beaver_policy()
  if (!mode %in% policy$allowed) {
    if (identical(mode, "dealer") && isTRUE(policy$requires_iknp)) {
      stop("DSVERT_BEAVER_POLICY_REQUIRES_IKNP: this server requires ",
           "IKNP OT-extension Beaver preprocessing", call. = FALSE)
    }
    stop("DSVERT_BEAVER_POLICY_DISALLOWS_MODE: this server does not allow ",
         mode, " Beaver preprocessing", call. = FALSE)
  }
  invisible(policy)
}
