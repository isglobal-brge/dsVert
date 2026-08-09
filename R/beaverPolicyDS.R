#' Report the server-side Beaver preprocessing policy
#'
#' Reports which Beaver preprocessing backends this DataSHIELD server allows.
#' The client uses this aggregate method during preflight negotiation so that
#' the effective backend is accepted by every participating server.
#'
#' Administrators can configure the policy with the ordinary R/DataSHIELD
#' options \code{dsvert.beaver_preprocessing.allowed},
#' \code{dsvert.beaver_preprocessing.preferred} and
#' \code{dsvert.beaver_preprocessing.minimum}. The corresponding
#' \code{default.*} option names are also honoured.
#'
#' The sole supported backend is dealer-free \code{"iknp"} OT-extension
#' (\code{"ot"} is normalised to \code{"iknp"}). Trusted-dealer preprocessing
#' has been removed because a participating-party dealer can reconstruct peer
#' operands, so any \code{"dealer"} request is refused.
#'
#' @return A list describing supported, allowed, preferred and minimum modes.
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
  # DEALER MODE REMOVED (F2/F17): a participating-party dealer can reconstruct
  # peer operands. IKNP OT-extension is the sole, dealer-free backend. The
  # policy advertises IKNP only; any 'dealer' request is normalised/refused.
  supported <- c("iknp")
  allowed <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.allowed", supported), supported)
  minimum <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.minimum", "iknp"), "iknp")[1L]
  preferred <- .dsvert_normalise_beaver_modes(.dsvert_get_option(
    "dsvert.beaver_preprocessing.preferred", "iknp"), "iknp")[1L]

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
