#' Identity link: set mu = eta (for Gaussian GLM)
#'
#' Copies the eta share to the mu share in session storage.
#' Used for Gaussian family where mu = eta (no sigmoid/exp transformation).
#'
#' @param session_id Character or NULL. Session identifier.
#' @return List with ok = TRUE.
#' @export
k2IdentityLinkDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  eta_fp <- ss$k2_eta_share_fp
  if (is.null(eta_fp)) stop("No eta share in session", call. = FALSE)
  ss$secure_mu_share <- eta_fp
  list(ok = TRUE)
}
