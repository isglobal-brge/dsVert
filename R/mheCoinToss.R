#' @title MHE Coin-Tossing CRP Protocol
#' @description Distributed randomness generation for CKKS key setup.
#'   Replaces Party 0's unilateral CRP generation with commit-reveal
#'   coin tossing so no single server or client can control the seed.
#' @name mhe-coin-toss
NULL

# ============================================================================
# Coin-Tossing CRP Protocol
# ============================================================================
# Replaces Party 0's unilateral CRP generation with distributed randomness.
# All servers contribute randomness via commit-reveal; no single server or
# client can control the CKKS key setup seed.

#' Coin-toss commit: generate contribution and SHA-256 commitment
#' @param session_id Character or NULL.
#' @return List with \code{commitment} (base64url SHA-256 hash).
#' @export
mheCoinTossCommitDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  result <- .callMheTool("mhe-coin-toss-commit", list())
  ss$coin_toss_contribution <- result$contribution
  list(commitment = base64_to_base64url(result$commitment))
}

#' Coin-toss reveal: return stored random contribution
#' @param session_id Character or NULL.
#' @return List with \code{contribution} (base64url).
#' @export
mheCoinTossRevealDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  contribution <- ss$coin_toss_contribution
  if (is.null(contribution))
    stop("No coin-toss contribution. Call mheCoinTossCommitDS first.", call. = FALSE)
  list(contribution = base64_to_base64url(contribution))
}

#' Coin-toss derive CRP: verify commitments and derive CRP + GKG seed
#' @param contributions Character vector (base64url).
#' @param commitments Character vector (base64url).
#' @param log_n Integer. CKKS ring dimension.
#' @param log_scale Integer. CKKS scale.
#' @param party_id Integer. This server's party ID.
#' @param session_id Character or NULL.
#' @return TRUE on success. CRP + GKG seed stored in blob for mheInitDS.
#' @export
mheCoinTossDeriveCRPDS <- function(contributions, commitments, log_n, log_scale,
                                    party_id, session_id = NULL) {
  ss <- .S(session_id)
  contribs_b64 <- unname(sapply(contributions, .base64url_to_base64, USE.NAMES = FALSE))
  commits_b64 <- unname(sapply(commitments, .base64url_to_base64, USE.NAMES = FALSE))

  result <- .callMheTool("mhe-coin-toss-derive-crp", list(
    contributions = as.list(contribs_b64),
    commitments = as.list(commits_b64),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  ))

  .blob_put("crp", base64_to_base64url(result$crp), ss)
  .blob_put("gkg_seed", base64_to_base64url(result$gkg_seed), ss)
  .blob_put("party_id", as.character(as.integer(party_id)), ss)
  TRUE
}
