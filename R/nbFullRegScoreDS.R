#' @title Per-patient mu seal on non-label server for NB full-reg theta MLE
#' @description Computes \eqn{\eta_i^s = X_i^s \beta} on this (non-
#'   label) server from the locally-held feature partition and a client-
#'   supplied beta-slice, then transport-seals the vector for the label
#'   server. Used by \code{ds.vertNBFullRegTheta(variant="full_reg")}
#'   to get per-patient mu_i to the outcome server without revealing
#'   them to the client.
#'
#'   Inter-server leakage (documented in P3 budget): the label server
#'   learns \code{eta_nl_i} per patient after decryption. Equivalent
#'   to sharing the non-label's BLUE fitted value with the outcome
#'   holder -- a weaker disclosure than raw features. The client still
#'   sees only scalar aggregates (Sumpsi, Sumlog terms).
#'
#' @param data_name Character. Data frame with the feature columns.
#' @param x_vars Character vector. Non-label feature names on this server.
#' @param beta_values Numeric vector same length as \code{x_vars}: the
#'   non-label beta-slice from a prior Poisson fit (client-provided, since
#'   beta is revealed at convergence).
#' @param target_pk Character. Transport PK (base64url) of the label
#'   server that should receive the sealed \code{eta_nl} vector.
#' @param session_id Character.
#' @param allow_disclosive_legacy Logical. Must be \code{TRUE} to run this
#'   archived helper. The non-disclosive replacement is
#'   \code{ds.vertNBFullRegTheta(variant = "full_reg_nd")}.
#' @return List with \code{sealed} (base64url blob).
#' @export
dsvertNBEtaSealDS <- function(data_name, x_vars, beta_values,
                              target_pk, session_id = NULL,
                              allow_disclosive_legacy = FALSE) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  .k2_enforce_K(.S(session_id), 2L, "dsvertNBEtaSealDS")
  if (!isTRUE(allow_disclosive_legacy)) {
    stop("dsvertNBEtaSealDS is disabled by default because it transports ",
         "per-patient non-label eta to the outcome server; use ",
         "ds.vertNBFullRegTheta(variant = 'full_reg_nd') or pass ",
         "allow_disclosive_legacy = TRUE only for archived reproducibility.",
         call. = FALSE)
  }
  if (!is.character(x_vars) || length(x_vars) < 1L)
    stop("x_vars must be a non-empty character vector", call. = FALSE)
  beta_values <- as.numeric(beta_values)
  if (length(beta_values) != length(x_vars))
    stop("beta_values length mismatch x_vars", call. = FALSE)

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  missing_cols <- setdiff(x_vars, names(data))
  if (length(missing_cols) > 0L)
    stop("columns not found: ", paste(missing_cols, collapse = ","),
         call. = FALSE)

  X <- as.matrix(data[, x_vars, drop = FALSE])
  eta_nl <- as.numeric(X %*% beta_values)   # length = nrow(data)

  n <- length(eta_nl)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    stop("Insufficient observations", call. = FALSE)

  # Transport-seal the \code{eta_nl} vector to the label server's PK. This is
  # JSON of a numeric vector; the label server decrypts in
  # dsvertNBFullScoreDS.
  payload <- jsonlite::base64_enc(charToRaw(jsonlite::toJSON(eta_nl)))
  # Accept target_pk as base64 or base64url (strip padding / swap chars).
  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt",
                          list(data = payload, recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed))
}


#' @title Full-regression theta-MLE score on label server (per-patient mu)
#' @description Computes Sum psi(y_i+theta), Sum psi_1(y_i+theta), Sum log(theta/(theta+mu_i)), and
#'   its derivative Sum mu_i/(theta(theta+mu_i)) on the label server, using
#'   per-patient mu_i = exp(eta_i_total) where eta_i_total is assembled from
#'   the label's own eta_i_label (computed from local x_vars_label +
#'   client-supplied beta_label) plus the peer's sealed eta_i^nl blob
#'   (previously stored via \code{mpcStoreBlobDS} under
#'   \code{peer_eta_key}).
#'
#'   This replaces the iid-mu approximation in
#'   \code{dsvertNBProfileSumsDS} with the true per-patient form.
#'   Empirically closes the ~16% -> ~0% gap to \code{MASS::glm.nb}
#'   (AUDITORIA C: \code{MASS::theta.ml(y, mu=fed_mu_per_patient)}
#'   matches glm.nb theta at rel err 7e-5 on NHANES-subset).
#'
#'   Reveals to the client exactly five scalars per theta evaluation:
#'   \code{sum_psi}, \code{sum_tri}, \code{sum_log_theta_ratio},
#'   \code{sum_mu_ratio}, \code{n}. Same disclosure class as the
#'   existing \code{dsvertNBProfileSumsDS}.
#'
#' @param data_name Character. Data frame on the label server.
#' @param y_var Character. Outcome column.
#' @param x_vars_label Character. Feature cols held on the label server.
#' @param beta_values_label Numeric. beta-slice for those columns (client-
#'   provided from prior Poisson fit).
#' @param beta_intercept Numeric scalar. The fit's intercept (revealed).
#' @param peer_eta_key Character. Session slot holding the peer's
#'   transport-sealed \code{eta_nl} blob (set via \code{mpcStoreBlobDS}).
#' @param theta Numeric scalar > 0.
#' @param session_id Character.
#' @param allow_disclosive_legacy Logical. Must be \code{TRUE} to consume the
#'   archived per-patient eta transport path. The non-disclosive replacement
#'   is \code{ds.vertNBFullRegTheta(variant = "full_reg_nd")}.
#' @return List of five numeric scalars.
#' @export
dsvertNBFullScoreDS <- function(data_name, y_var,
                                x_vars_label, beta_values_label,
                                beta_intercept,
                                peer_eta_key, theta,
                                session_id = NULL,
                                allow_disclosive_legacy = FALSE) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  theta <- as.numeric(theta)
  if (!is.finite(theta) || theta <= 0)
    stop("theta must be finite positive", call. = FALSE)

  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBFullScoreDS")
  if (!isTRUE(allow_disclosive_legacy)) {
    stop("dsvertNBFullScoreDS is disabled by default because it consumes ",
         "per-patient non-label eta on the outcome server; use ",
         "ds.vertNBFullRegTheta(variant = 'full_reg_nd') or pass ",
         "allow_disclosive_legacy = TRUE only for archived reproducibility.",
         call. = FALSE)
  }

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!(y_var %in% names(data)))
    stop("y_var '", y_var, "' not in data", call. = FALSE)

  y <- as.numeric(data[[y_var]])
  ok <- !is.na(y)
  y <- y[ok]
  n <- length(y)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min) {
    return(list(sum_psi = NA_real_, sum_tri = NA_real_,
                sum_log_theta_ratio = NA_real_, sum_mu_ratio = NA_real_,
                n = n))
  }

  # Label-side eta contribution.
  if (length(x_vars_label) == 0L) {
    eta_label <- rep(0, n)
  } else {
    beta_values_label <- as.numeric(beta_values_label)
    if (length(beta_values_label) != length(x_vars_label))
      stop("beta_values_label length mismatch x_vars_label", call. = FALSE)
    Xl <- as.matrix(data[ok, x_vars_label, drop = FALSE])
    eta_label <- as.numeric(Xl %*% beta_values_label)
  }

  # Decrypt peer \code{eta_nl} from the session blob.
  blob <- .blob_consume(peer_eta_key, ss)
  if (is.null(blob))
    stop("peer eta blob missing at key '", peer_eta_key,
         "'; client must relay from non-label server", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport secret key missing -- call glmRing63TransportInitDS first",
         call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  eta_nl <- as.numeric(jsonlite::fromJSON(rawToChar(
    jsonlite::base64_dec(dec$data))))
  if (length(eta_nl) != n)
    stop(sprintf("peer eta length %d != label n %d", length(eta_nl), n),
         call. = FALSE)

  beta_intercept <- as.numeric(beta_intercept)
  eta <- beta_intercept + eta_label + eta_nl
  # Clamp for numerical safety (Poisson mu in [1e-10, 1e10] is ample).
  eta <- pmin(pmax(eta, -23), 23)
  mu <- exp(eta)

  # Complete NB profile score per Venables-Ripley 2002 Sec.7.4 +
  # Lawless 1987 Can J Stat 15 (AUDITORIA correction -- prior score
  # omitted the +n and -Sum(y+theta)/(theta+mu) terms -> biased 5.87% fixed point):
  #   ell'(theta) = Sumpsi(y_i+theta) - n*psi(theta) + n*log(theta) - Sumlog(theta+mu_i)
  #           + n - Sum(y_i+theta)/(theta+mu_i)
  #   ell''(theta) = Sumpsi_1(y_i+theta) - n*psi_1(theta) + n/theta - 2*Sum1/(theta+mu_i)
  #            + Sum(y_i+theta)/(theta+mu_i)^2
  sum_psi <- sum(digamma(y + theta))
  sum_tri <- sum(trigamma(y + theta))
  # Sum log(theta / (theta + mu_i)) = n*log(theta) - Sumlog(theta+mu_i)
  sum_log_theta_ratio <- sum(log(theta) - log(theta + mu))
  # Sum mu_i/(theta*(theta+mu_i)) = n/theta - Sum1/(theta+mu_i)  (d/dtheta of log(theta/(theta+mu)))
  sum_mu_ratio <- sum(mu / (theta * (theta + mu)))
  # Full-score completion sums:
  inv_theta_plus_mu      <- 1 / (theta + mu)
  y_plus_theta_over_tmu  <- (y + theta) / (theta + mu)
  y_plus_theta_over_tmu2 <- y_plus_theta_over_tmu / (theta + mu)
  sum_inv_tmu       <- sum(inv_theta_plus_mu)        # Sum 1/(theta+mu)
  sum_ypt_over_tmu  <- sum(y_plus_theta_over_tmu)    # Sum (y+theta)/(theta+mu)
  sum_ypt_over_tmu2 <- sum(y_plus_theta_over_tmu2)   # Sum (y+theta)/(theta+mu)^2

  list(sum_psi = sum_psi,
       sum_tri = sum_tri,
       sum_log_theta_ratio = sum_log_theta_ratio,
       sum_mu_ratio = sum_mu_ratio,
       sum_inv_tmu = sum_inv_tmu,
       sum_ypt_over_tmu = sum_ypt_over_tmu,
       sum_ypt_over_tmu2 = sum_ypt_over_tmu2,
       n = n)
}
