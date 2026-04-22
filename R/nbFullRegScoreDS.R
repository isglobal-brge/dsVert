#' @title Per-patient μ seal on non-label server for NB full-reg θ MLE
#' @description Computes \eqn{\eta_i^s = X_i^s \beta} on this (non-
#'   label) server from the locally-held feature partition and a client-
#'   supplied β-slice, then transport-seals the vector for the label
#'   server. Used by \code{ds.vertNBFullRegTheta(variant="full_reg")}
#'   to get per-patient μᵢ to the outcome server without revealing
#'   them to the client.
#'
#'   Inter-server leakage (documented in P3 budget): the label server
#'   learns \eqn{\eta^{nl}_i} per patient after decryption. Equivalent
#'   to sharing the non-label's BLUE fitted value with the outcome
#'   holder — a weaker disclosure than raw features. The client still
#'   sees only scalar aggregates (Σψ, Σlog terms).
#'
#' @param data_name Character. Data frame with the feature columns.
#' @param x_vars Character vector. Non-label feature names on this server.
#' @param beta_values Numeric vector same length as \code{x_vars}: the
#'   non-label β-slice from a prior Poisson fit (client-provided, since
#'   β is revealed at convergence).
#' @param target_pk Character. Transport PK (base64url) of the label
#'   server that should receive the sealed η^{nl} vector.
#' @param session_id Character.
#' @return List with \code{sealed} (base64url blob).
#' @export
dsvertNBEtaSealDS <- function(data_name, x_vars, beta_values,
                              target_pk, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
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

  # Transport-seal the η^{nl} vector to the label server's PK. This is
  # JSON of a numeric vector; the label server decrypts in
  # dsvertNBFullScoreDS.
  payload <- jsonlite::base64_enc(charToRaw(jsonlite::toJSON(eta_nl)))
  # Accept target_pk as base64 or base64url (strip padding / swap chars).
  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt",
                          list(data = payload, recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed))
}


#' @title Full-regression θ-MLE score on label server (per-patient μ)
#' @description Computes Σ ψ(yᵢ+θ), Σ ψ₁(yᵢ+θ), Σ log(θ/(θ+μᵢ)), and
#'   its derivative Σ μᵢ/(θ(θ+μᵢ)) on the label server, using
#'   per-patient μᵢ = exp(ηᵢ_total) where ηᵢ_total is assembled from
#'   the label's own ηᵢ_label (computed from local x_vars_label +
#'   client-supplied β_label) plus the peer's sealed ηᵢ^nl blob
#'   (previously stored via \code{mpcStoreBlobDS} under
#'   \code{peer_eta_key}).
#'
#'   This replaces the iid-μ approximation in
#'   \code{dsvertNBProfileSumsDS} with the true per-patient form.
#'   Empirically closes the ~16% → ~0% gap to \code{MASS::glm.nb}
#'   (AUDITORIA C: \code{MASS::theta.ml(y, mu=fed_mu_per_patient)}
#'   matches glm.nb θ at rel err 7e-5 on NHANES-subset).
#'
#'   Reveals to the client exactly five scalars per θ evaluation:
#'   \code{sum_psi}, \code{sum_tri}, \code{sum_log_theta_ratio},
#'   \code{sum_mu_ratio}, \code{n}. Same disclosure class as the
#'   existing \code{dsvertNBProfileSumsDS}.
#'
#' @param data_name Character. Data frame on the label server.
#' @param y_var Character. Outcome column.
#' @param x_vars_label Character. Feature cols held on the label server.
#' @param beta_values_label Numeric. β-slice for those columns (client-
#'   provided from prior Poisson fit).
#' @param beta_intercept Numeric scalar. The fit's intercept (revealed).
#' @param peer_eta_key Character. Session slot holding the peer's
#'   transport-sealed η^{nl} blob (set via \code{mpcStoreBlobDS}).
#' @param theta Numeric scalar > 0.
#' @param session_id Character.
#' @return List of five numeric scalars.
#' @export
dsvertNBFullScoreDS <- function(data_name, y_var,
                                x_vars_label, beta_values_label,
                                beta_intercept,
                                peer_eta_key, theta,
                                session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  theta <- as.numeric(theta)
  if (!is.finite(theta) || theta <= 0)
    stop("theta must be finite positive", call. = FALSE)

  ss <- .S(session_id)

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

  # Label-side η contribution.
  if (length(x_vars_label) == 0L) {
    eta_label <- rep(0, n)
  } else {
    beta_values_label <- as.numeric(beta_values_label)
    if (length(beta_values_label) != length(x_vars_label))
      stop("beta_values_label length mismatch x_vars_label", call. = FALSE)
    Xl <- as.matrix(data[ok, x_vars_label, drop = FALSE])
    eta_label <- as.numeric(Xl %*% beta_values_label)
  }

  # Decrypt peer η^{nl} from the session blob.
  blob <- .blob_consume(peer_eta_key, ss)
  if (is.null(blob))
    stop("peer η blob missing at key '", peer_eta_key,
         "'; client must relay from non-label server", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport secret key missing — call glmRing63TransportInitDS first",
         call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
    list(sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  eta_nl <- as.numeric(jsonlite::fromJSON(rawToChar(
    jsonlite::base64_dec(dec$data))))
  if (length(eta_nl) != n)
    stop(sprintf("peer η length %d != label n %d", length(eta_nl), n),
         call. = FALSE)

  beta_intercept <- as.numeric(beta_intercept)
  eta <- beta_intercept + eta_label + eta_nl
  # Clamp for numerical safety (Poisson μ in [1e-10, 1e10] is ample).
  eta <- pmin(pmax(eta, -23), 23)
  mu <- exp(eta)

  sum_psi <- sum(digamma(y + theta))
  sum_tri <- sum(trigamma(y + theta))
  # Σ log(θ / (θ + μᵢ))
  sum_log_theta_ratio <- sum(log(theta) - log(theta + mu))
  # Σ μᵢ / (θ·(θ+μᵢ))  (d/dθ of log(θ/(θ+μ)))
  sum_mu_ratio <- sum(mu / (theta * (theta + mu)))

  list(sum_psi = sum_psi,
       sum_tri = sum_tri,
       sum_log_theta_ratio = sum_log_theta_ratio,
       sum_mu_ratio = sum_mu_ratio,
       n = n)
}
